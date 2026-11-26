use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use reqwest::{Method, RequestBuilder, StatusCode, Url, cookie::Jar};
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::checks::*;
use crate::error::{Error, Result};
use crate::events::{EventStream, Position};
use crate::issues::*;
use crate::types::*;

/// Builds a [`Client`].
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    base: String,
    token: Option<String>,
    roots_pem: Vec<Vec<u8>>,
    timeout: Duration,
}

impl ClientBuilder {
    /// Sign in with an API token (`Authorization: Bearer`). Tokens are not ambient credentials, so no CSRF
    /// token is needed.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Trust this certificate (PEM) for an `https://` engine. Without any, only the public web roots are
    /// trusted, which will not include the engine's own certificate authority.
    pub fn ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.roots_pem.push(pem.into());
        self
    }

    /// How long one request may take (default 30 seconds). The event stream has no limit.
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub fn build(self) -> Result<Client> {
        let base = self.base.trim_end_matches('/').to_string();
        let url = Url::parse(&base).map_err(|e| Error::Setup(format!("bad engine address {base:?}: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::Setup(format!(
                "the engine address must start with http:// or https://, not {base:?}"
            )));
        }
        let jar = Arc::new(Jar::default());
        let mut b = reqwest::Client::builder()
            .cookie_provider(jar.clone())
            // The engine is usually local; a proxy from the environment (perhaps Bosun's own) must not sit between.
            .no_proxy()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none());
        for pem in &self.roots_pem {
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| Error::Setup(format!("bad CA certificate: {e}")))?;
            b = b.add_root_certificate(cert);
        }
        Ok(Client {
            inner: Arc::new(Inner {
                http: b.build()?,
                base,
                url,
                token: self.token,
                roots_pem: self.roots_pem,
                jar,
                csrf: Mutex::new(None),
            }),
        })
    }
}

pub(crate) struct Inner {
    pub(crate) http: reqwest::Client,
    pub(crate) base: String,
    pub(crate) url: Url,
    pub(crate) token: Option<String>,
    pub(crate) roots_pem: Vec<Vec<u8>>,
    pub(crate) jar: Arc<Jar>,
    csrf: Mutex<Option<String>>,
}

/// A connection to one engine. Cheap to clone; clones share the session.
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.inner.base)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Start building a client for the engine at `base` (such as `http://127.0.0.1:8090`).
    pub fn builder(base: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            base: base.into(),
            token: None,
            roots_pem: Vec::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// A client with no credentials yet, for [`Client::setup`], [`Client::login`] and the public endpoints.
    pub fn new(base: impl Into<String>) -> Result<Self> {
        Self::builder(base).build()
    }

    pub fn base_url(&self) -> &str {
        &self.inner.base
    }

    /// Your credentials, for opening the event stream.
    pub(crate) fn authorize(&self, h: &mut reqwest::header::HeaderMap) {
        use reqwest::cookie::CookieStore;
        if let Some(t) = &self.inner.token {
            if let Ok(v) = format!("Bearer {t}").parse() {
                h.insert(reqwest::header::AUTHORIZATION, v);
            }
        } else if let Some(c) = self.inner.jar.cookies(&self.inner.url) {
            h.insert(reqwest::header::COOKIE, c);
        }
    }

    fn req(&self, method: Method, path: &str) -> RequestBuilder {
        let mut rb = self
            .inner
            .http
            .request(method.clone(), format!("{}/api/v1{path}", self.inner.base));
        if let Some(t) = &self.inner.token {
            rb = rb.bearer_auth(t);
        } else if method != Method::GET
            && method != Method::HEAD
            && let Some(c) = self.inner.csrf.lock().ok().and_then(|g| g.clone())
        {
            rb = rb.header("x-csrf-token", c);
        }
        rb
    }

    async fn check(&self, r: reqwest::Response) -> Result<reqwest::Response> {
        let status = r.status();
        if status.is_success() {
            return Ok(r);
        }
        let text = r.text().await.unwrap_or_default();
        let message = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
            .unwrap_or(text);
        Err(Error::Api {
            status: status.as_u16(),
            message,
        })
    }

    async fn json<T: DeserializeOwned>(&self, rb: RequestBuilder) -> Result<T> {
        let r = self.check(rb.send().await?).await?;
        let bytes = r.bytes().await?;
        serde_json::from_slice(&bytes).map_err(Error::decode)
    }

    async fn unit(&self, rb: RequestBuilder) -> Result<()> {
        self.check(rb.send().await?).await?;
        Ok(())
    }

    fn remember(&self, me: &Me) {
        if let Ok(mut g) = self.inner.csrf.lock() {
            *g = me.csrf.clone();
        }
    }

    // --- session -------------------------------------------------------------------------------------------

    /// The engine's name and version, and whether first-run setup is pending. Needs no sign-in.
    pub async fn status(&self) -> Result<Status> {
        self.json(self.req(Method::GET, "/status")).await
    }

    /// Create the first admin account with the code the engine printed at start-up, and sign in as it.
    pub async fn setup(&self, code: &str, username: &str, password: &str) -> Result<Me> {
        let me: Me = self
            .json(
                self.req(Method::POST, "/setup")
                    .json(&json!({ "code": code, "username": username, "password": password })),
            )
            .await?;
        self.remember(&me);
        Ok(me)
    }

    /// Sign in with a password. The session cookie and CSRF token are kept for later calls.
    ///
    /// An account with a second factor answers [`Error::SecondFactor`] (no session yet): call
    /// [`Client::login_totp`] with the `pending` token it carries.
    pub async fn login(&self, username: &str, password: &str) -> Result<Me> {
        let v: serde_json::Value = self
            .json(
                self.req(Method::POST, "/auth/login")
                    .json(&json!({ "username": username, "password": password })),
            )
            .await?;
        if let Some(pending) = v.get("pending").and_then(|p| p.as_str()) {
            return Err(Error::SecondFactor {
                pending: pending.to_string(),
            });
        }
        let me: Me = serde_json::from_value(v).map_err(Error::decode)?;
        self.remember(&me);
        Ok(me)
    }

    /// Finish a sign-in that asked for a second factor, with a 6-digit code or an unused recovery code.
    pub async fn login_totp(&self, pending: &str, code: &str) -> Result<Me> {
        let me: Me = self
            .json(
                self.req(Method::POST, "/auth/login/totp")
                    .json(&json!({ "pending": pending, "code": code })),
            )
            .await?;
        self.remember(&me);
        Ok(me)
    }

    /// Your own second-factor state.
    pub async fn totp_status(&self) -> Result<TotpStatus> {
        self.json(self.req(Method::GET, "/auth/totp")).await
    }

    /// Make a TOTP secret for your account. Nothing is enforced until [`Client::totp_confirm`].
    pub async fn totp_enroll(&self) -> Result<TotpEnrolment> {
        self.json(self.req(Method::POST, "/auth/totp/enroll")).await
    }

    /// Turn the second factor on with the first valid code. The recovery codes are shown only here.
    pub async fn totp_confirm(&self, code: &str) -> Result<RecoveryCodes> {
        self.json(
            self.req(Method::POST, "/auth/totp/confirm")
                .json(&json!({ "code": code })),
        )
        .await
    }

    /// Turn your own second factor off (needs a valid code or recovery code).
    pub async fn totp_disable(&self, code: &str) -> Result<()> {
        self.unit(
            self.req(Method::POST, "/auth/totp/disable")
                .json(&json!({ "code": code })),
        )
        .await
    }

    /// Replace your recovery codes (needs a valid code).
    pub async fn totp_recovery_codes(&self, code: &str) -> Result<RecoveryCodes> {
        self.json(
            self.req(Method::POST, "/auth/totp/recovery-codes")
                .json(&json!({ "code": code })),
        )
        .await
    }

    /// Admin: require a second factor of every password account, or stop requiring it.
    pub async fn totp_set_required(&self, required: bool) -> Result<TotpStatus> {
        self.json(
            self.req(Method::PUT, "/auth/totp/required")
                .json(&json!({ "required": required })),
        )
        .await
    }

    /// Admin: remove a user's second factor (a lost device); their sessions end.
    pub async fn reset_user_totp(&self, id: i64) -> Result<()> {
        self.unit(self.req(Method::DELETE, &format!("/users/{id}/totp")))
            .await
    }

    /// Sign in with the login ticket an embedded engine (`bosun serve --embedded`) gave its parent process.
    /// A ticket works once, within 60 seconds, and only from the same machine.
    pub async fn login_ticket(&self, ticket: &str) -> Result<Me> {
        let me: Me = self
            .json(
                self.req(Method::POST, "/auth/ticket")
                    .json(&json!({ "ticket": ticket })),
            )
            .await?;
        self.remember(&me);
        Ok(me)
    }

    pub async fn logout(&self) -> Result<()> {
        self.unit(self.req(Method::POST, "/auth/logout")).await
    }

    pub async fn me(&self) -> Result<Me> {
        let me: Me = self.json(self.req(Method::GET, "/auth/me")).await?;
        self.remember(&me);
        Ok(me)
    }

    pub async fn sso_config(&self) -> Result<SsoInfo> {
        self.json(self.req(Method::GET, "/auth/sso")).await
    }

    /// Change your own password. Your API tokens are ended too unless `revoke_tokens` is `Some(false)`.
    pub async fn change_password(&self, current: &str, new: &str, revoke_tokens: Option<bool>) -> Result<()> {
        self.unit(
            self.req(Method::POST, "/auth/password")
                .json(&json!({ "current": current, "new": new, "revoke_tokens": revoke_tokens })),
        )
        .await
    }

    // --- history ------------------------------------------------------------------------------------------

    pub async fn flows(&self, q: &FlowQuery) -> Result<Vec<FlowSummary>> {
        self.json(self.req(Method::GET, "/flows").query(q)).await
    }

    /// What a history query means (its terms and its mistakes) without running it.
    pub async fn check_flow_query(&self, q: &str) -> Result<QueryCheck> {
        self.json(self.req(Method::GET, "/flows/query").query(&[("q", q)]))
            .await
    }

    pub async fn saved_filters(&self) -> Result<Vec<SavedFilter>> {
        self.json(self.req(Method::GET, "/saved-filters")).await
    }

    /// Replace the project's saved filters.
    pub async fn put_saved_filters(&self, list: &[SavedFilter]) -> Result<Vec<SavedFilter>> {
        self.json(self.req(Method::PUT, "/saved-filters").json(list))
            .await
    }

    /// Add and remove tags on many flows at once; returns how many flows changed.
    pub async fn change_tags(&self, ids: &[FlowId], add: &[&str], remove: &[&str]) -> Result<u64> {
        #[derive(serde::Deserialize)]
        struct R {
            changed: u64,
        }
        let r: R = self
            .json(
                self.req(Method::POST, "/flows/tags")
                    .json(&json!({ "ids": ids, "add": add, "remove": remove })),
            )
            .await?;
        Ok(r.changed)
    }

    // --- organizer -----------------------------------------------------------------------------------------

    pub async fn organizer(&self) -> Result<Vec<OrganizerItem>> {
        self.json(self.req(Method::GET, "/organizer")).await
    }

    /// Keep requests for follow-up; returns how many were new.
    pub async fn add_to_organizer(&self, flow_ids: &[FlowId]) -> Result<u64> {
        #[derive(serde::Deserialize)]
        struct R {
            added: u64,
        }
        let r: R = self
            .json(
                self.req(Method::POST, "/organizer")
                    .json(&json!({ "flow_ids": flow_ids })),
            )
            .await?;
        Ok(r.added)
    }

    pub async fn update_organizer_item(
        &self,
        id: i64,
        status: Option<OrganizerStatus>,
        note: Option<&str>,
    ) -> Result<()> {
        self.unit(
            self.req(Method::PATCH, &format!("/organizer/{id}"))
                .json(&json!({ "status": status, "note": note })),
        )
        .await
    }

    pub async fn delete_organizer_item(&self, id: i64) -> Result<()> {
        self.unit(self.req(Method::DELETE, &format!("/organizer/{id}")))
            .await
    }

    /// Delete flows by id; returns how many were removed.
    pub async fn delete_flows(&self, ids: &[FlowId]) -> Result<u64> {
        #[derive(serde::Deserialize)]
        struct R {
            deleted: u64,
        }
        let r: R = self
            .json(self.req(Method::DELETE, "/flows").json(&json!({ "ids": ids })))
            .await?;
        Ok(r.deleted)
    }

    pub async fn flow(&self, id: FlowId) -> Result<FlowMeta> {
        self.json(self.req(Method::GET, &format!("/flows/{id}"))).await
    }

    /// Set a flow's tags and note. `None` leaves that part as it is.
    pub async fn annotate_flow(&self, id: FlowId, tags: Option<&[String]>, note: Option<&str>) -> Result<()> {
        self.unit(
            self.req(Method::PATCH, &format!("/flows/{id}"))
                .json(&json!({ "tags": tags, "note": note })),
        )
        .await
    }

    pub async fn ws_messages(
        &self,
        id: FlowId,
        after: Option<i64>,
        limit: Option<u32>,
    ) -> Result<Vec<WsMessage>> {
        self.json(
            self.req(Method::GET, &format!("/flows/{id}/ws"))
                .query(&[("after", after), ("limit", limit.map(i64::from))]),
        )
        .await
    }

    /// Comments, scripts and references in the response, and the request's parameters.
    pub async fn flow_engage(&self, id: FlowId) -> Result<EngageReport> {
        self.json(self.req(Method::GET, &format!("/flows/{id}/engage")))
            .await
    }

    /// The distinct endpoints and parameters of a host across the history, with counts.
    pub async fn host_analysis(&self, host: &str, port: Option<u16>) -> Result<HostAnalysis> {
        let mut rb = self.req(Method::GET, "/analysis").query(&[("host", host)]);
        if let Some(p) = port {
            rb = rb.query(&[("port", p)]);
        }
        self.json(rb).await
    }

    /// A CSRF proof of concept for the request, as HTML text.
    pub async fn flow_csrf_poc(&self, id: FlowId, auto_submit: bool) -> Result<String> {
        let mut rb = self.req(Method::GET, &format!("/flows/{id}/csrf-poc"));
        if auto_submit {
            rb = rb.query(&[("auto", "1")]);
        }
        Ok(self.check(rb.send().await?).await?.text().await?)
    }

    /// A whole message body. `decoded` undoes the response's `Content-Encoding`.
    pub async fn flow_body(&self, id: FlowId, part: Part, decoded: bool) -> Result<Bytes> {
        let mut rb = self.req(Method::GET, &format!("/flows/{id}/{}/body", part.path()));
        if decoded {
            rb = rb.query(&[("decoded", "1")]);
        }
        Ok(self.check(rb.send().await?).await?.bytes().await?)
    }

    /// Bytes `start..=end` of a body (to the end when `end` is `None`).
    pub async fn flow_body_range(
        &self,
        id: FlowId,
        part: Part,
        start: u64,
        end: Option<u64>,
    ) -> Result<Bytes> {
        let range = match end {
            Some(e) => format!("bytes={start}-{e}"),
            None => format!("bytes={start}-"),
        };
        let rb = self
            .req(Method::GET, &format!("/flows/{id}/{}/body", part.path()))
            .header("range", range);
        let r = rb.send().await?;
        if r.status() != StatusCode::PARTIAL_CONTENT && r.status() != StatusCode::OK {
            return Err(self
                .check(r)
                .await
                .err()
                .unwrap_or_else(|| Error::decode("unexpected status")));
        }
        Ok(r.bytes().await?)
    }

    pub async fn site_map(&self, host: Option<&str>) -> Result<Vec<SiteMapEntry>> {
        self.json(self.req(Method::GET, "/sitemap").query(&[("host", host)]))
            .await
    }

    // --- scope and rules ----------------------------------------------------------------------------------

    pub async fn scope(&self) -> Result<ScopeSpec> {
        self.json(self.req(Method::GET, "/scope")).await
    }

    pub async fn put_scope(&self, spec: &ScopeSpec) -> Result<ScopeSpec> {
        self.json(self.req(Method::PUT, "/scope").json(spec)).await
    }

    pub async fn rules(&self) -> Result<Vec<MatchRule>> {
        self.json(self.req(Method::GET, "/rules")).await
    }

    pub async fn put_rules(&self, rules: &[MatchRule]) -> Result<Vec<MatchRule>> {
        self.json(self.req(Method::PUT, "/rules").json(rules)).await
    }

    /// The Map Local, Map Remote and throttle rules, in the order they are tried.
    pub async fn map_rules(&self) -> Result<Vec<MapRule>> {
        self.json(self.req(Method::GET, "/map-rules")).await
    }

    /// Replace the Map Local, Map Remote and throttle rules. A Map Local rule needs the admin role; a Map Remote
    /// target the scope gate refuses, or a missing directory, is a 400 that names the rule.
    pub async fn put_map_rules(&self, rules: &[MapRule]) -> Result<Vec<MapRule>> {
        self.json(self.req(Method::PUT, "/map-rules").json(rules)).await
    }

    // --- intercept ----------------------------------------------------------------------------------------

    pub async fn intercept(&self) -> Result<InterceptSettings> {
        self.json(self.req(Method::GET, "/intercept")).await
    }

    pub async fn put_intercept(&self, s: &InterceptSettings) -> Result<InterceptSettings> {
        self.json(self.req(Method::PUT, "/intercept").json(s)).await
    }

    pub async fn response_filter(&self) -> Result<ResponseFilter> {
        self.json(self.req(Method::GET, "/intercept/response-filter"))
            .await
    }

    pub async fn put_response_filter(&self, f: &ResponseFilter) -> Result<ResponseFilter> {
        self.json(self.req(Method::PUT, "/intercept/response-filter").json(f))
            .await
    }

    pub async fn intercept_queue(&self) -> Result<Vec<InterceptSummary>> {
        self.json(self.req(Method::GET, "/intercept/queue")).await
    }

    pub async fn intercept_item(&self, id: u64) -> Result<InterceptItem> {
        self.json(self.req(Method::GET, &format!("/intercept/queue/{id}")))
            .await
    }

    pub async fn intercept_decide(&self, id: u64, d: &Decision) -> Result<()> {
        self.unit(self.req(Method::POST, &format!("/intercept/queue/{id}")).json(d))
            .await
    }

    /// Forward everything held; returns how many messages were released.
    pub async fn intercept_forward_all(&self) -> Result<u64> {
        #[derive(serde::Deserialize)]
        struct R {
            forwarded: u64,
        }
        let r: R = self
            .json(self.req(Method::POST, "/intercept/forward-all"))
            .await?;
        Ok(r.forwarded)
    }

    // --- proxy ---------------------------------------------------------------------------------------------

    pub async fn proxy_info(&self) -> Result<ProxyInfo> {
        self.json(self.req(Method::GET, "/proxy")).await
    }

    /// Import request definitions (OpenAPI, GraphQL introspection, Postman, HAR, URL list or Burp XML) as Repeater
    /// tabs. `body` is the `ImportBody` of the API: `format`, `content`, and optionally `base_url` and `dry_run`.
    /// Nothing is sent; the reply lists what was found and the hosts involved.
    pub async fn import_requests(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, "/import").json(body)).await
    }

    /// The proxy listeners (`ListenerInfo` in the OpenAPI description; passwords are never returned).
    pub async fn list_listeners(&self) -> Result<Vec<serde_json::Value>> {
        self.json(self.req(Method::GET, "/proxy/listeners")).await
    }

    /// Start another proxy listener. `spec` is the `ListenerSpec` of the API: `addr` and optionally `invisible`,
    /// `tls_passthrough`, `auth` and `allow_clients`. Needs the admin role.
    pub async fn add_listener(&self, spec: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, "/proxy/listeners").json(spec))
            .await
    }

    /// Change a listener's options live. Needs the admin role.
    pub async fn update_listener(&self, id: u32, spec: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(
            self.req(Method::PUT, &format!("/proxy/listeners/{id}"))
                .json(spec),
        )
        .await
    }

    /// Stop an added listener. Needs the admin role.
    pub async fn remove_listener(&self, id: u32) -> Result<()> {
        self.unit(self.req(Method::DELETE, &format!("/proxy/listeners/{id}")))
            .await
    }

    /// The live proxy settings and the names of the settings that need a restart.
    pub async fn proxy_config(&self) -> Result<serde_json::Value> {
        self.json(self.req(Method::GET, "/proxy/config")).await
    }

    /// Change the live proxy settings (all of `LiveSettings`). A setting that needs a restart is a 409.
    pub async fn put_proxy_config(&self, live: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::PUT, "/proxy/config").json(live)).await
    }

    /// Send a raw request through the Repeater. `body` is the `SendBody` of the API (see `docs/openapi.json`):
    /// target, base64 request, and optionally protocol, count and mode. Returns the reply with one result per send.
    pub async fn repeater_send(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, "/repeater/send").json(body))
            .await
    }

    /// Open a WebSocket, send frames and listen. `body` is the `WsBody` of the API.
    pub async fn repeater_ws(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, "/repeater/ws").json(body)).await
    }

    /// Run a chain of decoders. `body` is the `DecodeBody` of the API: base64 `input` and a list of `ops`.
    pub async fn decoder_apply(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, "/decoder/apply").json(body))
            .await
    }

    /// Guess and apply a chain of decoders on base64 `input`.
    pub async fn decoder_smart(&self, input_b64: &str) -> Result<serde_json::Value> {
        self.json(
            self.req(Method::POST, "/decoder/smart")
                .json(&json!({ "input": input_b64 })),
        )
        .await
    }

    /// Analyse how random a set of tokens is (20 to 10000). Returns the `Analysis` of the API: statistics, FIPS 140-2
    /// results, an entropy estimate and a `verdict` (`excellent`, `good`, `poor`, `not_random`).
    pub async fn sequencer_analyze(&self, tokens: &[String]) -> Result<serde_json::Value> {
        self.json(
            self.req(Method::POST, "/sequencer/analyze")
                .json(&json!({ "tokens": tokens })),
        )
        .await
    }

    /// Start a live capture. `body` is the `CaptureBody` of the API: target, base64 request, `source` (header,
    /// cookie or regex), `count` and optionally `delay_ms`. Returns `{ "id": n }`.
    pub async fn sequencer_capture(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, "/sequencer/capture").json(body))
            .await
    }

    /// The progress of a capture, with its tokens from index `from` on.
    pub async fn sequencer_capture_status(&self, id: u64, from: usize) -> Result<serde_json::Value> {
        self.json(self.req(Method::GET, &format!("/sequencer/capture/{id}?from={from}")))
            .await
    }

    /// Stop a capture after the request in flight.
    pub async fn sequencer_capture_stop(&self, id: u64) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, &format!("/sequencer/capture/{id}/stop")))
            .await
    }

    /// Compare two base64 inputs; `level` is `words` or `bytes`.
    pub async fn comparer_diff(&self, a_b64: &str, b_b64: &str, level: &str) -> Result<serde_json::Value> {
        self.json(
            self.req(Method::POST, "/comparer/diff")
                .json(&json!({ "a": a_b64, "b": b_b64, "level": level })),
        )
        .await
    }

    /// Whether the Repeater may send out of scope.
    pub async fn repeater_settings(&self) -> Result<bool> {
        #[derive(serde::Deserialize)]
        struct R {
            allow_out_of_scope: bool,
        }
        let r: R = self.json(self.req(Method::GET, "/repeater/settings")).await?;
        Ok(r.allow_out_of_scope)
    }

    /// Allow or refuse out-of-scope sends from the Repeater. Returns the new state.
    pub async fn put_repeater_settings(&self, allow_out_of_scope: bool) -> Result<bool> {
        #[derive(serde::Deserialize)]
        struct R {
            allow_out_of_scope: bool,
        }
        let r: R = self
            .json(
                self.req(Method::PUT, "/repeater/settings")
                    .json(&json!({ "allow_out_of_scope": allow_out_of_scope })),
            )
            .await?;
        Ok(r.allow_out_of_scope)
    }

    /// The Repeater's saved tabs (`tabs`, `active`, `next`).
    pub async fn repeater_tabs(&self) -> Result<serde_json::Value> {
        self.json(self.req(Method::GET, "/repeater/tabs")).await
    }

    /// Replace the Repeater's saved tabs.
    pub async fn put_repeater_tabs(&self, doc: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::PUT, "/repeater/tabs").json(doc)).await
    }

    /// Check an attack without sending anything. `body` is the `StartBody` of the API: target, base64 request with
    /// `§` around each position, attack type and payload sets (and optionally options and grep rules). Returns the
    /// number of requests and the first few payloads, or an error that says what is wrong.
    pub async fn intruder_plan(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, "/intruder/plan").json(body))
            .await
    }

    /// Like [`Client::intruder_plan`], listing the payloads of the first `limit` requests (at most 1000).
    pub async fn intruder_plan_limit(
        &self,
        body: &serde_json::Value,
        limit: u32,
    ) -> Result<serde_json::Value> {
        self.json(
            self.req(Method::POST, "/intruder/plan")
                .query(&[("limit", limit)])
                .json(body),
        )
        .await
    }

    /// Start an Intruder attack (same body as [`Client::intruder_plan`]). Returns the attack as it starts; results
    /// arrive as `IntruderResult` events and can be read with [`Client::intruder_results`].
    pub async fn intruder_start(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, "/intruder/attacks").json(body))
            .await
    }

    /// The project's Intruder attacks, newest first.
    pub async fn intruder_attacks(&self) -> Result<serde_json::Value> {
        self.json(self.req(Method::GET, "/intruder/attacks")).await
    }

    /// One attack with its request and configuration.
    pub async fn intruder_attack(&self, id: i64) -> Result<serde_json::Value> {
        self.json(self.req(Method::GET, &format!("/intruder/attacks/{id}")))
            .await
    }

    /// A page of an attack's results, in request order (at most 5000 a page).
    pub async fn intruder_results(&self, id: i64, offset: u64, limit: u64) -> Result<serde_json::Value> {
        self.json(
            self.req(Method::GET, &format!("/intruder/attacks/{id}/results"))
                .query(&[("offset", offset), ("limit", limit)]),
        )
        .await
    }

    /// Throw the stop switch of an attack. False if it was not running.
    pub async fn intruder_stop(&self, id: i64) -> Result<bool> {
        #[derive(serde::Deserialize)]
        struct R {
            stopped: bool,
        }
        let r: R = self
            .json(self.req(Method::POST, &format!("/intruder/attacks/{id}/stop")))
            .await?;
        Ok(r.stopped)
    }

    /// Delete an attack and its results.
    pub async fn intruder_delete(&self, id: i64) -> Result<()> {
        self.unit(self.req(Method::DELETE, &format!("/intruder/attacks/{id}")))
            .await
    }

    /// Start a spider crawl. `body` is the `StartBody` of the API: `start` URLs and optionally depth, page limit,
    /// form options and headers. Returns the crawl as it starts.
    pub async fn crawl_start(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, "/crawl/crawls").json(body))
            .await
    }

    /// The crawls of this run of the server, newest first.
    pub async fn crawl_list(&self) -> Result<serde_json::Value> {
        self.json(self.req(Method::GET, "/crawl/crawls")).await
    }

    /// One crawl with its pages from index `from` on.
    pub async fn crawl_get(&self, id: u64, from: usize) -> Result<serde_json::Value> {
        self.json(self.req(Method::GET, &format!("/crawl/crawls/{id}?from={from}")))
            .await
    }

    /// Throw the stop switch of a crawl.
    pub async fn crawl_stop(&self, id: u64) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, &format!("/crawl/crawls/{id}/stop")))
            .await
    }

    /// Start an active scan. `body` is the `ScanStartBody` of the API: `targets` (each a `url`, optionally with
    /// `method`, `headers`, `body`, `content_type`) and optionally `checks`, `strength`, `concurrency`, `delay_ms`,
    /// `max_requests`. Returns the scan as it starts.
    pub async fn scan_start(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, "/scan/scans").json(body)).await
    }

    /// The scans of this run of the server, newest first.
    pub async fn scan_list(&self) -> Result<serde_json::Value> {
        self.json(self.req(Method::GET, "/scan/scans")).await
    }

    /// The active checks: id and description.
    pub async fn scan_checks(&self) -> Result<serde_json::Value> {
        self.json(self.req(Method::GET, "/scan/checks")).await
    }

    /// One scan with its progress and findings.
    pub async fn scan_get(&self, id: u64) -> Result<serde_json::Value> {
        self.json(self.req(Method::GET, &format!("/scan/scans/{id}")))
            .await
    }

    /// Throw the stop switch of a scan.
    pub async fn scan_stop(&self, id: u64) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, &format!("/scan/scans/{id}/stop")))
            .await
    }

    /// Pause a scan: no request starts until it is resumed.
    pub async fn scan_pause(&self, id: u64) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, &format!("/scan/scans/{id}/pause")))
            .await
    }

    /// Resume a paused scan.
    pub async fn scan_resume(&self, id: u64) -> Result<serde_json::Value> {
        self.json(self.req(Method::POST, &format!("/scan/scans/{id}/resume")))
            .await
    }

    /// The kill switch for all tool traffic. Returns the new state.
    pub async fn set_stopped(&self, stopped: bool) -> Result<bool> {
        #[derive(serde::Deserialize)]
        struct R {
            stopped: bool,
        }
        let r: R = self
            .json(
                self.req(Method::PUT, "/tools/stop")
                    .json(&json!({ "stopped": stopped })),
            )
            .await?;
        Ok(r.stopped)
    }

    pub async fn ca_info(&self) -> Result<CaInfo> {
        self.json(self.req(Method::GET, "/ca")).await
    }

    /// The CA certificate as PEM text.
    pub async fn ca_pem(&self) -> Result<String> {
        Ok(self
            .check(self.req(Method::GET, "/ca/cert.pem").send().await?)
            .await?
            .text()
            .await?)
    }

    /// Start a browser set up for the proxy. Returns the browser's name.
    pub async fn launch_browser(&self) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct R {
            launched: String,
        }
        let r: R = self.json(self.req(Method::POST, "/browser/launch")).await?;
        Ok(r.launched)
    }

    // --- projects ------------------------------------------------------------------------------------------

    pub async fn list_projects(&self) -> Result<ProjectList> {
        self.json(self.req(Method::GET, "/projects")).await
    }

    pub async fn create_project(&self, name: &str, open: bool) -> Result<ProjectInfo> {
        self.json(
            self.req(Method::POST, "/projects")
                .json(&json!({ "name": name, "open": open })),
        )
        .await
    }

    /// Switch to a project. Every connected client is told to reload.
    pub async fn open_project(&self, name: &str) -> Result<CurrentProject> {
        self.json(self.req(Method::POST, &format!("/projects/{}/open", enc(name))))
            .await
    }

    /// Close the project; a temporary in-memory one opens in its place.
    pub async fn close_project(&self) -> Result<CurrentProject> {
        self.json(self.req(Method::POST, "/projects/close")).await
    }

    pub async fn rename_project(&self, name: &str, to: &str) -> Result<ProjectInfo> {
        self.json(
            self.req(Method::POST, &format!("/projects/{}/rename", enc(name)))
                .json(&json!({ "name": to })),
        )
        .await
    }

    pub async fn delete_project(&self, name: &str) -> Result<()> {
        self.unit(self.req(Method::DELETE, &format!("/projects/{}", enc(name))))
            .await
    }

    /// The project file's bytes (a consistent copy, also of the open project).
    pub async fn export_project(&self, name: &str) -> Result<Vec<u8>> {
        let r = self
            .req(Method::GET, &format!("/projects/{}/export", enc(name)))
            .send()
            .await?;
        Ok(self.check(r).await?.bytes().await?.to_vec())
    }

    /// Import a project file under `name`. The file is checked and rebuilt, never opened as it came.
    pub async fn import_project(&self, name: &str, file: Vec<u8>, open: bool) -> Result<ProjectInfo> {
        self.json(
            self.req(Method::POST, "/projects/import")
                .query(&[("name", name), ("open", if open { "true" } else { "false" })])
                .header("content-type", "application/octet-stream")
                .body(file),
        )
        .await
    }

    /// Save a copy in the engine's backups folder.
    pub async fn backup_project(&self, name: &str) -> Result<BackupInfo> {
        self.json(self.req(Method::POST, &format!("/projects/{}/backup", enc(name))))
            .await
    }

    // --- accounts ------------------------------------------------------------------------------------------

    pub async fn tokens(&self) -> Result<Vec<ApiToken>> {
        self.json(self.req(Method::GET, "/tokens")).await
    }

    pub async fn create_token(
        &self,
        name: &str,
        expires_days: Option<u32>,
        scope: Option<TokenScope>,
    ) -> Result<NewToken> {
        self.json(
            self.req(Method::POST, "/tokens")
                .json(&json!({ "name": name, "expires_days": expires_days, "scope": scope })),
        )
        .await
    }

    pub async fn delete_token(&self, id: i64) -> Result<()> {
        self.unit(self.req(Method::DELETE, &format!("/tokens/{id}")))
            .await
    }

    pub async fn users(&self) -> Result<Vec<User>> {
        self.json(self.req(Method::GET, "/users")).await
    }

    pub async fn create_user(&self, username: &str, password: &str, role: Role) -> Result<User> {
        self.json(
            self.req(Method::POST, "/users")
                .json(&json!({ "username": username, "password": password, "role": role })),
        )
        .await
    }

    pub async fn delete_user(&self, id: i64) -> Result<()> {
        self.unit(self.req(Method::DELETE, &format!("/users/{id}"))).await
    }

    pub async fn set_user_role(&self, id: i64, role: Role) -> Result<()> {
        self.unit(
            self.req(Method::PUT, &format!("/users/{id}/role"))
                .json(&json!({ "role": role })),
        )
        .await
    }

    pub async fn user_sessions(&self, id: i64) -> Result<Vec<SessionInfo>> {
        self.json(self.req(Method::GET, &format!("/users/{id}/sessions")))
            .await
    }

    /// End all of a user's sessions; returns how many.
    pub async fn revoke_user_sessions(&self, id: i64) -> Result<u64> {
        #[derive(serde::Deserialize)]
        struct R {
            revoked: u64,
        }
        let r: R = self
            .json(self.req(Method::DELETE, &format!("/users/{id}/sessions")))
            .await?;
        Ok(r.revoked)
    }

    pub async fn revoke_user_session(&self, id: i64, session_id: &str) -> Result<()> {
        self.unit(self.req(Method::DELETE, &format!("/users/{id}/sessions/{session_id}")))
            .await
    }

    pub async fn user_tokens(&self, id: i64) -> Result<Vec<ApiToken>> {
        self.json(self.req(Method::GET, &format!("/users/{id}/tokens")))
            .await
    }

    pub async fn revoke_user_token(&self, id: i64, token_id: i64) -> Result<()> {
        self.unit(self.req(Method::DELETE, &format!("/users/{id}/tokens/{token_id}")))
            .await
    }

    pub async fn audit(&self, before: Option<i64>, limit: Option<u32>) -> Result<Vec<AuditEntry>> {
        self.json(
            self.req(Method::GET, "/audit")
                .query(&[("before", before), ("limit", limit.map(i64::from))]),
        )
        .await
    }

    // --- client certificates -----------------------------------------------------------------------------------

    pub async fn client_certs(&self) -> Result<Vec<ClientCert>> {
        Ok(self
            .json::<ClientCertList>(self.req(Method::GET, "/client-certs"))
            .await?
            .certs)
    }

    /// Add a client certificate for a host pattern from a PEM file (certificate and key) or a base64 PKCS#12 file.
    /// Needs the admin role.
    pub async fn add_client_cert(
        &self,
        host: &str,
        pem: Option<&str>,
        pkcs12_base64: Option<&str>,
        password: Option<&str>,
    ) -> Result<ClientCert> {
        self.json(self.req(Method::POST, "/client-certs").json(&json!({
            "host": host, "pem": pem, "pkcs12_base64": pkcs12_base64, "password": password
        })))
        .await
    }

    pub async fn delete_client_cert(&self, id: i64) -> Result<()> {
        self.unit(self.req(Method::DELETE, &format!("/client-certs/{id}")))
            .await
    }

    // --- custom checks ---------------------------------------------------------------------------------------

    pub async fn checks(&self) -> Result<Vec<CustomCheck>> {
        Ok(self
            .json::<CustomCheckList>(self.req(Method::GET, "/checks"))
            .await?
            .checks)
    }

    /// Add a custom passive check (YAML). A 400 error carries what is wrong with it.
    pub async fn add_check(&self, yaml: &str) -> Result<CustomCheck> {
        self.json(self.req(Method::POST, "/checks").json(&json!({ "yaml": yaml })))
            .await
    }

    /// Validate without storing.
    pub async fn validate_check(&self, yaml: &str) -> Result<CheckValidation> {
        self.json(
            self.req(Method::POST, "/checks/validate")
                .json(&json!({ "yaml": yaml })),
        )
        .await
    }

    pub async fn replace_check(&self, id: i64, yaml: &str) -> Result<CustomCheck> {
        self.json(
            self.req(Method::PUT, &format!("/checks/{id}"))
                .json(&json!({ "yaml": yaml })),
        )
        .await
    }

    pub async fn set_check_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        self.unit(
            self.req(Method::PATCH, &format!("/checks/{id}"))
                .json(&json!({ "enabled": enabled })),
        )
        .await
    }

    pub async fn delete_check(&self, id: i64) -> Result<()> {
        self.unit(self.req(Method::DELETE, &format!("/checks/{id}")))
            .await
    }

    // --- issues (passive scanner) --------------------------------------------------------------------------

    pub async fn issues(&self, q: &IssueQuery) -> Result<IssueList> {
        self.json(self.req(Method::GET, "/issues").query(q)).await
    }

    pub async fn issue(&self, id: i64) -> Result<Issue> {
        self.json(self.req(Method::GET, &format!("/issues/{id}"))).await
    }

    pub async fn change_issue(&self, id: i64, status: IssueStatus) -> Result<()> {
        self.unit(
            self.req(Method::PATCH, &format!("/issues/{id}"))
                .json(&json!({ "status": status })),
        )
        .await
    }

    /// The issues as a report file (`format`: html, json, sarif, junit or markdown). Secrets are redacted unless
    /// `redact` is false (tester role; audited).
    pub async fn issues_report(&self, q: &IssueQuery, format: &str, redact: bool) -> Result<Bytes> {
        let mut rb = self
            .req(Method::GET, "/issues/report")
            .query(q)
            .query(&[("format", format)]);
        if !redact {
            rb = rb.query(&[("redact", "0")]);
        }
        Ok(self.check(rb.send().await?).await?.bytes().await?)
    }

    /// One issue prepared for a tracker (`github`, `jira` or `linear`): title, Markdown body and the create-issue
    /// JSON, to copy or post by hand. Secrets are redacted unless `redact` is false (tester role; audited either way).
    pub async fn issue_tracker(&self, id: i64, tracker: &str, redact: bool) -> Result<serde_json::Value> {
        let mut rb = self
            .req(Method::GET, &format!("/issues/{id}/tracker"))
            .query(&[("tracker", tracker)]);
        if !redact {
            rb = rb.query(&[("redact", "0")]);
        }
        Ok(self.check(rb.send().await?).await?.json().await?)
    }

    /// Queue every recorded flow for the scanner again.
    pub async fn rescan_issues(&self) -> Result<()> {
        self.unit(self.req(Method::POST, "/issues/rescan")).await
    }

    // --- events --------------------------------------------------------------------------------------------

    /// Open the live event stream. Pass the [`Position`] of an earlier stream to be sent what it missed.
    pub async fn events(&self, resume: Option<&Position>) -> Result<EventStream> {
        EventStream::connect(self.clone(), resume.cloned()).await
    }
}

/// Percent-encode a path segment.
fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
