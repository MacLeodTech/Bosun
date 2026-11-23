//! Single sign-on with OpenID Connect, next to the local accounts.
//!
//! Two ways in, both ending in the same kind of session as a password login:
//!
//! - **OIDC**: the browser goes to the provider (authorization code + PKCE + nonce) and comes back to
//!   `/auth/oidc/callback`.
//! - **Edge SSO**: a trusted front door (Caddy + oauth2-proxy) already signed the person in and forwards the
//!   provider's ID token as `Authorization: Bearer`. `/auth/oidc/edge` verifies that token itself (signature,
//!   issuer, expiry, and an audience that is the proxy's client id), accepts it only from a trusted proxy address
//!   (the TCP peer, never a forwarded header), and then applies the same email allow-list.
//!
//! Who may sign in is an explicit `email_roles` list; an empty list lets nobody in. Local accounts keep working, so a
//! provider outage never locks the admin out. These routes sit outside `/api/`: the browser reaches them through a
//! cross-site redirect, which the API's `Sec-Fetch-Site` rule refuses by design.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bosun_store::Role;
use ipnet::IpNet;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreClient, CoreIdToken, CoreIdTokenClaims, CoreProviderMetadata, CoreResponseType},
    reqwest,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use crate::{AppState, Peer};

/// A client for the given provider metadata (the typestate type is unwieldy to name).
macro_rules! client {
    ($meta:expr, $id:expr, $secret:expr) => {
        CoreClient::from_provider_metadata(
            $meta,
            ClientId::new($id.to_string()),
            $secret.map(ClientSecret::new),
        )
    };
}

type R<T> = Result<T, String>;

const COOKIE: &str = "bosun_sso";
const REFRESH: Duration = Duration::from_secs(3600);
const PENDING_TTL: Duration = Duration::from_secs(600);

/// `[api.sso]` in the config file.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SsoConfig {
    pub issuer: String,
    pub client_id: String,
    /// Prefer the `BOSUN_OIDC_CLIENT_SECRET` environment variable over writing this in the file.
    #[serde(skip_serializing)]
    pub client_secret: Option<String>,
    /// `https://bosun.example.com`: the redirect URI is `<public_url>/auth/oidc/callback`.
    pub public_url: String,
    /// Button label, e.g. "Google".
    pub name: String,
    /// Lower-case email -> `admin`, `tester` or `viewer`.
    pub email_roles: BTreeMap<String, String>,
    /// Edge SSO: the client id of the sign-in proxy whose forwarded ID token is accepted.
    pub edge_audience: Option<String>,
    /// Edge SSO: addresses allowed to present such a token.
    pub edge_trusted_proxies: Vec<IpNet>,
}

impl std::fmt::Debug for SsoConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoConfig")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl SsoConfig {
    /// Refuse a half-configured setup so a typo cannot leave the door open or unusable.
    pub fn validate(&self) -> Result<(), String> {
        let local = |u: &str| u.starts_with("http://127.0.0.1") || u.starts_with("http://localhost");
        if self.issuer.is_empty() || self.client_id.is_empty() || self.secret().is_none() {
            return Err("sso needs issuer, client_id and a client secret (BOSUN_OIDC_CLIENT_SECRET)".into());
        }
        if !self.issuer.starts_with("https://") && !local(&self.issuer) {
            return Err("sso issuer must be an https URL".into());
        }
        if !self.public_url.starts_with("https://") && !local(&self.public_url) {
            return Err("sso public_url must be the https address people use".into());
        }
        if self.email_roles.is_empty() {
            return Err(
                "sso email_roles must name who may sign in: an empty list would let nobody in".into(),
            );
        }
        for (e, r) in &self.email_roles {
            if !e.contains('@') || e.to_ascii_lowercase() != *e || Role::parse(r).is_none() {
                return Err(format!(
                    "sso email_roles {e:?} = {r:?}: want a lower-case email and admin, tester or viewer"
                ));
            }
        }
        if self.edge_audience.as_deref().is_some_and(|a| !a.is_empty())
            && self.edge_trusted_proxies.is_empty()
        {
            return Err(
                "sso edge_audience needs edge_trusted_proxies: only the sign-in proxy may present a token"
                    .into(),
            );
        }
        Ok(())
    }

    fn secret(&self) -> Option<String> {
        std::env::var("BOSUN_OIDC_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| self.client_secret.clone().filter(|s| !s.is_empty()))
    }
}

struct Pending {
    nonce: String,
    verifier: String,
    expires: Instant,
}

/// Provider state: discovery is lazy (a provider outage at start-up must not stop Bosun) and refreshed hourly.
pub struct Sso {
    cfg: SsoConfig,
    http: reqwest::Client,
    meta: RwLock<Option<(CoreProviderMetadata, Instant)>>,
    pending: Mutex<HashMap<String, Pending>>,
}

/// Who the provider says signed in.
struct Identity {
    issuer: String,
    subject: String,
    email: Option<String>,
}

impl Sso {
    pub fn new(cfg: &SsoConfig) -> Result<Self, String> {
        cfg.validate()?;
        let http = reqwest::ClientBuilder::new()
            // Following redirects here would allow SSRF; providers don't need it.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            cfg: cfg.clone(),
            http,
            meta: RwLock::new(None),
            pending: Mutex::new(HashMap::new()),
        })
    }

    async fn fetch(&self) -> R<CoreProviderMetadata> {
        let issuer = IssuerUrl::new(self.cfg.issuer.clone()).map_err(|e| e.to_string())?;
        CoreProviderMetadata::discover_async(issuer, &self.http)
            .await
            .map_err(|e| format!("provider discovery: {e}"))
    }

    async fn metadata(&self) -> R<CoreProviderMetadata> {
        if let Some((m, at)) = self.meta.read().await.as_ref()
            && at.elapsed() < REFRESH
        {
            return Ok(m.clone());
        }
        self.refresh().await
    }

    async fn refresh(&self) -> R<CoreProviderMetadata> {
        let fresh = self.fetch().await?;
        *self.meta.write().await = Some((fresh.clone(), Instant::now()));
        Ok(fresh)
    }

    fn redirect_url(&self) -> String {
        format!("{}/auth/oidc/callback", self.cfg.public_url.trim_end_matches('/'))
    }

    fn edge_peer_trusted(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.cfg.edge_audience.as_deref().is_some_and(|a| !a.is_empty())
            && self.cfg.edge_trusted_proxies.iter().any(|n| n.contains(&ip))
    }

    fn edge_on(&self) -> bool {
        self.cfg.edge_audience.as_deref().is_some_and(|a| !a.is_empty())
    }

    /// Verify the ID token the sign-in proxy forwarded. Same signature, issuer and expiry checks as the callback, but
    /// the audience is the proxy's client id and there is no nonce (the proxy ran the browser flow).
    async fn verify_edge(&self, raw: &str) -> R<Identity> {
        let aud = self
            .cfg
            .edge_audience
            .clone()
            .ok_or("Edge SSO is not configured")?;
        let token: CoreIdToken = raw.parse().map_err(|_| "not an ID token".to_string())?;
        let no_nonce = |_: Option<&Nonce>| Ok(());
        let client = client!(self.metadata().await?, aud, None::<String>);
        if let Ok(claims) = token.claims(&client.id_token_verifier(), no_nonce) {
            return Ok(identity(claims));
        }
        // Keys may have rotated since we last looked: refresh once and verify again.
        let client = client!(self.refresh().await?, aud, None::<String>);
        let claims = token
            .claims(&client.id_token_verifier(), no_nonce)
            .map_err(|e| format!("ID token rejected: {e}"))?;
        Ok(identity(claims))
    }
}

fn identity(claims: &CoreIdTokenClaims) -> Identity {
    // Only a provider-verified email is an identity; the allow-list is keyed on it.
    let email = claims
        .email()
        .filter(|_| claims.email_verified() == Some(true))
        .map(|e| e.as_str().to_ascii_lowercase());
    Identity {
        issuer: claims.issuer().as_str().to_string(),
        subject: claims.subject().as_str().to_string(),
        email,
    }
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn fail(msg: &str) -> Response {
    redirect(&format!("/?sso_error={}", enc(msg)), None)
}

fn redirect(to: &str, cookie: Option<HeaderValue>) -> Response {
    let mut r = (StatusCode::FOUND, [(header::LOCATION, to)]).into_response();
    if let Some(c) = cookie {
        r.headers_mut().append(header::SET_COOKIE, c);
    }
    r
}

fn pending_cookie(st: &AppState, value: &str, max_age: i64) -> HeaderValue {
    // Lax: the provider sends the browser back with a cross-site navigation, which Strict would not carry.
    let mut c = cookie::Cookie::build((COOKIE, value.to_string()))
        .http_only(true)
        .same_site(cookie::SameSite::Lax)
        .path("/auth/oidc")
        .max_age(cookie::time::Duration::seconds(max_age));
    if st.inner.secure_cookies {
        c = c.secure(true);
    }
    HeaderValue::from_str(&c.build().to_string()).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// `GET /api/v1/auth/sso`: what the sign-in page may offer.
pub async fn config(State(st): State<AppState>) -> Response {
    let Some(s) = &st.inner.sso else {
        return Json(serde_json::json!({ "sso": null })).into_response();
    };
    let name = if s.cfg.name.is_empty() {
        "single sign-on"
    } else {
        &s.cfg.name
    };
    Json(serde_json::json!({ "sso": {
        "name": name,
        "login": "/auth/oidc/login",
        "edge": s.edge_on().then_some("/auth/oidc/edge"),
    }}))
    .into_response()
}

/// `GET /auth/oidc/login`: send the browser to the provider.
pub async fn login(State(st): State<AppState>) -> Response {
    let Some(s) = &st.inner.sso else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let meta = match s.metadata().await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("{e}");
            return fail("the sign-in provider could not be reached");
        }
    };
    let Ok(redirect_url) = RedirectUrl::new(s.redirect_url()) else {
        return fail("sign-in is misconfigured");
    };
    let client = client!(meta, s.cfg.client_id, s.cfg.secret()).set_redirect_uri(redirect_url);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .set_pkce_challenge(challenge)
        .url();
    {
        let mut p = s.pending.lock().unwrap_or_else(|e| e.into_inner());
        p.retain(|_, v| v.expires > Instant::now());
        if p.len() > 2000 {
            return fail("too many sign-ins in progress; try again shortly");
        }
        p.insert(
            state.secret().clone(),
            Pending {
                nonce: nonce.secret().clone(),
                verifier: verifier.secret().clone(),
                expires: Instant::now() + PENDING_TTL,
            },
        );
    }
    redirect(
        url.as_str(),
        Some(pending_cookie(&st, state.secret(), PENDING_TTL.as_secs() as i64)),
    )
}

/// `GET /auth/oidc/callback`: the provider sends the browser back here.
pub async fn callback(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(s) = &st.inner.sso else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let clear = pending_cookie(&st, "", 0);
    let state = q.get("state").cloned().unwrap_or_default();
    let jar = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| cookie::Cookie::parse(c.trim().to_string()).ok())
        .find(|c| c.name() == COOKIE)
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    // A state works once, and only in the browser that started it.
    let pending = s.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&state);
    let Some(p) =
        pending.filter(|p| p.expires > Instant::now() && bool::from(jar.as_bytes().ct_eq(state.as_bytes())))
    else {
        return redirect(
            "/?sso_error=the%20sign-in%20expired%20or%20did%20not%20start%20here%3B%20try%20again",
            Some(clear),
        );
    };
    if q.contains_key("error") {
        return with(fail("the provider refused the sign-in"), clear);
    }
    let Some(code) = q.get("code") else {
        return with(fail("the provider sent no code"), clear);
    };
    let meta = match s.metadata().await {
        Ok(m) => m,
        Err(_) => return with(fail("the sign-in provider could not be reached"), clear),
    };
    let Ok(redirect_url) = RedirectUrl::new(s.redirect_url()) else {
        return with(fail("sign-in is misconfigured"), clear);
    };
    let client = client!(meta, s.cfg.client_id, s.cfg.secret()).set_redirect_uri(redirect_url);
    let exchange = match client.exchange_code(AuthorizationCode::new(code.clone())) {
        Ok(x) => x.set_pkce_verifier(PkceCodeVerifier::new(p.verifier.clone())),
        Err(_) => return with(fail("sign-in is misconfigured"), clear),
    };
    let tokens = match exchange.request_async(&s.http).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("sso token request failed: {e}");
            return with(fail("the provider rejected the sign-in"), clear);
        }
    };
    let Some(id_token) = tokens.id_token() else {
        return with(fail("the provider sent no identity token"), clear);
    };
    let nonce = Nonce::new(p.nonce.clone());
    let id = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(c) => identity(c),
        Err(_) => {
            // The provider may have rotated its keys since we last looked: refresh once and verify again.
            let Ok(fresh) = s.refresh().await else {
                return with(fail("the provider's identity token was not valid"), clear);
            };
            let client = client!(fresh, s.cfg.client_id, s.cfg.secret());
            match id_token.claims(&client.id_token_verifier(), &nonce) {
                Ok(c) => identity(c),
                Err(e) => {
                    tracing::warn!("sso id token rejected: {e}");
                    return with(fail("the provider's identity token was not valid"), clear);
                }
            }
        }
    };
    with(finish(&st, s, id, "oidc", None).await, clear)
}

/// `GET /auth/oidc/edge`: sign in with the ID token the trusted front door forwarded.
pub async fn edge(
    State(st): State<AppState>,
    peer: Option<axum::Extension<Peer>>,
    headers: HeaderMap,
) -> Response {
    let Some(s) = &st.inner.sso else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !s.edge_on() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let ip = peer.map(|p| p.0.0.ip());
    let remote = ip.map(|i| i.to_string()).unwrap_or_default();
    let ip_key = format!("ip:{remote}");
    let audit = async |what: &str, who: Option<&str>| {
        st.audit(
            who.map(str::to_string),
            "login.failed",
            what,
            Some(remote.clone()),
        )
        .await;
    };
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.len() <= 8192);
    let (Some(raw), Some(ip)) = (raw, ip) else {
        audit("Edge SSO: no token", None).await;
        return fail("this sign-in only works through the sign-in proxy");
    };
    if !s.edge_peer_trusted(ip) {
        audit("Edge SSO: not from a trusted proxy", None).await;
        return fail("this sign-in only works through the sign-in proxy");
    }
    if st.inner.limiter.blocked(&ip_key) {
        return fail("too many failed attempts; try again in a few minutes");
    }
    match s.verify_edge(raw).await {
        Ok(id) => finish(&st, s, id, "edge", Some(&ip_key)).await,
        Err(e) => {
            tracing::warn!("edge sso: {e}");
            st.inner.limiter.fail(&ip_key);
            audit("Edge SSO: token refused", None).await;
            fail("the identity token from the sign-in proxy was not valid")
        }
    }
}

fn with(mut r: Response, cookie: HeaderValue) -> Response {
    r.headers_mut().append(header::SET_COOKIE, cookie);
    r
}

/// Any sign-in, once the token is verified: a verified, listed email gets a role, an account and a session.
async fn finish(st: &AppState, s: &Sso, id: Identity, how: &str, fail_key: Option<&str>) -> Response {
    let refuse = async |why: &str, who: Option<&str>, msg: &str| {
        if let Some(k) = fail_key {
            st.inner.limiter.fail(k);
        }
        st.audit(
            who.map(str::to_string),
            "login.refused",
            &format!("{how}: {why}"),
            None,
        )
        .await;
        fail(msg)
    };
    let Some(email) = id.email else {
        return refuse(
            "email missing or not verified",
            None,
            "your email address is not verified with the provider",
        )
        .await;
    };
    let Some(role) = s.cfg.email_roles.get(&email).and_then(|r| Role::parse(r)) else {
        return refuse(
            "not on the allow-list",
            Some(&email),
            "your account has no access here; ask an admin",
        )
        .await;
    };
    let app = st.inner.app.clone();
    let key = format!("{}|{}", id.issuer, id.subject);
    let e2 = email.clone();
    let user = match tokio::task::spawn_blocking(move || app.ensure_sso_user(&key, &e2, role)).await {
        Ok(Ok(u)) => u,
        _ => return fail("could not set up your account"),
    };
    let cookie = match crate::auth::new_session_cookie(st, &user).await {
        Ok(c) => c,
        Err(_) => return fail("could not create a session"),
    };
    st.audit(
        Some(user.username.clone()),
        "login",
        &format!("signed in ({how})"),
        None,
    )
    .await;
    redirect("/", Some(cookie))
}
