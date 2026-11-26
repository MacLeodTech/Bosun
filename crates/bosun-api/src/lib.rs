//! The Bosun API and web UI server.
//!
//! One versioned API (`/api/v1`) serves every front end: the web UI, the desktop shell, the CLI and scripts.
//! See [`security`] for the request-level defences and [`auth`] for accounts and sessions.

// Handlers return `Result<Response, Response>` (axum's idiom); the error side is a whole response by design.
#![allow(clippy::result_large_err)]

pub mod auth;
pub mod browser;
pub mod child;
pub mod codec;
pub mod engage;
pub mod events;
pub mod handlers;
pub mod openapi;
pub mod projects;
pub mod repeater;
pub mod security;
pub mod sso;
pub mod totp;
pub mod web;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::routing::{get, post, put};
use bosun_ca::CertificateAuthority;
use bosun_proxy::{ConnLimit, EventSender, LoopGuard, Proxy};
use bosun_scope::Gate;
use bosun_store::{AppDb, Project};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower::ServiceExt;

pub use browser::BrowserLauncher;

/// Largest project file the API accepts for import.
pub const MAX_PROJECT_UPLOAD: u64 = 2 << 30;

pub const SETTING_SCOPE: &str = "scope";
pub const SETTING_RULES: &str = "match_replace";
pub const SETTING_SAVED_FILTERS: &str = "saved_filters";
pub const SETTING_INTERCEPT: &str = "intercept";
pub const SETTING_REPEATER_TABS: &str = "repeater_tabs";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    /// UI/API listener. Loopback by default.
    pub listen: SocketAddr,
    /// Host names the UI may be reached by (Host header allowlist, against DNS rebinding). Loopback names
    /// are always allowed.
    pub hosts: Vec<String>,
    /// Extra exact origins allowed in the Origin header, e.g. `https://bosun.lab.example` behind a reverse proxy.
    pub origins: Vec<String>,
    /// Serve the UI over HTTPS. With `tls_cert` and `tls_key` that certificate is used (re-read when the files
    /// change or on SIGHUP); without them a self-signed certificate made for the UI alone is used. It never comes
    /// from the interception CA. A TLS-terminating reverse proxy in front is the recommended setup.
    pub tls: bool,
    /// PEM certificate chain (leaf first) for the UI.
    pub tls_cert: Option<std::path::PathBuf>,
    /// PEM private key for `tls_cert`.
    pub tls_key: Option<std::path::PathBuf>,
    /// Mark the session cookie `Secure`. Defaults to on when `tls` is on; set it when TLS is terminated by a
    /// reverse proxy in front.
    pub secure_cookies: Option<bool>,
    /// A session ends after this many hours without activity.
    pub session_hours: u64,
    /// ... and no later than this many hours after sign-in, however active it is.
    pub session_max_hours: u64,
    /// Networks of reverse proxies in front of the API. Only when the connection comes from one of these are
    /// `X-Forwarded-For` (client address) and `X-Forwarded-Proto` (scheme) believed. Empty by default.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Password hashes allowed to run at once (each uses about 19 MiB). Extra sign-ins wait briefly, then get 429.
    pub max_password_hashes: usize,
    /// Most connections at once; further ones are closed immediately.
    pub max_connections: usize,
    /// Seconds a client may take to send a request's headers (also bounds idle keep-alive connections).
    pub header_timeout_secs: u64,
    /// Sign-in with an OpenID Connect provider and Edge SSO; off unless this table is present.
    pub sso: Option<sso::SsoConfig>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8090)),
            hosts: Vec::new(),
            origins: Vec::new(),
            tls: false,
            tls_cert: None,
            tls_key: None,
            secure_cookies: None,
            session_hours: 12,
            session_max_hours: 24 * 7,
            trusted_proxies: Vec::new(),
            max_password_hashes: 2,
            max_connections: 256,
            header_timeout_secs: 30,
            sso: None,
        }
    }
}

/// Peer address of the connection a request arrived on.
#[derive(Debug, Clone, Copy)]
pub struct Peer(pub SocketAddr);

/// The client behind the connection: the peer itself, or (from a trusted proxy) the address and scheme it
/// forwarded. Used for rate limits, audit entries and `Caller::remote`.
#[derive(Debug, Clone, Copy)]
pub struct ClientInfo {
    pub ip: std::net::IpAddr,
    pub https: bool,
}

/// Work out the client of a request. Forwarded headers are believed only when `peer` is in `trusted`.
pub fn client_info(peer: SocketAddr, headers: &http::HeaderMap, trusted: &[ipnet::IpNet]) -> ClientInfo {
    let peer_ip = peer.ip().to_canonical();
    let is_trusted = |ip: &std::net::IpAddr| trusted.iter().any(|n| n.contains(ip));
    if !is_trusted(&peer_ip) {
        return ClientInfo {
            ip: peer_ip,
            https: false,
        };
    }
    // Rightmost entry that is not one of our own proxies: entries further left are client-supplied.
    let chain: Vec<std::net::IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|e| e.trim().parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_canonical())
        .collect();
    let ip = chain
        .iter()
        .rev()
        .find(|ip| !is_trusted(ip))
        .or(chain.first())
        .copied()
        .unwrap_or(peer_ip);
    let https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"));
    ClientInfo { ip, https }
}

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<Inner>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

pub struct Inner {
    pub app: Arc<AppDb>,
    pub projects: projects::Manager,
    pub proxy: Proxy,
    pub gate: Gate,
    /// The Repeater's sender. It shares the proxy's memory budget, upstream proxy and loop guard.
    pub repeater: bosun_http::Engine,
    pub ca: Arc<CertificateAuthority>,
    pub events: EventSender,
    pub limiter: auth::Limiter,
    pub conn_limit: ConnLimit,
    pub header_timeout: Duration,
    pub hash_slots: Arc<tokio::sync::Semaphore>,
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// The one-time setup code, while no user exists.
    pub setup_code: Mutex<Option<String>>,
    pub allowed_hosts: Vec<String>,
    pub extra_origins: Vec<String>,
    pub port: u16,
    pub tls: bool,
    pub secure_cookies: bool,
    pub ui_tls: Option<Arc<bosun_ca::UiTls>>,
    pub session_ttl_ms: i64,
    pub session_max_ms: i64,
    /// Present only when launching a browser is allowed (the API listens on loopback).
    pub browser: Option<BrowserLauncher>,
    pub loop_guard: LoopGuard,
    pub sso: Option<sso::Sso>,
    pub tickets: auth::Tickets,
    /// Password-checked sign-ins waiting for a second factor.
    pub pending: totp::Pending,
    /// The data key, for sealing second-factor secrets.
    pub data_key: Arc<bosun_ca::DataKey>,
    /// An admin requires a second factor of every password account.
    pub totp_required: std::sync::atomic::AtomicBool,
}

pub struct Deps {
    pub app: Arc<AppDb>,
    /// Where projects live (`<data dir>/projects`). Projects are managed by name inside it.
    pub projects_dir: std::path::PathBuf,
    /// The file the open project came from; none for a temporary (in-memory) project.
    pub project_path: Option<std::path::PathBuf>,
    pub proxy: Proxy,
    pub gate: Gate,
    pub ca: Arc<CertificateAuthority>,
    pub events: EventSender,
    pub browser: Option<BrowserLauncher>,
    /// The UI's certificate; required when `api.tls` is on.
    pub ui_tls: Option<Arc<bosun_ca::UiTls>>,
    /// The install's data key (second-factor secrets are sealed with it).
    pub data_key: Arc<bosun_ca::DataKey>,
}

impl std::fmt::Debug for Deps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deps").finish_non_exhaustive()
    }
}

/// The names and addresses the UI is reached by (what its certificate must cover, and the Host allowlist).
pub fn ui_hosts(cfg: &ApiConfig) -> Vec<String> {
    let mut hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "[::1]".into()];
    for h in &cfg.hosts {
        hosts.push(security::host_only(h));
    }
    let ip = cfg.listen.ip();
    if !ip.is_unspecified() {
        hosts.push(if ip.is_ipv6() {
            format!("[{ip}]")
        } else {
            ip.to_string()
        });
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

impl AppState {
    /// A single-use, 60-second ticket that `POST /auth/ticket` exchanges for an admin session (loopback only). For an
    /// embedded engine to hand to the app that started it. Issuing another replaces the first.
    pub fn issue_login_ticket(&self) -> String {
        self.inner.tickets.issue()
    }

    /// The project that is open now. It can change between two calls (a project switch), so take it once per
    /// operation.
    pub fn project(&self) -> Arc<Project> {
        self.inner.proxy.project()
    }

    /// Run `f` against the account database on a blocking thread. SQLite calls never run on the async workers.
    pub(crate) async fn with_app<T: Send + 'static>(
        &self,
        f: impl FnOnce(&AppDb) -> T + Send + 'static,
    ) -> Result<T, axum::response::Response> {
        let app = self.inner.app.clone();
        tokio::task::spawn_blocking(move || f(&app)).await.map_err(|e| {
            tracing::error!(error = %e, "a database task failed");
            security::reject(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "internal error (see the server log)",
            )
        })
    }

    /// Write an audit entry and wait for it. A failure to write is logged and does not fail the request.
    pub(crate) async fn audit(
        &self,
        user: Option<String>,
        action: &str,
        detail: &str,
        remote: Option<String>,
    ) {
        let (action, detail) = (action.to_string(), detail.to_string());
        let r = self
            .with_app(move |a| a.audit(user.as_deref(), &action, &detail, remote.as_deref()))
            .await;
        if let Ok(Err(e)) = r {
            tracing::error!(error = %e, "could not write an audit entry");
        }
    }

    /// Build the state. Returns the setup code when there are no users yet (print it for the operator).
    pub fn new(cfg: &ApiConfig, d: Deps) -> Result<(Self, Option<String>), bosun_store::StoreError> {
        let setup_code = if d.app.user_count()? == 0 {
            Some(auth::random_token())
        } else {
            None
        };
        let hosts = ui_hosts(cfg);
        let browser = if cfg.listen.ip().is_loopback() {
            d.browser
        } else {
            None
        };
        let ui_tls = if cfg.tls {
            Some(d.ui_tls.ok_or_else(|| {
                bosun_store::StoreError::Conflict("api.tls is on but there is no UI certificate".into())
            })?)
        } else {
            None
        };
        let totp_required =
            std::sync::atomic::AtomicBool::new(d.app.meta("totp_required")?.as_deref() == Some("1"));
        let loop_guard = d.proxy.loop_guard();
        let sso = match &cfg.sso {
            Some(c) => Some(sso::Sso::new(c).map_err(bosun_store::StoreError::Conflict)?),
            None => None,
        };
        let inner = Inner {
            app: d.app,
            projects: projects::Manager::new(d.projects_dir, d.project_path.as_deref(), MAX_PROJECT_UPLOAD),
            repeater: bosun_http::Engine::new(d.gate.clone(), d.proxy.budget())
                .with_connector(d.proxy.tool_connector()),
            proxy: d.proxy,
            gate: d.gate,
            ca: d.ca,
            events: d.events,
            limiter: auth::Limiter::default(),
            conn_limit: ConnLimit::new("api", cfg.max_connections),
            header_timeout: Duration::from_secs(cfg.header_timeout_secs.max(1)),
            hash_slots: Arc::new(tokio::sync::Semaphore::new(cfg.max_password_hashes.clamp(1, 64))),
            trusted_proxies: cfg.trusted_proxies.clone(),
            setup_code: Mutex::new(setup_code.clone()),
            allowed_hosts: hosts,
            extra_origins: cfg
                .origins
                .iter()
                .map(|o| o.trim_end_matches('/').to_string())
                .collect(),
            port: cfg.listen.port(),
            tls: cfg.tls,
            ui_tls,
            secure_cookies: cfg.secure_cookies.unwrap_or(cfg.tls),
            session_ttl_ms: (cfg.session_hours.clamp(1, 24 * 30) * 3600 * 1000) as i64,
            session_max_ms: (cfg.session_max_hours.clamp(1, 24 * 90) * 3600 * 1000) as i64,
            browser,
            loop_guard,
            sso,
            tickets: auth::Tickets::default(),
            pending: totp::Pending::default(),
            data_key: d.data_key,
            totp_required,
        };
        Ok((
            Self {
                inner: Arc::new(inner),
            },
            setup_code,
        ))
    }
}

pub fn router(st: AppState) -> Router {
    use handlers as h;
    let api = Router::new()
        .route("/status", get(h::status))
        .route("/setup", post(auth::setup))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route("/auth/ticket", post(auth::ticket))
        .route("/auth/sso", get(sso::config))
        .route("/auth/password", post(auth::change_password))
        .route("/auth/login/totp", post(totp::login))
        .route("/auth/totp", get(totp::status))
        .route("/auth/totp/enroll", post(totp::enroll))
        .route("/auth/totp/confirm", post(totp::confirm))
        .route("/auth/totp/disable", post(totp::disable))
        .route("/auth/totp/recovery-codes", post(totp::recovery_codes))
        .route("/auth/totp/required", put(totp::set_required))
        .route("/users/{id}/totp", axum::routing::delete(totp::admin_reset))
        .route("/flows", get(h::list_flows).delete(h::delete_flows))
        .route("/flows/query", get(h::check_flow_query))
        .route("/flows/tags", post(h::change_tags))
        .route("/organizer", get(h::list_organizer).post(h::add_to_organizer))
        .route(
            "/organizer/{id}",
            axum::routing::patch(h::update_organizer_item).delete(h::delete_organizer_item),
        )
        .route(
            "/saved-filters",
            get(h::get_saved_filters).put(h::put_saved_filters),
        )
        .route("/flows/{id}", get(h::get_flow).patch(h::annotate_flow))
        .route("/flows/{id}/ws", get(h::ws_messages))
        .route("/flows/{id}/engage", get(engage::flow_engage))
        .route("/flows/{id}/csrf-poc", get(engage::flow_csrf_poc))
        .route("/flows/{id}/{part}/body", get(h::flow_body))
        .route("/sitemap", get(h::site_map))
        .route("/scope", get(h::get_scope).put(h::put_scope))
        .route("/rules", get(h::get_rules).put(h::put_rules))
        .route("/intercept", get(h::get_intercept).put(h::put_intercept))
        .route("/intercept/queue", get(h::intercept_queue))
        .route(
            "/intercept/queue/{id}",
            get(h::intercept_item).post(h::intercept_decide),
        )
        .route("/intercept/forward-all", post(h::intercept_forward_all))
        .route("/proxy", get(h::proxy_info))
        .route("/tools/stop", put(h::set_stopped))
        .route("/ca", get(h::ca_info))
        .route("/ca/cert.pem", get(h::ca_pem))
        .route("/browser/launch", post(h::launch_browser))
        .route("/tokens", get(h::list_tokens).post(h::create_token))
        .route("/tokens/{id}", axum::routing::delete(h::delete_token))
        .route("/users/{id}/role", put(h::set_user_role))
        .route(
            "/users/{id}/sessions",
            get(h::list_user_sessions).delete(h::revoke_user_sessions),
        )
        .route(
            "/users/{id}/sessions/{sid}",
            axum::routing::delete(h::revoke_user_session),
        )
        .route("/users/{id}/tokens", get(h::list_user_tokens))
        .route(
            "/users/{id}/tokens/{tid}",
            axum::routing::delete(h::revoke_user_token),
        )
        .route("/users", get(h::list_users).post(h::create_user))
        .route("/users/{id}", axum::routing::delete(h::delete_user))
        .route("/projects", get(projects::list).post(projects::create))
        .route("/projects/close", post(projects::close))
        .route("/projects/import", post(projects::import))
        .route("/projects/{name}", axum::routing::delete(projects::delete))
        .route("/projects/{name}/open", post(projects::open))
        .route("/projects/{name}/rename", post(projects::rename))
        .route("/projects/{name}/export", get(projects::export))
        .route("/projects/{name}/backup", post(projects::backup))
        .route("/decoder/apply", post(codec::decode))
        .route("/decoder/smart", post(codec::smart))
        .route("/comparer/diff", post(codec::compare))
        .route("/repeater/send", post(repeater::send))
        .route(
            "/repeater/settings",
            get(repeater::get_settings).put(repeater::put_settings),
        )
        .route("/repeater/ws", post(repeater::ws_send))
        .route("/repeater/tabs", get(repeater::get_tabs).put(repeater::put_tabs))
        .route("/audit", get(h::audit_log))
        .route("/events", get(events::events));
    Router::new()
        .nest("/api/v1", api)
        // Outside /api/: the browser arrives by cross-site redirect (see sso.rs).
        .route("/auth/oidc/login", get(sso::login))
        .route("/auth/oidc/callback", get(sso::callback))
        .route("/auth/oidc/edge", get(sso::edge))
        .fallback(web::static_handler)
        .layer(axum::extract::DefaultBodyLimit::max(70 * 1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(st.clone(), security::guard))
        .with_state(st)
}

/// Serve the API until `shutdown` resolves.
pub async fn serve(st: AppState, listener: TcpListener, shutdown: impl std::future::Future<Output = ()>) {
    let app = router(st.clone());
    let ui_tls = st.inner.ui_tls.clone();
    // SIGHUP re-reads configured certificate files.
    #[cfg(unix)]
    let _hup = ui_tls.clone().and_then(|u| {
        let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok()?;
        Some(AbortOnDrop(tokio::spawn(async move {
            while hup.recv().await.is_some() {
                u.reload();
            }
        })))
    });
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(_) => continue,
            },
        };
        // Our own proxy's outbound connections must never reach the API (a proxied page asking the proxy
        // for http://127.0.0.1:8090/ would otherwise arrive here as a local request).
        if st.inner.loop_guard.is_own(&peer) {
            tracing::warn!(%peer, "refused an API connection that came from the proxy itself");
            continue;
        }
        let Some(permit) = st.inner.conn_limit.try_acquire() else {
            continue;
        };
        let app = app.clone();
        let st = st.clone();
        let ui_tls = ui_tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let guard = st.inner.loop_guard.clone();
            let trusted = st.inner.trusted_proxies.clone();
            let svc = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
                req.extensions_mut().insert(Peer(peer));
                let info = client_info(peer, req.headers(), &trusted);
                req.extensions_mut().insert(info);
                let app = app.clone();
                // Checked again per request: the proxy registers an outbound connection just after the TCP
                // handshake, which can be after we accepted it, but always before it sends a request.
                let own = guard.is_own(&peer);
                async move {
                    if own {
                        tracing::warn!(%peer, "refused an API request that came from the proxy itself");
                        return Ok::<_, Infallible>(security::reject(
                            http::StatusCode::LOOP_DETECTED,
                            "requests to the API through the proxy are refused",
                        ));
                    }
                    Ok::<_, Infallible>(
                        app.oneshot(req.map(axum::body::Body::new))
                            .await
                            .unwrap_or_else(|e| match e {}),
                    )
                }
            });
            let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(st.inner.header_timeout);
            builder
                .http2()
                .timer(hyper_util::rt::TokioTimer::new())
                .max_concurrent_streams(100)
                .max_header_list_size(64 * 1024)
                .keep_alive_interval(Duration::from_secs(30))
                .keep_alive_timeout(Duration::from_secs(20));
            if let Some(ui_tls) = ui_tls {
                let acceptor =
                    tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
                let Ok(Ok(start)) = tokio::time::timeout(Duration::from_secs(20), acceptor).await else {
                    return;
                };
                let cfg = ui_tls.config();
                let Ok(tls) = start.into_stream(cfg).await else {
                    return;
                };
                let _ = builder
                    .serve_connection_with_upgrades(TokioIo::new(tls), svc)
                    .await;
            } else {
                let _ = builder
                    .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                    .await;
            }
        });
    }
}

#[cfg(unix)]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

#[cfg(unix)]
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(xff: &str, proto: Option<&str>) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert("x-forwarded-for", xff.parse().unwrap());
        if let Some(p) = proto {
            h.insert("x-forwarded-proto", p.parse().unwrap());
        }
        h
    }

    fn nets(v: &[&str]) -> Vec<ipnet::IpNet> {
        v.iter().map(|n| n.parse().unwrap()).collect()
    }

    #[test]
    fn untrusted_peers_cannot_choose_their_address() {
        let c = client_info(
            "198.51.100.1:5000".parse().unwrap(),
            &headers("1.2.3.4", Some("https")),
            &[],
        );
        assert_eq!(c.ip.to_string(), "198.51.100.1");
        assert!(!c.https);
    }

    #[test]
    fn the_rightmost_untrusted_entry_is_the_client() {
        let t = nets(&["10.0.0.0/8"]);
        // client-supplied "9.9.9.9", then the real client, then our own proxies.
        let h = headers("9.9.9.9, 203.0.113.4, 10.0.0.2", Some("https"));
        let c = client_info("10.0.0.1:1".parse().unwrap(), &h, &t);
        assert_eq!(c.ip.to_string(), "203.0.113.4");
        assert!(c.https);
        // Nothing forwarded: the peer is the client.
        let c = client_info("10.0.0.1:1".parse().unwrap(), &http::HeaderMap::new(), &t);
        assert_eq!(c.ip.to_string(), "10.0.0.1");
    }
}
