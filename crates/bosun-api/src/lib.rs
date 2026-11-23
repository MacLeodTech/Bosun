//! The Bosun API and web UI server.
//!
//! One versioned API (`/api/v1`) serves every front end: the web UI, the desktop shell, the CLI and scripts.
//! See [`security`] for the request-level defences and [`auth`] for accounts and sessions.

// Handlers return `Result<Response, Response>` (axum's idiom); the error side is a whole response by design.
#![allow(clippy::result_large_err)]

pub mod auth;
pub mod browser;
pub mod events;
pub mod handlers;
pub mod security;
pub mod sso;
pub mod web;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::routing::{get, post, put};
use bosun_ca::CertificateAuthority;
use bosun_proxy::{EventSender, LoopGuard, Proxy};
use bosun_scope::Gate;
use bosun_store::{AppDb, Project};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower::ServiceExt;

pub use browser::BrowserLauncher;

pub const SETTING_SCOPE: &str = "scope";
pub const SETTING_RULES: &str = "match_replace";
pub const SETTING_INTERCEPT: &str = "intercept";

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
    /// Serve the UI over HTTPS with a certificate from the install's CA.
    pub tls: bool,
    /// Mark the session cookie `Secure`. Defaults to on when `tls` is on; set it when TLS is terminated by a
    /// reverse proxy in front.
    pub secure_cookies: Option<bool>,
    pub session_hours: u64,
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
            secure_cookies: None,
            session_hours: 12,
            sso: None,
        }
    }
}

/// Peer address of the connection a request arrived on.
#[derive(Debug, Clone, Copy)]
pub struct Peer(pub SocketAddr);

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
    pub project: Arc<Project>,
    pub proxy: Proxy,
    pub gate: Gate,
    pub ca: Arc<CertificateAuthority>,
    pub events: EventSender,
    pub limiter: auth::Limiter,
    /// The one-time setup code, while no user exists.
    pub setup_code: Mutex<Option<String>>,
    pub allowed_hosts: Vec<String>,
    pub extra_origins: Vec<String>,
    pub port: u16,
    pub tls: bool,
    pub secure_cookies: bool,
    pub session_ttl_ms: i64,
    /// Present only when launching a browser is allowed (the API listens on loopback).
    pub browser: Option<BrowserLauncher>,
    pub loop_guard: LoopGuard,
    pub sso: Option<sso::Sso>,
}

pub struct Deps {
    pub app: Arc<AppDb>,
    pub project: Arc<Project>,
    pub proxy: Proxy,
    pub gate: Gate,
    pub ca: Arc<CertificateAuthority>,
    pub events: EventSender,
    pub browser: Option<BrowserLauncher>,
}

impl std::fmt::Debug for Deps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deps").finish_non_exhaustive()
    }
}

impl AppState {
    /// Build the state. Returns the setup code when there are no users yet (print it for the operator).
    pub fn new(cfg: &ApiConfig, d: Deps) -> Result<(Self, Option<String>), bosun_store::StoreError> {
        let setup_code = if d.app.user_count()? == 0 {
            Some(auth::random_token())
        } else {
            None
        };
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
        let browser = if cfg.listen.ip().is_loopback() {
            d.browser
        } else {
            None
        };
        let loop_guard = d.proxy.loop_guard();
        let sso = match &cfg.sso {
            Some(c) => Some(sso::Sso::new(c).map_err(bosun_store::StoreError::Conflict)?),
            None => None,
        };
        let inner = Inner {
            app: d.app,
            project: d.project,
            proxy: d.proxy,
            gate: d.gate,
            ca: d.ca,
            events: d.events,
            limiter: auth::Limiter::default(),
            setup_code: Mutex::new(setup_code.clone()),
            allowed_hosts: hosts,
            extra_origins: cfg
                .origins
                .iter()
                .map(|o| o.trim_end_matches('/').to_string())
                .collect(),
            port: cfg.listen.port(),
            tls: cfg.tls,
            secure_cookies: cfg.secure_cookies.unwrap_or(cfg.tls),
            session_ttl_ms: (cfg.session_hours.clamp(1, 24 * 30) * 3600 * 1000) as i64,
            browser,
            loop_guard,
            sso,
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
        .route("/auth/sso", get(sso::config))
        .route("/auth/password", post(auth::change_password))
        .route("/flows", get(h::list_flows).delete(h::delete_flows))
        .route("/flows/{id}", get(h::get_flow).patch(h::annotate_flow))
        .route("/flows/{id}/ws", get(h::ws_messages))
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
        .route("/users", get(h::list_users).post(h::create_user))
        .route("/users/{id}", axum::routing::delete(h::delete_user))
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
    let tls = st.inner.tls;
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
        let app = app.clone();
        let st = st.clone();
        tokio::spawn(async move {
            let guard = st.inner.loop_guard.clone();
            let svc = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
                req.extensions_mut().insert(Peer(peer));
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
            let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            if tls {
                let acceptor =
                    tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
                let Ok(Ok(start)) = tokio::time::timeout(Duration::from_secs(20), acceptor).await else {
                    return;
                };
                let sni = start.client_hello().server_name().map(str::to_ascii_lowercase);
                let name = sni
                    .filter(|s| st.inner.allowed_hosts.contains(s))
                    .unwrap_or_else(|| "localhost".into());
                let Ok(cfg) = st.inner.ca.server_config(&name, true) else {
                    return;
                };
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
