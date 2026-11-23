//! The proxy listener and per-request handling.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bosun_ca::CertificateAuthority;
use bosun_model::{FlowId, FlowSource, RawRequest, RawResponse, Scheme};
use bosun_scope::{Gate, RuleSpec as ScopeRule, Scope, ScopeSpec};
use bosun_store::{NewFlow, Project};
use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::body::{CollectError, TeeBody, collect_budgeted};
use crate::budget::MemoryBudget;
use crate::config::ProxyConfig;
use crate::events::EventSender;
use crate::intercept::{Decision, InterceptController, Phase};
use crate::limits::ConnLimit;
use crate::recorder::Recorder;
use crate::rules::{RuleSet, RuleSpec, RuleTarget};
use crate::upstream::{BoxError, Connector, LoopGuard};

pub type RespBody = UnsyncBoxBody<Bytes, BoxError>;
type UpClient = Client<Connector, Full<Bytes>>;

/// The magic host served by the proxy itself (CA download), like `http://burp` in other tools.
pub const MAGIC_HOST: &str = "bosun";

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("invalid proxy configuration: {0}")]
    Config(String),
    #[error("cannot listen on {0}: {1}")]
    Bind(SocketAddr, std::io::Error),
}

pub(crate) struct Shared {
    pub cfg: ProxyConfig,
    pub ca: Arc<CertificateAuthority>,
    pub gate: Gate,
    /// The project being recorded to, and the recorder that writes to it. A request keeps the pair it started
    /// with, so switching projects never sends half a flow to each.
    pub active: RwLock<Arc<Active>>,
    pub events: EventSender,
    pub intercept: Arc<InterceptController>,
    pub rules: RwLock<Arc<RuleSet>>,
    pub client: UpClient,
    pub ws_client: UpClient,
    /// Opens plain TCP for pass-through tunnels: same upstream proxy and loop guard as the HTTP clients.
    pub tcp: Connector,
    pub guard: LoopGuard,
    pub limit: ConnLimit,
    pub budget: MemoryBudget,
    pub passthrough: Scope,
    pub expected_auth: Option<String>,
}

pub(crate) struct Active {
    pub project: Arc<Project>,
    pub recorder: Recorder,
}

#[derive(Clone, Debug)]
struct Tunnel {
    scheme: Scheme,
    host: String,
    port: u16,
}

#[derive(Clone)]
struct ConnCtx {
    peer: SocketAddr,
    tunnel: Option<Tunnel>,
}

/// Resource counters (see [`Proxy::stats`]).
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ProxyStats {
    pub memory_budget: usize,
    pub memory_used: usize,
    pub memory_refused: u64,
    pub recorder_bodies_dropped: u64,
    pub recorder_records_dropped: u64,
    pub recorder_write_failures: u64,
    pub recorder_records_lost: u64,
    pub intercept_refused: u64,
    pub intercept_queued_bytes: usize,
}

/// Handle to a configured proxy.
#[derive(Clone)]
pub struct Proxy {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("listen", &self.shared.cfg.listen)
            .finish_non_exhaustive()
    }
}

impl Proxy {
    pub fn new(
        cfg: ProxyConfig,
        ca: Arc<CertificateAuthority>,
        gate: Gate,
        project: Arc<Project>,
        events: EventSender,
    ) -> Result<Self, ProxyError> {
        cfg.validate().map_err(ProxyError::Config)?;
        let guard = LoopGuard::default();
        let mut self_addrs = cfg.self_addrs.clone();
        self_addrs.push(cfg.listen);
        let mk = |h2: bool| -> Result<UpClient, ProxyError> {
            let conn = Connector::new(
                cfg.upstream.as_ref(),
                cfg.verify_upstream_tls,
                h2,
                guard.clone(),
                self_addrs.clone(),
            )
            .map_err(ProxyError::Config)?;
            let mut b = Client::builder(TokioExecutor::new());
            b.pool_idle_timeout(Duration::from_secs(60))
                .pool_max_idle_per_host(16)
                .http1_preserve_header_case(true)
                .set_host(false);
            Ok(b.build(conn))
        };
        let tcp = Connector::new(
            cfg.upstream.as_ref(),
            cfg.verify_upstream_tls,
            false,
            guard.clone(),
            self_addrs.clone(),
        )
        .map_err(ProxyError::Config)?;
        let limit = ConnLimit::new("proxy", cfg.max_connections);
        let client = mk(true)?;
        let ws_client = mk(false)?;
        let passthrough = Scope::compile(ScopeSpec {
            include: cfg
                .tls_passthrough
                .iter()
                .map(|h| ScopeRule {
                    host: h.clone(),
                    ..Default::default()
                })
                .collect(),
            exclude: vec![],
        })
        .map_err(|e| ProxyError::Config(format!("tls_passthrough: {e}")))?;
        let expected_auth = cfg.auth.as_ref().map(|a| {
            use base64::Engine;
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", a.username, a.password))
            )
        });
        let budget = MemoryBudget::new(
            cfg.memory_budget_mib
                .map_or_else(MemoryBudget::default_cap, |m| m.saturating_mul(1 << 20)),
        );
        let active = Arc::new(Active {
            recorder: Recorder::start(project.clone(), events.clone(), budget.clone()),
            project,
        });
        Ok(Self {
            shared: Arc::new(Shared {
                intercept: Arc::new(InterceptController::with_limits(
                    events.clone(),
                    cfg.max_intercept_items,
                    cfg.max_intercept_bytes,
                )),
                cfg,
                ca,
                gate,
                active: RwLock::new(active),
                events,
                rules: RwLock::new(Arc::new(RuleSet::default())),
                client,
                ws_client,
                tcp,
                guard,
                limit,
                budget,
                passthrough,
                expected_auth,
            }),
        })
    }

    /// Counters for `/proxy`: memory in use, and what had to be refused or dropped.
    pub fn stats(&self) -> ProxyStats {
        let sh = &self.shared;
        let active = sh.active();
        ProxyStats {
            memory_budget: sh.budget.cap(),
            memory_used: sh.budget.used(),
            memory_refused: sh.budget.refused(),
            recorder_bodies_dropped: active
                .recorder
                .stats()
                .bodies_dropped
                .load(std::sync::atomic::Ordering::Relaxed),
            recorder_records_dropped: active
                .recorder
                .stats()
                .records_dropped
                .load(std::sync::atomic::Ordering::Relaxed),
            recorder_write_failures: active
                .recorder
                .stats()
                .write_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            recorder_records_lost: active
                .recorder
                .stats()
                .records_lost
                .load(std::sync::atomic::Ordering::Relaxed),
            intercept_refused: sh.intercept.refused(),
            intercept_queued_bytes: sh.intercept.queued_bytes(),
        }
    }

    pub fn config(&self) -> &ProxyConfig {
        &self.shared.cfg
    }

    pub fn intercept(&self) -> &Arc<InterceptController> {
        &self.shared.intercept
    }

    pub fn loop_guard(&self) -> LoopGuard {
        self.shared.guard.clone()
    }

    pub fn rules(&self) -> Vec<RuleSpec> {
        self.shared.rules().specs().to_vec()
    }

    pub fn set_rules(&self, specs: Vec<RuleSpec>) -> Result<(), String> {
        let rs = RuleSet::compile(specs)?;
        *self.shared.rules.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(rs);
        Ok(())
    }

    /// Wait until everything recorded so far has been written to the project.
    pub fn flush(&self) {
        self.shared.active().recorder.flush();
    }

    /// The project flows are being recorded to.
    pub fn project(&self) -> Arc<Project> {
        self.shared.active().project.clone()
    }

    /// Record to `project` from now on. Requests already in flight finish into the project they began in; this
    /// waits until everything recorded so far has been written there, so the old project can then be closed.
    pub fn switch_project(&self, project: Arc<Project>) {
        let fresh = Arc::new(Active {
            recorder: Recorder::start(
                project.clone(),
                self.shared.events.clone(),
                self.shared.budget.clone(),
            ),
            project,
        });
        let old = std::mem::replace(
            &mut *self.shared.active.write().unwrap_or_else(|e| e.into_inner()),
            fresh,
        );
        old.recorder.flush();
    }

    pub async fn bind(&self) -> Result<TcpListener, ProxyError> {
        TcpListener::bind(self.shared.cfg.listen)
            .await
            .map_err(|e| ProxyError::Bind(self.shared.cfg.listen, e))
    }

    /// Accept connections until `shutdown` resolves.
    pub async fn serve(&self, listener: TcpListener, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else { continue };
                    // Over the limit: close at once; connections already open are unaffected.
                    let Some(permit) = self.shared.limit.try_acquire() else { continue };
                    let shared = self.shared.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        shared.accept(stream, peer).await
                    });
                }
            }
        }
    }
}

impl Shared {
    fn active(&self) -> Arc<Active> {
        self.active.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn rules(&self) -> Arc<RuleSet> {
        self.rules.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn client_allowed(&self, peer: &SocketAddr) -> bool {
        let ip = peer.ip().to_canonical();
        self.cfg.allow_clients.is_empty() || self.cfg.allow_clients.iter().any(|n| n.contains(&ip))
    }

    async fn accept(self: Arc<Self>, stream: TcpStream, peer: SocketAddr) {
        if !self.client_allowed(&peer) {
            tracing::warn!(%peer, "proxy client not in allow_clients; closing");
            return;
        }
        if self.guard.is_own(&peer) {
            tracing::warn!(%peer, "refused a connection from the proxy's own outbound traffic (loop)");
            return;
        }
        let _ = stream.set_nodelay(true);
        let ctx = ConnCtx { peer, tunnel: None };
        self.serve_h1(TokioIo::new(stream), ctx).await;
    }

    async fn serve_h1<I>(self: Arc<Self>, io: I, ctx: ConnCtx)
    where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let peer = ctx.peer;
        let shared = self.clone();
        let svc = service_fn(move |req| {
            let shared = shared.clone();
            let ctx = ctx.clone();
            async move { Ok::<_, Infallible>(shared.entry(ctx, req).await) }
        });
        let res = hyper::server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .header_read_timeout(Duration::from_secs(self.cfg.header_timeout_secs.max(1)))
            .timer(hyper_util::rt::TokioTimer::new())
            .serve_connection(io, svc)
            .with_upgrades()
            .await;
        if let Err(e) = res {
            tracing::debug!(error = %e, peer = %peer, "client connection ended with an error");
        }
    }

    /// Boxed so the CONNECT -> MITM -> entry recursion has a concrete (and `Send`) type.
    fn entry(
        self: Arc<Self>,
        ctx: ConnCtx,
        req: Request<Incoming>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response<RespBody>> + Send>> {
        Box::pin(self.entry_inner(ctx, req))
    }

    async fn entry_inner(self: Arc<Self>, ctx: ConnCtx, req: Request<Incoming>) -> Response<RespBody> {
        // Also checked at accept time; this catches connections accepted before the outbound side registered.
        if self.guard.is_own(&ctx.peer) {
            return text(
                StatusCode::LOOP_DETECTED,
                "refusing a request from the proxy's own outbound connection",
            );
        }
        if req.method() == Method::CONNECT {
            return self.connect(ctx, req).await;
        }
        let uri_host = req.uri().host().map(str::to_ascii_lowercase);
        let host_header = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|h| split_host_port(h).0.to_ascii_lowercase());
        let magic = match &ctx.tunnel {
            Some(t) => t.host == MAGIC_HOST,
            None => {
                uri_host.as_deref() == Some(MAGIC_HOST)
                    || (uri_host.is_none() && host_header.as_deref() == Some(MAGIC_HOST))
            }
        };
        if magic {
            return self.magic(&req);
        }
        if ctx.tunnel.is_none() && !self.authorised(req.headers()) {
            return proxy_auth_required();
        }
        let target = if let Some(t) = &ctx.tunnel {
            t.clone()
        } else if let (Some(scheme), Some(auth)) = (req.uri().scheme_str(), req.uri().authority()) {
            let Some(scheme) = Scheme::parse(scheme) else {
                return text(StatusCode::BAD_REQUEST, "unsupported scheme");
            };
            Tunnel {
                scheme,
                host: auth
                    .host()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_ascii_lowercase(),
                port: auth.port_u16().unwrap_or(scheme.default_port()),
            }
        } else if self.cfg.invisible {
            let Some(h) = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) else {
                return text(StatusCode::BAD_REQUEST, "invisible proxying needs a Host header");
            };
            let (host, port) = split_host_port(h);
            Tunnel {
                scheme: Scheme::Http,
                host: host.to_ascii_lowercase(),
                port: port.unwrap_or(80),
            }
        } else {
            return text(
                StatusCode::BAD_REQUEST,
                "This is the Bosun proxy. Configure your client to use it as an HTTP proxy, or open \
                 http://bosun/ through it to download the CA certificate.",
            );
        };
        self.proxy_request(ctx, target, req).await
    }

    fn authorised(&self, headers: &HeaderMap) -> bool {
        match &self.expected_auth {
            None => true,
            Some(expected) => headers
                .get(header::PROXY_AUTHORIZATION)
                .is_some_and(|v| bool::from(v.as_bytes().ct_eq(expected.as_bytes()))),
        }
    }

    async fn connect(self: Arc<Self>, ctx: ConnCtx, mut req: Request<Incoming>) -> Response<RespBody> {
        if !self.authorised(req.headers()) {
            return proxy_auth_required();
        }
        let Some(auth) = req.uri().authority().cloned() else {
            return text(StatusCode::BAD_REQUEST, "CONNECT needs host:port");
        };
        let host = auth
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        let port = auth.port_u16().unwrap_or(443);
        let on_upgrade = hyper::upgrade::on(&mut req);
        let passthrough = self.passthrough.contains(Scheme::Https, &host, port, "/");
        let shared = self.clone();
        tokio::spawn(async move {
            let upgraded = match on_upgrade.await {
                Ok(u) => TokioIo::new(u),
                Err(e) => {
                    tracing::debug!(error = %e, "CONNECT upgrade failed");
                    return;
                }
            };
            if passthrough {
                shared.passthrough_tunnel(upgraded, &host, port).await;
            } else {
                shared.mitm(upgraded, ctx, host, port).await;
            }
        });
        Response::new(empty())
    }

    async fn passthrough_tunnel<I: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut client: I,
        host: &str,
        port: u16,
    ) {
        // Through the connector, so the upstream proxy (SOCKS5/Tor) and the loop guard apply to pass-through hosts too.
        match self.tcp.connect_tcp(host, port).await {
            Ok((mut server, _registration)) => {
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            }
            Err(e) => tracing::debug!(error = %e, host, port, "pass-through connect failed"),
        }
    }

    async fn mitm<I>(self: Arc<Self>, mut io: I, ctx: ConnCtx, host: String, port: u16)
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut first = [0u8; 1];
        let n = match tokio::time::timeout(Duration::from_secs(30), io.read(&mut first)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return,
        };
        let io = Rewind::new(io, first[..n].to_vec());
        if first[0] == 0x16 {
            let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io);
            let start = match tokio::time::timeout(Duration::from_secs(30), acceptor).await {
                Ok(Ok(s)) => s,
                _ => return,
            };
            let sni = start.client_hello().server_name().map(str::to_string);
            let cert_host = sni.clone().unwrap_or_else(|| host.clone());
            let cfg = match self.ca.server_config(&cert_host, self.cfg.http2) {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, host = cert_host, "cannot issue a certificate");
                    return;
                }
            };
            let tls = match start.into_stream(cfg).await {
                Ok(t) => t,
                Err(e) => {
                    // Usually the client does not trust our CA yet.
                    tracing::info!(error = %e, host, "TLS handshake with the client failed (is the Bosun CA trusted?)");
                    return;
                }
            };
            let ctx = ConnCtx {
                tunnel: Some(Tunnel {
                    scheme: Scheme::Https,
                    host,
                    port,
                }),
                ..ctx
            };
            let shared = self.clone();
            let svc = service_fn(move |req| {
                let shared = shared.clone();
                let ctx = ctx.clone();
                async move { Ok::<_, Infallible>(shared.entry(ctx, req).await) }
            });
            let mut b = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            b.http1()
                .preserve_header_case(true)
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(self.cfg.header_timeout_secs.max(1)));
            b.http2()
                .timer(hyper_util::rt::TokioTimer::new())
                .max_concurrent_streams(100)
                .max_header_list_size(64 * 1024)
                .keep_alive_interval(Duration::from_secs(30))
                .keep_alive_timeout(Duration::from_secs(20));
            if let Err(e) = b.serve_connection_with_upgrades(TokioIo::new(tls), svc).await {
                tracing::debug!(error = %e, "TLS client connection ended with an error");
            }
        } else {
            let ctx = ConnCtx {
                tunnel: Some(Tunnel {
                    scheme: Scheme::Http,
                    host,
                    port,
                }),
                ..ctx
            };
            self.serve_h1(TokioIo::new(io), ctx).await;
        }
    }

    fn magic(&self, req: &Request<Incoming>) -> Response<RespBody> {
        let path = req.uri().path();
        let (ctype, disposition, body): (&str, Option<&str>, Vec<u8>) = match path {
            "/cert" | "/cert.pem" => (
                "application/x-pem-file",
                Some("attachment; filename=\"bosun-ca.pem\""),
                self.ca.cert_pem().as_bytes().to_vec(),
            ),
            "/cert.der" | "/cert.cer" => (
                "application/x-x509-ca-cert",
                Some("attachment; filename=\"bosun-ca.cer\""),
                self.ca.cert_der().to_vec(),
            ),
            "/" => (
                "text/html; charset=utf-8",
                None,
                MAGIC_PAGE.replace("{fp}", &self.ca.fingerprint()).into_bytes(),
            ),
            _ => return text(StatusCode::NOT_FOUND, "not found"),
        };
        let mut r = Response::new(full(body));
        let h = r.headers_mut();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
        );
        h.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Some(d) = disposition {
            h.insert(header::CONTENT_DISPOSITION, HeaderValue::from_static(d));
        }
        r
    }

    async fn proxy_request(
        self: Arc<Self>,
        _ctx: ConnCtx,
        target: Tunnel,
        mut req: Request<Incoming>,
    ) -> Response<RespBody> {
        let started = bosun_model::now_ms();
        let t0 = std::time::Instant::now();
        let active = self.active();
        let flow_id = active.project.next_flow_id();
        let wants_upgrade = is_upgrade(req.headers());
        let client_upgrade = wants_upgrade.then(|| hyper::upgrade::on(&mut req));
        let (parts, body) = req.into_parts();
        // `_mem` keeps the body's bytes counted against the memory budget while this request is in flight.
        let (body, _mem) = match collect_budgeted(body, self.cfg.max_request_body, &self.budget).await {
            Ok(b) => b,
            Err(CollectError::TooBig) => {
                return text(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body is larger than proxy.max_request_body",
                );
            }
            Err(CollectError::OutOfMemory) => return busy(),
            Err(CollectError::Other(_)) => {
                return text(StatusCode::BAD_REQUEST, "failed to read the request body");
            }
        };
        let path = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let path = if path.is_empty() { "/".to_string() } else { path };
        let version = version_label(parts.version);
        let authority_for_h2 = (parts.version == Version::HTTP_2).then(|| authority(&target));
        let mut raw = serialize_request(
            parts.method.as_str(),
            &path,
            version,
            &parts.headers,
            &body,
            authority_for_h2.as_deref(),
        );
        let in_scope = self
            .gate
            .scope()
            .contains(target.scheme, &target.host, target.port, &path);
        let record = in_scope || self.cfg.record_out_of_scope;
        let rules = self.rules();
        let mut original_request = None;
        if let Some(new) = rules.apply_request(&raw) {
            original_request = Some(std::mem::replace(&mut raw, new));
        }
        let url = format!("{}{}", origin(&target), path);
        if self.intercept.should_hold(Phase::Request, in_scope) {
            let held = self
                .intercept
                .hold(
                    flow_id,
                    Phase::Request,
                    parts.method.as_str(),
                    &url,
                    None,
                    raw.clone(),
                )
                .await;
            let Ok(held) = held else {
                return queue_full();
            };
            match held {
                Decision::Drop => {
                    if record {
                        active.recorder.flow(self.new_flow(
                            flow_id,
                            &target,
                            started,
                            t0,
                            &raw,
                            original_request,
                            None,
                            None,
                            false,
                            Some("dropped in the intercept queue".into()),
                            in_scope,
                        ));
                    }
                    return text(
                        StatusCode::BAD_GATEWAY,
                        "Request dropped in Bosun's intercept queue.",
                    );
                }
                Decision::Forward { raw: Some(edited) } if edited != raw => {
                    original_request.get_or_insert_with(|| raw.clone());
                    raw = edited;
                }
                Decision::Forward { .. } => {}
            }
        }

        // Build the outbound request: from the (possibly edited) raw text if anything changed, otherwise from
        // the original parts so nothing is normalised unnecessarily.
        let (method, out_path, mut headers, out_body) = if original_request.is_some() {
            match RawRequest::parse(&raw) {
                Ok(r) => {
                    let mut hm = HeaderMap::new();
                    for (n, v) in &r.headers {
                        if let (Ok(n), Ok(v)) =
                            (HeaderName::from_bytes(n.as_bytes()), HeaderValue::from_bytes(v))
                        {
                            hm.append(n, v);
                        }
                    }
                    let mut p = r.target.clone();
                    if let Ok(u) = r.target.parse::<http::Uri>()
                        && u.scheme().is_some()
                    {
                        p = u
                            .path_and_query()
                            .map(|p| p.as_str().to_string())
                            .unwrap_or_else(|| "/".into());
                    }
                    if hm.contains_key(header::CONTENT_LENGTH) {
                        hm.insert(header::CONTENT_LENGTH, HeaderValue::from(r.body.len()));
                    }
                    let Ok(m) = Method::from_bytes(r.method.as_bytes()) else {
                        return text(
                            StatusCode::BAD_REQUEST,
                            "the edited request has an invalid method",
                        );
                    };
                    (m, p, hm, Bytes::from(r.body))
                }
                Err(e) => {
                    return text(
                        StatusCode::BAD_REQUEST,
                        &format!("the edited request is not valid HTTP: {e}"),
                    );
                }
            }
        } else {
            (
                parts.method.clone(),
                path.clone(),
                parts.headers.clone(),
                Bytes::from(body),
            )
        };
        strip_hop_by_hop(&mut headers, wants_upgrade);
        if !headers.contains_key(header::HOST)
            && let Ok(v) = HeaderValue::from_str(&authority(&target))
        {
            headers.insert(header::HOST, v);
        }
        let uri = format!(
            "{}{}",
            origin(&target),
            if out_path.starts_with('/') {
                out_path.clone()
            } else {
                format!("/{out_path}")
            }
        );
        let Ok(uri) = uri.parse::<http::Uri>() else {
            return text(StatusCode::BAD_REQUEST, "invalid request target");
        };
        let mut out = Request::new(Full::new(out_body));
        *out.method_mut() = method;
        *out.uri_mut() = uri;
        *out.headers_mut() = headers;
        if original_request.is_none() {
            // Keeps the client's header-name casing for HTTP/1 (hyper stores it in the extensions).
            *out.extensions_mut() = parts.extensions;
        }
        let client = if wants_upgrade {
            &self.ws_client
        } else {
            &self.client
        };
        let resp = match tokio::time::timeout(
            Duration::from_secs(self.cfg.upstream_timeout_secs),
            client.request(out),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                let msg = error_chain(&e);
                if record {
                    active.recorder.flow(self.new_flow(
                        flow_id,
                        &target,
                        started,
                        t0,
                        &raw,
                        original_request,
                        None,
                        None,
                        false,
                        Some(msg.clone()),
                        in_scope,
                    ));
                }
                return text(
                    StatusCode::BAD_GATEWAY,
                    &format!("Bosun could not reach {}: {msg}", origin(&target)),
                );
            }
            Err(_) => {
                let msg = "timed out waiting for the response".to_string();
                if record {
                    active.recorder.flow(self.new_flow(
                        flow_id,
                        &target,
                        started,
                        t0,
                        &raw,
                        original_request,
                        None,
                        None,
                        false,
                        Some(msg.clone()),
                        in_scope,
                    ));
                }
                return text(StatusCode::GATEWAY_TIMEOUT, &msg);
            }
        };

        let mut resp = resp;
        let server_upgrade = (resp.status() == StatusCode::SWITCHING_PROTOCOLS && client_upgrade.is_some())
            .then(|| hyper::upgrade::on(&mut resp));
        let (mut rparts, rbody) = resp.into_parts();
        let rversion = version_label(rparts.version);
        let mut head = serialize_response(rversion, rparts.status, &rparts.headers, &[]);

        // WebSocket (or other) upgrade.
        if rparts.status == StatusCode::SWITCHING_PROTOCOLS
            && let (Some(client_upgrade), Some(server_upgrade)) = (client_upgrade, server_upgrade)
        {
            if record {
                active.recorder.flow(self.new_flow(
                    flow_id,
                    &target,
                    started,
                    t0,
                    &raw,
                    original_request,
                    Some(head),
                    None,
                    false,
                    None,
                    in_scope,
                ));
            }
            let recorder = active.recorder.clone();
            tokio::spawn(async move {
                match tokio::join!(client_upgrade, server_upgrade) {
                    (Ok(c), Ok(s)) => {
                        if record {
                            crate::ws::relay(TokioIo::new(c), TokioIo::new(s), flow_id, recorder).await;
                        } else {
                            let (mut c, mut s) = (TokioIo::new(c), TokioIo::new(s));
                            let _ = tokio::io::copy_bidirectional(&mut c, &mut s).await;
                        }
                    }
                    (Err(e), _) | (_, Err(e)) => tracing::debug!(error = %e, "upgrade failed"),
                }
            });
            let mut r = Response::from_parts(rparts, empty());
            *r.version_mut() = Version::HTTP_11;
            return r;
        }

        let need_buffer = self.intercept.should_hold(Phase::Response, in_scope)
            || rules.has(|t| t == RuleTarget::ResponseBody);
        if need_buffer {
            let (rbody, _resp_mem) =
                match collect_budgeted(rbody, self.cfg.max_buffered_response, &self.budget).await {
                    Ok(b) => b,
                    Err(CollectError::OutOfMemory) => return busy(),
                    Err(e) => {
                        let msg = format!("failed to read the response body: {e:?}");
                        if record {
                            active.recorder.flow(self.new_flow(
                                flow_id,
                                &target,
                                started,
                                t0,
                                &raw,
                                original_request,
                                Some(head),
                                None,
                                false,
                                Some(msg.clone()),
                                in_scope,
                            ));
                        }
                        return text(StatusCode::BAD_GATEWAY, &msg);
                    }
                };
            let mut resp_raw = serialize_response(rversion, rparts.status, &rparts.headers, &rbody);
            let mut original_response = None;
            if let Some(new) = rules.apply_response(&resp_raw, true) {
                original_response = Some(std::mem::replace(&mut resp_raw, new));
            }
            if self.intercept.should_hold(Phase::Response, in_scope) {
                let held = self
                    .intercept
                    .hold(
                        flow_id,
                        Phase::Response,
                        parts.method.as_str(),
                        &url,
                        Some(rparts.status.as_u16()),
                        resp_raw.clone(),
                    )
                    .await;
                let Ok(held) = held else {
                    return queue_full();
                };
                match held {
                    Decision::Drop => {
                        if record {
                            active.recorder.flow(self.new_flow(
                                flow_id,
                                &target,
                                started,
                                t0,
                                &raw,
                                original_request,
                                Some(resp_raw),
                                original_response,
                                false,
                                Some("response dropped in the intercept queue".into()),
                                in_scope,
                            ));
                        }
                        return text(
                            StatusCode::BAD_GATEWAY,
                            "Response dropped in Bosun's intercept queue.",
                        );
                    }
                    Decision::Forward { raw: Some(edited) } if edited != resp_raw => {
                        original_response.get_or_insert_with(|| resp_raw.clone());
                        resp_raw = edited;
                    }
                    Decision::Forward { .. } => {}
                }
            }
            let response = if original_response.is_some() {
                match response_from_raw(&resp_raw, true) {
                    Ok(r) => r,
                    Err(e) => {
                        return text(
                            StatusCode::BAD_GATEWAY,
                            &format!("the edited response is not valid HTTP: {e}"),
                        );
                    }
                }
            } else {
                strip_hop_by_hop(&mut rparts.headers, false);
                Response::from_parts(rparts, full(rbody))
            };
            if record {
                active.recorder.flow(self.new_flow(
                    flow_id,
                    &target,
                    started,
                    t0,
                    &raw,
                    original_request,
                    Some(resp_raw),
                    original_response,
                    false,
                    None,
                    in_scope,
                ));
            }
            return response;
        }

        // Streamed response. Header and first-line rules can still apply.
        let mut original_head = None;
        if let Some(new) = rules.apply_response(&head, false) {
            match RawResponse::parse(&new) {
                Ok(p) => {
                    if let Ok(s) = StatusCode::from_u16(p.status) {
                        rparts.status = s;
                    }
                    let mut hm = HeaderMap::new();
                    for (n, v) in &p.headers {
                        if let (Ok(n), Ok(v)) =
                            (HeaderName::from_bytes(n.as_bytes()), HeaderValue::from_bytes(v))
                        {
                            hm.append(n, v);
                        }
                    }
                    rparts.headers = hm;
                    original_head = Some(std::mem::replace(&mut head, new));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "a response header rule produced an invalid message; ignored")
                }
            }
        }
        strip_hop_by_hop(&mut rparts.headers, false);
        let shared = self.clone();
        let tee = TeeBody::new(
            rbody,
            self.cfg.record_body_limit,
            Box::new(move |captured, truncated, error| {
                if !record {
                    return;
                }
                let mut full_resp = head;
                full_resp.extend_from_slice(&captured);
                let orig = original_head.map(|mut h| {
                    h.extend_from_slice(&captured);
                    h
                });
                active.recorder.flow(shared.new_flow(
                    flow_id,
                    &target,
                    started,
                    t0,
                    &raw,
                    original_request,
                    Some(full_resp),
                    orig,
                    truncated,
                    error,
                    in_scope,
                ));
            }),
        );
        Response::from_parts(rparts, UnsyncBoxBody::new(tee.with_budget(&self.budget)))
    }

    #[allow(clippy::too_many_arguments)]
    fn new_flow(
        &self,
        id: FlowId,
        target: &Tunnel,
        started: i64,
        t0: std::time::Instant,
        request: &[u8],
        original_request: Option<Vec<u8>>,
        response: Option<Vec<u8>>,
        original_response: Option<Vec<u8>>,
        truncated: bool,
        error: Option<String>,
        in_scope: bool,
    ) -> NewFlow {
        let parsed = RawRequest::parse(request).ok();
        let status = response
            .as_deref()
            .and_then(|r| RawResponse::parse(r).ok())
            .map(|r| r.status);
        NewFlow {
            id,
            source: FlowSource::Proxy,
            started_ms: started,
            duration_ms: Some(t0.elapsed().as_millis() as i64),
            scheme: target.scheme,
            host: target.host.clone(),
            port: target.port,
            method: parsed.as_ref().map(|p| p.method.clone()).unwrap_or_default(),
            path: parsed
                .as_ref()
                .map(|p| p.target.clone())
                .unwrap_or_else(|| "/".into()),
            http_version: parsed.as_ref().map(|p| p.version.clone()).unwrap_or_default(),
            status,
            in_scope,
            edited: original_request.is_some() || original_response.is_some(),
            error,
            request: request.to_vec(),
            original_request,
            response,
            original_response,
            response_truncated: truncated,
        }
    }
}

fn origin(t: &Tunnel) -> String {
    bosun_model::Target::new(t.scheme, t.host.clone(), t.port).origin()
}

fn authority(t: &Tunnel) -> String {
    let host = if t.host.contains(':') {
        format!("[{}]", t.host)
    } else {
        t.host.clone()
    };
    if t.port == t.scheme.default_port() {
        host
    } else {
        format!("{host}:{}", t.port)
    }
}

fn split_host_port(h: &str) -> (&str, Option<u16>) {
    if let Some(rest) = h.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        return (host, tail.strip_prefix(':').and_then(|p| p.parse().ok()));
    }
    match h.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, port.parse().ok()),
        _ => (h, None),
    }
}

fn version_label(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}

fn serialize_request(
    method: &str,
    path: &str,
    version: &str,
    headers: &HeaderMap,
    body: &[u8],
    h2_authority: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 512);
    out.extend_from_slice(format!("{method} {path} {version}\r\n").as_bytes());
    if let Some(a) = h2_authority
        && !headers.contains_key(header::HOST)
    {
        out.extend_from_slice(format!("host: {a}\r\n").as_bytes());
    }
    write_headers(&mut out, headers);
    out.extend_from_slice(body);
    out
}

fn serialize_response(version: &str, status: StatusCode, headers: &HeaderMap, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 512);
    out.extend_from_slice(
        format!(
            "{version} {} {}\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("")
        )
        .as_bytes(),
    );
    write_headers(&mut out, headers);
    out.extend_from_slice(body);
    out
}

fn write_headers(out: &mut Vec<u8>, headers: &HeaderMap) {
    for (n, v) in headers {
        out.extend_from_slice(n.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

fn response_from_raw(raw: &[u8], fix_length: bool) -> Result<Response<RespBody>, bosun_model::ParseError> {
    let p = RawResponse::parse(raw)?;
    let mut r = Response::new(full(p.body.clone()));
    *r.status_mut() =
        StatusCode::from_u16(p.status).map_err(|e| bosun_model::ParseError::Invalid(e.to_string()))?;
    let h = r.headers_mut();
    for (n, v) in &p.headers {
        if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(n.as_bytes()), HeaderValue::from_bytes(v)) {
            h.append(n, v);
        }
    }
    strip_hop_by_hop(h, false);
    if fix_length && h.contains_key(header::CONTENT_LENGTH) {
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(p.body.len()));
    }
    Ok(r)
}

fn is_upgrade(h: &HeaderMap) -> bool {
    h.contains_key(header::UPGRADE)
        && h.get_all(header::CONNECTION).iter().any(|v| {
            v.to_str()
                .is_ok_and(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
        })
}

/// Remove headers that apply to a single connection. hyper frames bodies itself, so Transfer-Encoding goes
/// too.
fn strip_hop_by_hop(h: &mut HeaderMap, keep_upgrade: bool) {
    let listed: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| {
            s.split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .filter(|t| !(keep_upgrade && t == "upgrade"))
        .filter_map(|t| HeaderName::from_bytes(t.as_bytes()).ok())
        .collect();
    for n in listed {
        h.remove(n);
    }
    for n in [
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
    ] {
        h.remove(n);
    }
    if !keep_upgrade {
        h.remove(header::CONNECTION);
        h.remove(header::UPGRADE);
    }
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        let cs = c.to_string();
        if !s.contains(&cs) {
            s.push_str(": ");
            s.push_str(&cs);
        }
        cur = c.source();
    }
    s
}

fn full(b: Vec<u8>) -> RespBody {
    UnsyncBoxBody::new(Full::new(Bytes::from(b)).map_err(|never: Infallible| match never {}))
}

fn empty() -> RespBody {
    UnsyncBoxBody::new(Empty::<Bytes>::new().map_err(|never: Infallible| match never {}))
}

/// 503: the memory budget is spent. The client may retry.
fn busy() -> Response<RespBody> {
    let mut r = text(
        StatusCode::SERVICE_UNAVAILABLE,
        "Bosun is out of memory budget for buffering; try again shortly (proxy.memory_budget_mib).",
    );
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
    r
}

/// 503: the intercept queue is full, so the message was not held. It is not forwarded.
fn queue_full() -> Response<RespBody> {
    text(
        StatusCode::SERVICE_UNAVAILABLE,
        "Bosun's intercept queue is full; the message was refused, not forwarded.",
    )
}

fn text(status: StatusCode, msg: &str) -> Response<RespBody> {
    let mut r = Response::new(full(format!("{msg}\n").into_bytes()));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r.headers_mut().insert(
        HeaderName::from_static("x-bosun"),
        HeaderValue::from_static("proxy-error"),
    );
    r
}

fn proxy_auth_required() -> Response<RespBody> {
    let mut r = text(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "proxy authentication required",
    );
    r.headers_mut().insert(
        header::PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"bosun\""),
    );
    r
}

const MAGIC_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Bosun</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem}code{word-break:break-all}</style>
</head><body>
<h1>Bosun</h1>
<p>Your traffic is going through Bosun. To intercept HTTPS, trust this install's CA certificate in this browser or device.</p>
<ul><li><a href="/cert.pem">Download the CA certificate (PEM)</a></li><li><a href="/cert.der">Download the CA certificate (DER, for Windows/Android/iOS)</a></li></ul>
<p>SHA-256 fingerprint: <code>{fp}</code></p>
<p>Only trust it on devices you use for testing. Anyone holding this install's CA key can read that device's HTTPS traffic.</p>
</body></html>
"#;

/// A stream that replays some already-read bytes before reading from the inner stream.
struct Rewind<I> {
    pre: Vec<u8>,
    pos: usize,
    inner: I,
}

impl<I> Rewind<I> {
    fn new(inner: I, pre: Vec<u8>) -> Self {
        Self { pre, pos: 0, inner }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for Rewind<I> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.pre.len() {
            let n = (self.pre.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.pre[start..start + n]);
            self.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Rewind<I> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_headers_are_removed() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        h.insert("x-secret", HeaderValue::from_static("1"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert(header::PROXY_AUTHORIZATION, HeaderValue::from_static("Basic x"));
        h.insert("x-keep", HeaderValue::from_static("1"));
        strip_hop_by_hop(&mut h, false);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("x-keep"));
    }

    #[test]
    fn host_port_splitting() {
        assert_eq!(split_host_port("a.test:8080"), ("a.test", Some(8080)));
        assert_eq!(split_host_port("a.test"), ("a.test", None));
        assert_eq!(split_host_port("[::1]:9"), ("::1", Some(9)));
        assert_eq!(split_host_port("::1"), ("::1", None));
    }
}
