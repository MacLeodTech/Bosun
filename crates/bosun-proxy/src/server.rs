//! The proxy listener and per-request handling.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bosun_ca::CertificateAuthority;
use bosun_model::{FlowId, FlowSource, RawRequest, RawResponse, Scheme};
use bosun_scope::{Gate, RuleSpec as ScopeRule, Scope, ScopeSpec};
use bosun_store::{NewFlow, Project};
use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use http_body::Body as _;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::body::{CollectError, LimitBody, TeeBody, collect_budgeted, discard_body};
use crate::budget::MemoryBudget;
use crate::config::{ListenerSpec, LiveSettings, ProxyConfig};
use crate::events::EventSender;
use crate::intercept::{Decision, InterceptController, Phase};
use crate::limits::ConnLimit;
use crate::mapping::{LocalOutcome, MapAction, MapDecision, MapRule, MapRules, RemoteTarget, ThrottleBody};
use crate::recorder::Recorder;
use crate::rules::{RuleSet, RuleSpec, RuleTarget};
use crate::upstream::{BoxError, Connector, LoopGuard};

pub type RespBody = UnsyncBoxBody<Bytes, BoxError>;
/// The body sent upstream: buffered (`Full`) or streamed from the client.
type UpBody = UnsyncBoxBody<Bytes, BoxError>;
type UpClient = Client<Connector, UpBody>;

/// What the client asked for, passed along so recording does not parse the message again.
struct ReqState {
    raw: Vec<u8>,
    original: Option<Vec<u8>>,
    /// The streamed request body's captured bytes, appended to `raw` (and `original`) when the flow is stored.
    tail: Option<Arc<Tail>>,
    /// Milliseconds until the response head arrived.
    ttfb_ms: Option<i64>,
    method: String,
    path: String,
    version: String,
}

impl ReqState {
    /// Re-derive the method, path and version after the message text was changed (rules or an edit).
    fn reparse(&mut self) {
        if let Ok(p) = RawRequest::parse(&self.raw) {
            self.method = p.method;
            self.path = p.target;
            self.version = p.version;
        }
    }

    /// The text to store: the head, plus the captured streamed body if the upload has ended. When it has not, the
    /// tail is returned to be appended once it does (see [`submit`]).
    fn finish(mut self) -> Finished {
        let mut raw = std::mem::take(&mut self.raw);
        let mut original = self.original.take();
        let pending = match self.tail.take() {
            Some(t) if t.is_done() => {
                let d = t.take();
                if let Some(o) = &mut original {
                    o.extend_from_slice(&d);
                }
                raw.extend_from_slice(&d);
                None
            }
            other => other,
        };
        (self.method, self.path, self.version, raw, original, pending)
    }
}

/// Method, path, version, the request text, its original text and a not yet finished upload.
type Finished = (
    String,
    String,
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Arc<Tail>>,
);

/// A streamed request body's captured bytes and whether the upload has ended.
struct Tail {
    data: std::sync::Mutex<Vec<u8>>,
    done: tokio::sync::watch::Sender<bool>,
}

impl Tail {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            data: Default::default(),
            done: tokio::sync::watch::channel(false).0,
        })
    }
    fn is_done(&self) -> bool {
        *self.done.borrow()
    }
    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.data.lock().unwrap_or_else(|e| e.into_inner()))
    }
    fn complete(&self, captured: Vec<u8>) {
        *self.data.lock().unwrap_or_else(|e| e.into_inner()) = captured;
        self.done.send_replace(true);
    }
}

/// A flow ready to store, except that its streamed request body may still be uploading.
struct Built {
    flow: NewFlow,
    pending: Option<Arc<Tail>>,
}

/// How long a recorded flow waits for a request upload that outlives its response.
const UPLOAD_WAIT: Duration = Duration::from_secs(300);

/// Store a flow. When the response ended before the request upload did, the flow is stored once the upload ends
/// (or is cut off), so it holds the whole request body and not only what was captured so far.
fn submit(active: &Arc<Active>, built: Built) {
    let Built { mut flow, pending } = built;
    let Some(tail) = pending else {
        active.recorder.flow(flow);
        return;
    };
    let active = active.clone();
    tokio::spawn(async move {
        let mut rx = tail.done.subscribe();
        let _ = tokio::time::timeout(UPLOAD_WAIT, rx.wait_for(|d| *d)).await;
        let d = tail.take();
        if let Some(o) = &mut flow.original_request {
            o.extend_from_slice(&d);
        }
        flow.request.extend_from_slice(&d);
        active.recorder.flow(flow);
    });
}

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
    pub maps: RwLock<Arc<MapRules>>,
    pub client: UpClient,
    pub ws_client: UpClient,
    /// Opens plain TCP for pass-through tunnels: same upstream proxy and loop guard as the HTTP clients.
    pub tcp: Connector,
    pub guard: LoopGuard,
    pub limit: ConnLimit,
    pub budget: MemoryBudget,
    /// Settings that change while running (see [`Proxy::set_live`]).
    pub live: RwLock<Arc<LiveSettings>>,
    pub listeners: Mutex<Listeners>,
}

/// A listener's options, compiled. Swapped whole when they change, so a request sees one consistent set.
pub(crate) struct ListenerOpts {
    spec: ListenerSpec,
    passthrough: Scope,
    expected_auth: Option<String>,
}

impl ListenerOpts {
    fn compile(spec: ListenerSpec) -> Result<Self, String> {
        spec.validate()?;
        let passthrough = Scope::compile(ScopeSpec {
            include: spec
                .tls_passthrough
                .iter()
                .map(|h| ScopeRule {
                    host: h.clone(),
                    ..Default::default()
                })
                .collect(),
            exclude: vec![],
        })
        .map_err(|e| format!("tls_passthrough: {e}"))?;
        let expected_auth = spec.auth.as_ref().map(|a| {
            use base64::Engine;
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", a.username, a.password))
            )
        });
        Ok(Self {
            spec,
            passthrough,
            expected_auth,
        })
    }
}

/// A running listener.
pub(crate) struct ListenerRt {
    id: u32,
    primary: bool,
    addr: SocketAddr,
    opts: RwLock<Arc<ListenerOpts>>,
    accepted: AtomicU64,
    /// Connections open now, against `max_connections`.
    open: Arc<std::sync::atomic::AtomicUsize>,
    task: Mutex<Option<tokio::task::AbortHandle>>,
}

/// Holds one slot of a listener's connection cap until the connection ends.
struct OpenGuard(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl ListenerRt {
    /// A slot for a new connection, or `None` when the listener's `max_connections` is reached.
    fn try_open(&self) -> Option<OpenGuard> {
        use std::sync::atomic::Ordering::AcqRel;
        let max = self.opts().spec.max_connections.unwrap_or(usize::MAX);
        if self.open.fetch_add(1, AcqRel) >= max {
            self.open.fetch_sub(1, AcqRel);
            return None;
        }
        Some(OpenGuard(self.open.clone()))
    }

    fn opts(&self) -> Arc<ListenerOpts> {
        self.opts.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[derive(Default)]
pub(crate) struct Listeners {
    next: u32,
    all: Vec<Arc<ListenerRt>>,
}

/// A listener as the API shows it. The password is never part of it.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ListenerInfo {
    pub id: u32,
    /// The listener from the config file: its options change live, but it cannot be removed or moved.
    pub primary: bool,
    #[serde(flatten)]
    pub spec: ListenerSpec,
    pub auth_required: bool,
    /// Connections accepted since it started.
    pub accepted: u64,
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
    listener: Arc<ListenerRt>,
    tunnel: Option<Tunnel>,
    /// Where a redirected (transparent) connection was originally headed; `None` when it was addressed to the
    /// proxy itself or the platform can't say.
    orig_dst: Option<SocketAddr>,
}

/// The original destination of a connection redirected to us by the firewall (Linux `SO_ORIGINAL_DST`).
#[cfg(target_os = "linux")]
fn original_dst(stream: &TcpStream) -> Option<SocketAddr> {
    use nix::sys::socket::{getsockopt, sockopt};
    if let Ok(a) = getsockopt(stream, sockopt::OriginalDst) {
        let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
        return Some(SocketAddr::new(ip.into(), u16::from_be(a.sin_port)));
    }
    let a = getsockopt(stream, sockopt::Ip6tOriginalDst).ok()?;
    Some(SocketAddr::new(
        std::net::Ipv6Addr::from(a.sin6_addr.s6_addr).into(),
        u16::from_be(a.sin6_port),
    ))
}

#[cfg(not(target_os = "linux"))]
fn original_dst(_: &TcpStream) -> Option<SocketAddr> {
    None
}

/// Resource counters (see [`Proxy::stats`]).
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ProxyStats {
    pub memory_budget: usize,
    pub memory_used: usize,
    pub memory_refused: u64,
    /// Connections closed at once because the proxy was at its connection limit.
    pub connections_refused: u64,
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
        let certs = crate::clientcert::ClientCerts::default();
        let mk = |h2: bool| -> Result<UpClient, ProxyError> {
            let conn = Connector::new(
                cfg.upstream.as_ref(),
                cfg.verify_upstream_tls,
                h2,
                guard.clone(),
                self_addrs.clone(),
            )
            .map_err(ProxyError::Config)?
            .with_sni_overrides(&cfg.upstream_sni)
            .with_client_certs(certs.clone());
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
        .map_err(ProxyError::Config)?
        .with_sni_overrides(&cfg.upstream_sni)
        .with_client_certs(certs.clone());
        let limit = ConnLimit::new("proxy", cfg.max_connections);
        let client = mk(true)?;
        let ws_client = mk(false)?;
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
                ca,
                gate,
                active: RwLock::new(active),
                events,
                rules: RwLock::new(Arc::new(RuleSet::default())),
                maps: RwLock::new(Arc::new(MapRules::default())),
                client,
                ws_client,
                tcp,
                guard,
                limit,
                budget,
                live: RwLock::new(Arc::new(LiveSettings::from_config(&cfg))),
                listeners: Mutex::new(Listeners::default()),
                cfg,
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
            connections_refused: sh.limit.refused(),
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

    pub fn map_rules(&self) -> Vec<MapRule> {
        self.shared.maps().specs().to_vec()
    }

    /// Replace the Map Local, Map Remote and throttle rules; the first rule that cannot be used is an error.
    pub fn set_map_rules(&self, specs: Vec<MapRule>) -> Result<(), String> {
        let m = MapRules::compile(specs)?;
        *self.shared.maps.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(m);
        Ok(())
    }

    /// Load saved rules, leaving out any that cannot be used now. Returns how many were left out.
    pub fn load_map_rules(&self, specs: Vec<MapRule>) -> usize {
        let (m, skipped) = MapRules::compile_lossy(specs);
        *self.shared.maps.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(m);
        skipped
    }

    /// Whether the scope gate lets a Map Remote rule send to `target`. Resolves the name: blocking.
    pub fn check_remote_target(&self, target: &RemoteTarget) -> Result<(), String> {
        remote_gate_check(&self.shared.gate, target, "/")
    }

    /// Wait until everything recorded so far has been written to the project.
    pub fn flush(&self) {
        self.shared.active().recorder.flush();
    }

    /// Record a flow made by a tool (the Repeater) in the open project, through the same recorder as proxied ones.
    pub fn record(&self, f: bosun_store::NewFlow) {
        self.shared.active().recorder.flow(f);
    }

    /// Record a WebSocket message of a flow made by a tool.
    pub fn record_ws(&self, m: bosun_store::NewWsMessage) {
        self.shared.active().recorder.ws(m);
    }

    /// The memory budget shared by the proxy and the tools.
    pub fn budget(&self) -> MemoryBudget {
        self.shared.budget.clone()
    }

    /// A plain-TCP connector with the proxy's upstream proxy and loop guard, for tools that make their own requests.
    pub fn tool_connector(&self) -> Connector {
        self.shared.tcp.clone()
    }

    /// The client certificates presented to upstream hosts, shared with the tools' engine.
    pub fn client_certs(&self) -> crate::clientcert::ClientCerts {
        self.shared.tcp.client_certs().clone()
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

    /// Accept connections on the configured listener until `shutdown` resolves.
    pub async fn serve(&self, listener: TcpListener, shutdown: impl std::future::Future<Output = ()>) {
        let addr = listener.local_addr().unwrap_or(self.shared.cfg.listen);
        let spec = ProxyConfig {
            listen: addr,
            ..self.shared.cfg.clone()
        }
        .listener_spec();
        let Ok(opts) = ListenerOpts::compile(spec) else {
            return;
        };
        let rt = self.register(addr, true, opts);
        self.shared.guard.add_self([addr]);
        accept_loop(self.shared.clone(), rt, listener, shutdown).await;
    }

    fn register(&self, addr: SocketAddr, primary: bool, opts: ListenerOpts) -> Arc<ListenerRt> {
        let mut l = self.shared.listeners.lock().unwrap_or_else(|e| e.into_inner());
        l.next += 1;
        let rt = Arc::new(ListenerRt {
            id: l.next,
            primary,
            addr,
            opts: RwLock::new(Arc::new(opts)),
            accepted: AtomicU64::new(0),
            open: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            task: Mutex::new(None),
        });
        l.all.push(rt.clone());
        rt
    }

    fn info(rt: &ListenerRt) -> ListenerInfo {
        let o = rt.opts();
        ListenerInfo {
            id: rt.id,
            primary: rt.primary,
            auth_required: o.spec.auth.is_some(),
            spec: ListenerSpec {
                addr: rt.addr,
                ..o.spec.clone()
            },
            accepted: rt.accepted.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Every listener, the configured one first.
    pub fn listeners(&self) -> Vec<ListenerInfo> {
        let l = self.shared.listeners.lock().unwrap_or_else(|e| e.into_inner());
        l.all.iter().map(|r| Self::info(r)).collect()
    }

    /// Every listener's spec with its password, the configured one first (flagged true): what has to be kept to
    /// bring them back. Never send these to a client.
    pub fn listener_specs(&self) -> Vec<(u32, bool, ListenerSpec)> {
        let l = self.shared.listeners.lock().unwrap_or_else(|e| e.into_inner());
        l.all
            .iter()
            .map(|r| {
                (
                    r.id,
                    r.primary,
                    ListenerSpec {
                        addr: r.addr,
                        ..r.opts().spec.clone()
                    },
                )
            })
            .collect()
    }

    /// Start another listener. It shares the connection limit and everything else with the others; no restart.
    pub async fn add_listener(&self, spec: ListenerSpec) -> Result<ListenerInfo, ProxyError> {
        let opts = ListenerOpts::compile(spec).map_err(ProxyError::Config)?;
        let addr = opts.spec.addr;
        {
            let l = self.shared.listeners.lock().unwrap_or_else(|e| e.into_inner());
            if addr.port() != 0 && l.all.iter().any(|r| r.addr == addr) {
                return Err(ProxyError::Config(format!("{addr} is already a proxy listener")));
            }
            if self.shared.guard.is_self(&addr) {
                return Err(ProxyError::Config(format!(
                    "{addr} is Bosun's own UI/API listener"
                )));
            }
        }
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ProxyError::Bind(addr, e))?;
        let bound = listener.local_addr().map_err(|e| ProxyError::Bind(addr, e))?;
        let rt = self.register(bound, false, opts);
        self.shared.guard.add_self([bound]);
        let handle = tokio::spawn(accept_loop(
            self.shared.clone(),
            rt.clone(),
            listener,
            std::future::pending::<()>(),
        ));
        *rt.task.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle.abort_handle());
        Ok(Self::info(&rt))
    }

    /// Change a listener's options, in effect for the next request on it. Connections already open keep running
    /// under the new options from their next request. An added listener may also move to another address (it is
    /// bound first, so a failure leaves it where it was); the configured one may not.
    pub async fn update_listener(&self, id: u32, spec: ListenerSpec) -> Result<ListenerInfo, ProxyError> {
        let opts = ListenerOpts::compile(spec).map_err(ProxyError::Config)?;
        let rt = self
            .find(id)
            .ok_or_else(|| ProxyError::Config(format!("no listener {id}")))?;
        if opts.spec.addr != rt.addr {
            if rt.primary {
                return Err(ProxyError::Config(
                    "the address of the configured listener needs a restart; add another listener instead"
                        .into(),
                ));
            }
            // Different address: start the new one, then retire this one.
            let fresh = self.add_listener(opts.spec.clone()).await?;
            self.remove_listener(id)?;
            return Ok(fresh);
        }
        *rt.opts.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(opts);
        Ok(Self::info(&rt))
    }

    fn find(&self, id: u32) -> Option<Arc<ListenerRt>> {
        let l = self.shared.listeners.lock().unwrap_or_else(|e| e.into_inner());
        l.all.iter().find(|r| r.id == id).cloned()
    }

    /// Stop listening on an added listener. Connections it already accepted run to their end.
    pub fn remove_listener(&self, id: u32) -> Result<(), ProxyError> {
        let mut l = self.shared.listeners.lock().unwrap_or_else(|e| e.into_inner());
        let Some(i) = l.all.iter().position(|r| r.id == id) else {
            return Err(ProxyError::Config(format!("no listener {id}")));
        };
        if l.all[i].primary {
            return Err(ProxyError::Config(
                "the configured listener cannot be removed while running".into(),
            ));
        }
        let rt = l.all.remove(i);
        if let Some(h) = rt.task.lock().unwrap_or_else(|e| e.into_inner()).take() {
            h.abort();
        }
        self.shared.guard.remove_self(&rt.addr);
        Ok(())
    }

    /// Stop every added listener (the configured one stops with its `serve` call).
    pub fn stop_added_listeners(&self) {
        let ids: Vec<u32> = self
            .listeners()
            .into_iter()
            .filter(|l| !l.primary)
            .map(|l| l.id)
            .collect();
        for id in ids {
            let _ = self.remove_listener(id);
        }
    }

    pub fn live(&self) -> LiveSettings {
        (*self.shared.live()).clone()
    }

    /// Apply new live settings. The connection limit takes effect at once; the rest from the next request or
    /// connection.
    pub fn set_live(&self, s: LiveSettings) -> Result<(), ProxyError> {
        s.validate().map_err(ProxyError::Config)?;
        self.shared.limit.set_max(s.max_connections);
        *self.shared.live.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(s);
        Ok(())
    }
}

async fn accept_loop(
    shared: Arc<Shared>,
    rt: Arc<ListenerRt>,
    listener: TcpListener,
    shutdown: impl std::future::Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { continue };
                // Over the limit: close at once; connections already open are unaffected.
                let Some(permit) = shared.limit.try_acquire() else { continue };
                let Some(slot) = rt.try_open() else {
                    tracing::debug!(%peer, listener = %rt.addr, "listener connection cap reached; closing");
                    continue;
                };
                rt.accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (shared, rt) = (shared.clone(), rt.clone());
                tokio::spawn(async move {
                    let (_permit, _slot) = (permit, slot);
                    shared.accept(stream, peer, rt).await
                });
            }
        }
    }
}

impl Shared {
    fn active(&self) -> Arc<Active> {
        self.active.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn maps(&self) -> Arc<MapRules> {
        self.maps.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn rules(&self) -> Arc<RuleSet> {
        self.rules.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn live(&self) -> Arc<LiveSettings> {
        self.live.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn accept(self: Arc<Self>, stream: TcpStream, peer: SocketAddr, listener: Arc<ListenerRt>) {
        let ip = peer.ip().to_canonical();
        let allow = &listener.opts().spec.allow_clients;
        if !(allow.is_empty() || allow.iter().any(|n| n.contains(&ip))) {
            tracing::warn!(%peer, "proxy client not in allow_clients; closing");
            return;
        }
        if self.guard.is_own(&peer) {
            tracing::warn!(%peer, "refused a connection from the proxy's own outbound traffic (loop)");
            return;
        }
        let _ = stream.set_nodelay(true);
        let mut ctx = ConnCtx {
            peer,
            listener,
            tunnel: None,
            orig_dst: None,
        };
        if ctx.listener.opts().spec.invisible {
            ctx.orig_dst = original_dst(&stream).filter(|d| Some(*d) != stream.local_addr().ok());
        }
        if ctx.listener.opts().spec.invisible {
            // Transparent HTTPS: a TLS ClientHello arriving straight at the listener. The target is the SNI
            // (port 443); without one there is nothing to name the host, so the connection is closed.
            let mut first = [0u8; 1];
            let seen = tokio::time::timeout(Duration::from_secs(30), stream.peek(&mut first)).await;
            match seen {
                Ok(Ok(1)) if first[0] == 0x16 => {
                    let port = ctx.orig_dst.map_or(443, |d| d.port());
                    self.mitm(stream, ctx, String::new(), port).await;
                    return;
                }
                Ok(Ok(n)) if n > 0 => {}
                _ => return,
            }
        }
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
            .header_read_timeout(Duration::from_secs(self.live().header_timeout_secs.max(1)))
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
        if ctx.tunnel.is_none() && !self.authorised(&ctx, req.headers()) {
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
        } else if ctx.listener.opts().spec.invisible {
            let Some(h) = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) else {
                return text(StatusCode::BAD_REQUEST, "invisible proxying needs a Host header");
            };
            let (host, port) = split_host_port(h);
            Tunnel {
                scheme: Scheme::Http,
                host: host.to_ascii_lowercase(),
                port: port.unwrap_or_else(|| ctx.orig_dst.map_or(80, |d| d.port())),
            }
        } else {
            return text(
                StatusCode::BAD_REQUEST,
                "This is the Bosun proxy. Configure your client to use it as an HTTP proxy, or open \
                 http://bosun/ through it to download the CA certificate.",
            );
        };
        let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let maps = self.maps();
        let decision = if maps.is_empty() {
            MapDecision::default()
        } else {
            maps.decide(&target.host, req.method().as_str(), path)
        };
        let bps = decision.throttle.map_or(0, |t| t.bytes_per_sec);
        let resp = self.proxy_request(ctx, target, req, decision).await;
        if bps == 0 {
            return resp;
        }
        let (parts, body) = resp.into_parts();
        Response::from_parts(parts, UnsyncBoxBody::new(ThrottleBody::new(body, bps)))
    }

    fn authorised(&self, ctx: &ConnCtx, headers: &HeaderMap) -> bool {
        match &ctx.listener.opts().expected_auth {
            None => true,
            Some(expected) => headers
                .get(header::PROXY_AUTHORIZATION)
                .is_some_and(|v| bool::from(v.as_bytes().ct_eq(expected.as_bytes()))),
        }
    }

    async fn connect(self: Arc<Self>, ctx: ConnCtx, mut req: Request<Incoming>) -> Response<RespBody> {
        if !self.authorised(&ctx, req.headers()) {
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
        let passthrough = ctx
            .listener
            .opts()
            .passthrough
            .contains(Scheme::Https, &host, port, "/");
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
            let sni = start.client_hello().server_name().map(|n| n.to_ascii_lowercase());
            let mut host = host;
            if host.is_empty() {
                // Transparent mode: the SNI is the only name the client gave.
                match &sni {
                    Some(n) => host = n.clone(),
                    None => match ctx.orig_dst {
                        // No SNI, but the firewall told us where it was going.
                        Some(d) => host = d.ip().to_string(),
                        None => {
                            tracing::info!("transparent TLS connection without an SNI or original destination; closing");
                            return;
                        }
                    },
                }
            }
            let cert_host = sni.clone().unwrap_or_else(|| host.clone());
            let cfg = match self.ca.server_config(&cert_host, self.live().http2) {
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
                .header_read_timeout(Duration::from_secs(self.live().header_timeout_secs.max(1)));
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
        let mut r = Response::new(full(Bytes::from(body)));
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
        decision: MapDecision,
    ) -> Response<RespBody> {
        let started = bosun_model::now_ms();
        let t0 = std::time::Instant::now();
        let active = self.active();
        let wants_upgrade = is_upgrade(req.headers());
        let client_upgrade = wants_upgrade.then(|| hyper::upgrade::on(&mut req));
        let (parts, mut body) = req.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let path = if path.is_empty() { "/".to_string() } else { path };
        let version = version_label(parts.version);
        let authority_for_h2 = (parts.version == Version::HTTP_2).then(|| authority(&target));
        let in_scope = self
            .gate
            .scope()
            .contains(target.scheme, &target.host, target.port, &path);
        let record = in_scope || self.live().record_out_of_scope;
        // An id is reserved only for flows that are stored (or held in the intercept queue).
        let mut flow_id: Option<FlowId> = record.then(|| active.project.next_flow_id());
        let rules = self.rules();
        let hold_request = self.intercept.should_hold(Phase::Request, in_scope);
        let any_request_rule = rules.has(|t| {
            matches!(
                t,
                RuleTarget::RequestFirstLine | RuleTarget::RequestHeader | RuleTarget::RequestBody
            )
        });
        // A request body is streamed (with a capped copy for the record) unless intercept or a body rule needs it
        // whole.
        let stream_request = !wants_upgrade
            && !hold_request
            && !body.is_end_stream()
            && !rules.has(|t| t == RuleTarget::RequestBody);
        let mut stream_body: Option<UpBody> = None;
        let mut tail = None;
        let _mem;
        let body = if stream_request {
            if body.size_hint().lower() > self.live().max_request_body as u64 {
                discard_body(body).await;
                return text(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body is larger than proxy.max_request_body",
                );
            }
            let limited = LimitBody::new(body, self.live().max_request_body);
            if record {
                // Reserve the part that will be kept up front; refuse (503) when it would not fit the budget.
                let expect = (limited.size_hint().lower() as usize).min(self.live().record_body_limit);
                let Some(admit) = self.budget.reserve(expect * crate::budget::COPY_FACTOR) else {
                    discard_body(limited).await;
                    return busy();
                };
                let slot = Tail::new();
                let slot2 = slot.clone();
                let tee = TeeBody::new(
                    limited,
                    self.live().record_body_limit,
                    Box::new(move |captured, _truncated, _error| {
                        slot2.complete(captured);
                    }),
                )
                .with_reservation(&self.budget, admit);
                tail = Some(slot);
                stream_body = Some(UnsyncBoxBody::new(tee));
            } else {
                stream_body = Some(UnsyncBoxBody::new(limited));
            }
            _mem = None;
            Bytes::new()
        } else {
            // `_mem` keeps the body's bytes counted against the memory budget while this request is in flight.
            let (b, mem) = match collect_budgeted(&mut body, self.live().max_request_body, &self.budget).await
            {
                Ok(b) => b,
                Err(CollectError::TooBig) => {
                    // Let the client finish its upload, so it can read the answer (see `discard_body`).
                    discard_body(body).await;
                    return text(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request body is larger than proxy.max_request_body",
                    );
                }
                Err(CollectError::OutOfMemory) => {
                    discard_body(body).await;
                    return busy();
                }
                Err(CollectError::Other(_)) => {
                    return text(StatusCode::BAD_REQUEST, "failed to read the request body");
                }
            };
            _mem = Some(mem);
            b
        };
        let need_raw = record || hold_request || any_request_rule;
        let mut req_state = ReqState {
            raw: if need_raw {
                serialize_request(
                    parts.method.as_str(),
                    &path,
                    version,
                    &parts.headers,
                    &body,
                    authority_for_h2.as_deref(),
                )
            } else {
                Vec::new()
            },
            original: None,
            tail,
            ttfb_ms: None,
            method: parts.method.as_str().to_string(),
            path: path.clone(),
            version: version.to_string(),
        };
        if any_request_rule && let Some(new) = rules.apply_request(&req_state.raw) {
            req_state.original = Some(std::mem::replace(&mut req_state.raw, new));
            req_state.reparse();
        }
        let url = format!("{}{}", origin(&target), path);
        if hold_request {
            let id = *flow_id.get_or_insert_with(|| active.project.next_flow_id());
            let held = self
                .intercept
                .hold(
                    id,
                    Phase::Request,
                    &req_state.method,
                    &url,
                    None,
                    req_state.raw.clone(),
                )
                .await;
            let Ok(held) = held else {
                return queue_full();
            };
            match held {
                Decision::Drop => {
                    if record {
                        submit(
                            &active,
                            self.new_flow(
                                flow_id.unwrap_or_default(),
                                &target,
                                started,
                                t0,
                                req_state,
                                None,
                                None,
                                None,
                                false,
                                Some("dropped in the intercept queue".into()),
                                in_scope,
                            ),
                        );
                    }
                    return text(
                        StatusCode::BAD_GATEWAY,
                        "Request dropped in Bosun's intercept queue.",
                    );
                }
                Decision::Forward { raw: Some(edited) } if edited != req_state.raw => {
                    let old = std::mem::replace(&mut req_state.raw, edited);
                    req_state.original.get_or_insert(old);
                    req_state.reparse();
                }
                Decision::Forward { .. } => {}
            }
        }

        // Map Local answers here, from a file; Map Remote changes where the request goes (what is recorded and
        // shown keeps the original target).
        let mut out_target = target.clone();
        let mut remapped = false;
        match &decision.action {
            Some(MapAction::Local(local)) => {
                let (local, p, max) = (
                    local.clone(),
                    req_state.path.clone(),
                    self.live().max_buffered_response,
                );
                let outcome = tokio::task::spawn_blocking(move || local.read(&p, max))
                    .await
                    .unwrap_or(LocalOutcome::NotFound);
                let (status, bytes, ctype) = match outcome {
                    LocalOutcome::File { bytes, content_type } => (StatusCode::OK, bytes, content_type),
                    LocalOutcome::Forbidden => (
                        StatusCode::FORBIDDEN,
                        b"Map Local refused this path: it leaves the chosen directory.\n".to_vec(),
                        "text/plain; charset=utf-8",
                    ),
                    LocalOutcome::TooBig => (
                        StatusCode::BAD_GATEWAY,
                        b"Map Local: the file is larger than proxy.max_buffered_response.\n".to_vec(),
                        "text/plain; charset=utf-8",
                    ),
                    LocalOutcome::NotFound => (StatusCode::OK, Vec::new(), ""),
                };
                if !ctype.is_empty() {
                    let head_only = req_state.method == "HEAD";
                    let mut raw = format!(
                        "HTTP/1.1 {} {}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\ncache-control: no-store\r\nx-bosun-map: local\r\n\r\n",
                        status.as_u16(),
                        status.canonical_reason().unwrap_or(""),
                        bytes.len()
                    )
                    .into_bytes();
                    let stored = {
                        let mut r = raw.clone();
                        r.extend_from_slice(&bytes);
                        r
                    };
                    if !head_only {
                        raw.extend_from_slice(&bytes);
                    }
                    if record {
                        submit(
                            &active,
                            self.new_flow(
                                flow_id.unwrap_or_default(),
                                &target,
                                started,
                                t0,
                                req_state,
                                Some(status.as_u16()),
                                Some(stored),
                                None,
                                false,
                                None,
                                in_scope,
                            ),
                        );
                    }
                    if let Ok(r) = response_from_raw(&raw, false) {
                        return r;
                    }
                    return text(StatusCode::BAD_GATEWAY, "Map Local could not build the response");
                }
            }
            Some(MapAction::Remote(to)) => {
                // The new target must be allowed by the scope gate, exactly like a tool's request would be.
                let (gate, to2, p) = (self.gate.clone(), to.clone(), req_state.path.clone());
                let checked = tokio::task::spawn_blocking(move || remote_gate_check(&gate, &to2, &p))
                    .await
                    .unwrap_or_else(|_| Err("the check did not finish".into()));
                if let Err(msg) = checked {
                    let msg = format!("Map Remote refused: {msg}");
                    if record {
                        submit(
                            &active,
                            self.new_flow(
                                flow_id.unwrap_or_default(),
                                &target,
                                started,
                                t0,
                                req_state,
                                None,
                                None,
                                None,
                                false,
                                Some(msg.clone()),
                                in_scope,
                            ),
                        );
                    }
                    return text(StatusCode::FORBIDDEN, &msg);
                }
                out_target = Tunnel {
                    scheme: to.scheme,
                    host: to.host.clone(),
                    port: to.port,
                };
                remapped = true;
            }
            None => {}
        }
        if let Some(t) = decision.throttle
            && t.latency_ms > 0
        {
            tokio::time::sleep(Duration::from_millis(u64::from(t.latency_ms))).await;
        }

        // Build the outbound request: from the (possibly edited) raw text if anything changed, otherwise from
        // the original parts so nothing is normalised unnecessarily.
        let (method, out_path, mut headers, out_body) = if req_state.original.is_some() {
            match RawRequest::parse(&req_state.raw) {
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
                    if stream_body.is_none() && hm.contains_key(header::CONTENT_LENGTH) {
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
            (parts.method.clone(), path.clone(), parts.headers.clone(), body)
        };
        strip_hop_by_hop(&mut headers, wants_upgrade);
        if (remapped || !headers.contains_key(header::HOST))
            && let Ok(v) = HeaderValue::from_str(&authority(&out_target))
        {
            headers.insert(header::HOST, v);
        }
        let uri = format!(
            "{}{}",
            origin(&out_target),
            if out_path.starts_with('/') {
                out_path.clone()
            } else {
                format!("/{out_path}")
            }
        );
        let Ok(uri) = uri.parse::<http::Uri>() else {
            return text(StatusCode::BAD_REQUEST, "invalid request target");
        };
        let mut out = Request::new(stream_body.unwrap_or_else(|| {
            UnsyncBoxBody::new(Full::new(out_body).map_err(|never: Infallible| match never {}))
        }));
        *out.method_mut() = method;
        *out.uri_mut() = uri;
        *out.headers_mut() = headers;
        // Keeps the client's header-name casing for HTTP/1 (hyper stores it in the extensions). After an edit
        // the names that are still there keep their casing; a name the edit added goes out in lower case.
        *out.extensions_mut() = parts.extensions;
        let client = if wants_upgrade {
            &self.ws_client
        } else {
            &self.client
        };
        let resp = match tokio::time::timeout(
            Duration::from_secs(self.live().upstream_timeout_secs),
            client.request(out),
        )
        .await
        {
            Ok(Ok(r)) => {
                req_state.ttfb_ms = Some(t0.elapsed().as_millis() as i64);
                r
            }
            Ok(Err(e)) => {
                let msg = error_chain(&e);
                if record {
                    submit(
                        &active,
                        self.new_flow(
                            flow_id.unwrap_or_default(),
                            &target,
                            started,
                            t0,
                            req_state,
                            None,
                            None,
                            None,
                            false,
                            Some(msg.clone()),
                            in_scope,
                        ),
                    );
                }
                return text(
                    StatusCode::BAD_GATEWAY,
                    &format!("Bosun could not reach {}: {msg}", origin(&out_target)),
                );
            }
            Err(_) => {
                let msg = "timed out waiting for the response".to_string();
                if record {
                    submit(
                        &active,
                        self.new_flow(
                            flow_id.unwrap_or_default(),
                            &target,
                            started,
                            t0,
                            req_state,
                            None,
                            None,
                            None,
                            false,
                            Some(msg.clone()),
                            in_scope,
                        ),
                    );
                }
                return text(StatusCode::GATEWAY_TIMEOUT, &msg);
            }
        };

        let mut resp = resp;
        let server_upgrade = (resp.status() == StatusCode::SWITCHING_PROTOCOLS && client_upgrade.is_some())
            .then(|| hyper::upgrade::on(&mut resp));
        let (mut rparts, mut rbody) = resp.into_parts();
        let rversion = version_label(rparts.version);
        let mut head = serialize_response(rversion, rparts.status, &rparts.headers, &[]);

        // WebSocket (or other) upgrade.
        if rparts.status == StatusCode::SWITCHING_PROTOCOLS
            && let (Some(client_upgrade), Some(server_upgrade)) = (client_upgrade, server_upgrade)
        {
            if record {
                submit(
                    &active,
                    self.new_flow(
                        flow_id.unwrap_or_default(),
                        &target,
                        started,
                        t0,
                        req_state,
                        Some(rparts.status.as_u16()),
                        Some(head),
                        None,
                        false,
                        None,
                        in_scope,
                    ),
                );
            }
            let recorder = active.recorder.clone();
            let ws_id = flow_id.unwrap_or_default();
            let deflate = rparts
                .headers
                .get_all("sec-websocket-extensions")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .find_map(crate::ws::DeflateParams::from_header);
            tokio::spawn(async move {
                match tokio::join!(client_upgrade, server_upgrade) {
                    (Ok(c), Ok(s)) => {
                        if record {
                            crate::ws::relay(TokioIo::new(c), TokioIo::new(s), ws_id, recorder, deflate)
                                .await;
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

        let resp_hold = self.intercept.response_hold(
            in_scope,
            hold_request,
            rparts.status.as_u16(),
            &String::from_utf8_lossy(&head),
        );
        let need_buffer =
            resp_hold != crate::intercept::RespHold::No || rules.has(|t| t == RuleTarget::ResponseBody);
        if need_buffer {
            let (rbody, _resp_mem) =
                match collect_budgeted(&mut rbody, self.live().max_buffered_response, &self.budget).await {
                    Ok(b) => b,
                    Err(CollectError::OutOfMemory) => return busy(),
                    Err(e) => {
                        let msg = format!("failed to read the response body: {e:?}");
                        if record {
                            submit(
                                &active,
                                self.new_flow(
                                    flow_id.unwrap_or_default(),
                                    &target,
                                    started,
                                    t0,
                                    req_state,
                                    Some(rparts.status.as_u16()),
                                    Some(head),
                                    None,
                                    false,
                                    Some(msg.clone()),
                                    in_scope,
                                ),
                            );
                        }
                        return text(StatusCode::BAD_GATEWAY, &msg);
                    }
                };
            let mut resp_raw = serialize_response(rversion, rparts.status, &rparts.headers, &rbody);
            let mut original_response = None;
            if let Some(new) = rules.apply_response(&resp_raw, true) {
                original_response = Some(std::mem::replace(&mut resp_raw, new));
            }
            if resp_hold == crate::intercept::RespHold::Yes
                || (resp_hold == crate::intercept::RespHold::IfBody && self.intercept.body_matches(&rbody))
            {
                let id = *flow_id.get_or_insert_with(|| active.project.next_flow_id());
                let held = self
                    .intercept
                    .hold(
                        id,
                        Phase::Response,
                        &req_state.method,
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
                            submit(
                                &active,
                                self.new_flow(
                                    flow_id.unwrap_or_default(),
                                    &target,
                                    started,
                                    t0,
                                    req_state,
                                    status_of(&resp_raw),
                                    Some(resp_raw),
                                    original_response,
                                    false,
                                    Some("response dropped in the intercept queue".into()),
                                    in_scope,
                                ),
                            );
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
            let status = if original_response.is_some() {
                status_of(&resp_raw)
            } else {
                Some(rparts.status.as_u16())
            };
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
                submit(
                    &active,
                    self.new_flow(
                        flow_id.unwrap_or_default(),
                        &target,
                        started,
                        t0,
                        req_state,
                        status,
                        Some(resp_raw),
                        original_response,
                        false,
                        None,
                        in_scope,
                    ),
                );
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
        let status = Some(rparts.status.as_u16());
        let shared = self.clone();
        let tee = TeeBody::new(
            rbody,
            self.live().record_body_limit,
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
                submit(
                    &active,
                    shared.new_flow(
                        flow_id.unwrap_or_default(),
                        &target,
                        started,
                        t0,
                        req_state,
                        status,
                        Some(full_resp),
                        orig,
                        truncated,
                        error,
                        in_scope,
                    ),
                );
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
        request: ReqState,
        status: Option<u16>,
        response: Option<Vec<u8>>,
        original_response: Option<Vec<u8>>,
        truncated: bool,
        error: Option<String>,
        in_scope: bool,
    ) -> Built {
        let ttfb_ms = request.ttfb_ms;
        let (method, path, http_version, request, original_request, pending) = request.finish();
        let flow = NewFlow {
            id,
            source: FlowSource::Proxy,
            started_ms: started,
            duration_ms: Some(t0.elapsed().as_millis() as i64),
            ttfb_ms,
            scheme: target.scheme,
            host: target.host.clone(),
            port: target.port,
            method,
            path,
            http_version,
            status,
            in_scope,
            edited: original_request.is_some() || original_response.is_some(),
            error,
            request,
            original_request,
            response,
            original_response,
            response_truncated: truncated,
        };
        Built { flow, pending }
    }
}

fn status_of(raw: &[u8]) -> Option<u16> {
    RawResponse::parse(raw).ok().map(|r| r.status)
}

/// Map Remote's check: the scope gate decides, as for any tool (an automated source never leaves scope).
fn remote_gate_check(gate: &Gate, to: &RemoteTarget, path: &str) -> Result<(), String> {
    gate.check(FlowSource::Plugin, to.scheme, &to.host, to.port, path)
        .map(|_| ())
        .map_err(|e| e.to_string())
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
    let body_len = p.body.len();
    let mut r = Response::new(full(Bytes::from(p.body)));
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
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(body_len));
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

fn full(b: Bytes) -> RespBody {
    UnsyncBoxBody::new(Full::new(b).map_err(|never: Infallible| match never {}))
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
    let mut r = Response::new(full(Bytes::from(format!("{msg}\n"))));
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
