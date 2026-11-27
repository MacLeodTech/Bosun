//! The active scan engine.
//!
//! A scan takes a list of [`Target`]s (requests the user or the crawler found), finds the **insertion points** in
//! each (query, form and JSON body values, cookies, headers, the last path segment) and runs the enabled checks
//! on every point. The units of work (one target and one point) go through a queue with a fixed number in flight;
//! the scan can be paused, resumed and stopped, and the sink sees progress as it goes.
//!
//! Safety rules, all enforced here and not left to the caller:
//! - every request is sent by [`bosun_http::Engine::send`], which calls [`bosun_scope::Gate::check`] first: a target
//!   outside the scope is never contacted (it is listed in [`Report::refused`]), the kill switch ends the scan, and
//!   the gate's per-host rate limit applies on top of the scan's own delay;
//! - the number of requests is capped by [`Options::max_requests`];
//! - checks only read answers; the built-in ones send nothing destructive (a quote, a marker, a sleep, an
//!   arithmetic expression). The ones that save data in the application ([`DESTRUCTIVE`]) are off unless named.
//!
//! The checks here are Rust checks ([`CHECKS`]). Active checks written in the check language arrive with the next
//! package.

mod checks;
mod extra;
mod points;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bosun_http::{Engine, Exchange, SendError, SendOptions};
use bosun_model::{FlowSource, RawResponse, Target as Origin};
use bosun_scope::ScopeError;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

pub use points::{Point, Req};

/// The checks this engine has: `(id, what it looks for)`.
pub const CHECKS: &[(&str, &str)] = &[
    (
        checks::SQLI_ERROR,
        "SQL injection, error based: a quote makes the database complain and a doubled quote does not",
    ),
    (
        checks::XSS_REFLECTED,
        "Reflected cross-site scripting: a marker with HTML metacharacters comes back unescaped in an HTML page",
    ),
    (
        checks::SQLI_BOOLEAN,
        "SQL injection, boolean blind: an always-true condition leaves the page as it was and an always-false one changes it, every time",
    ),
    (
        checks::SQLI_TIME,
        "SQL injection, time based: a sleep in the injected condition delays the answer, a sleep of zero does not",
    ),
    (
        checks::XSS_STORED,
        "Stored cross-site scripting (destructive: saves a marker in the application): a marker sent in one request comes back unescaped when the page is read again without it",
    ),
    (
        checks::SSTI,
        "Server-side template injection: an arithmetic expression in template syntax is evaluated and its result comes back",
    ),
    (
        checks::CMD_INJECTION,
        "OS command injection: an injected command's output (a computed number) comes back, or an injected sleep delays the answer",
    ),
    (
        checks::PATH_TRAVERSAL,
        "Path traversal and local file inclusion: dot-dot sequences make the application return a well-known system file",
    ),
    (
        checks::OPEN_REDIRECT,
        "Open redirect: a value naming another host is returned as the target of a redirect",
    ),
    (
        checks::CRLF_INJECTION,
        "CRLF and header injection: a line break in a value starts a new response header",
    ),
    (
        checks::CORS,
        "CORS misconfiguration: an arbitrary or null Origin is allowed together with credentials",
    ),
    (
        checks::HOST_HEADER,
        "Host header attack: a Host or X-Forwarded-Host of the scanner's choosing comes back in links or redirects",
    ),
    (
        checks::XXE,
        "XML external entities: an XML body with an external entity makes the parser return a system file or an entity-loading error (in band, no out-of-band channel)",
    ),
    (
        checks::FILE_UPLOAD,
        "Unrestricted file upload (destructive: uploads a file): a multipart upload named with a script extension is accepted and its name confirmed",
    ),
    (
        checks::JWT,
        "JWT attacks: a token signed with a weak secret, accepted with `alg: none`, or accepted with a changed signature",
    ),
    (
        checks::DESERIALIZATION,
        "Deserialization indicators: serialized-object probes make the application answer a Java, PHP, .NET or Python deserialization error",
    ),
    (
        checks::PROTOTYPE_POLLUTION,
        "Server-side prototype pollution: a JSON `__proto__` property shows up in later answers of the same request",
    ),
    (
        checks::GRAPHQL,
        "GraphQL issues: introspection enabled, field suggestions in errors, query batching and unlimited aliases",
    ),
    (
        checks::SESSION,
        "Session weaknesses: a session cookie without HttpOnly, Secure or SameSite, and a session id chosen by the client that the server adopts",
    ),
    (
        checks::TLS,
        "TLS configuration: TLS 1.1 or older, RC4, 3DES, NULL or export suites accepted, an expired or self-signed certificate",
    ),
];

/// Checks that change state in the application (they save data), off unless named in [`Options::checks`].
pub const DESTRUCTIVE: &[&str] = &[checks::XSS_STORED, checks::FILE_UPLOAD];

pub fn is_destructive(id: &str) -> bool {
    DESTRUCTIVE.contains(&id)
}

const RATE_WAIT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("{0}")]
    BadOption(String),
    #[error("not a usable target: {0}")]
    BadTarget(String),
}

/// How hard a scan tries: more strength sends more requests and tests more insertion points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    /// Query, form and JSON values; one probe per check.
    Low,
    /// Adds cookies and the last path segment; more probes.
    #[default]
    Medium,
    /// Adds the `User-Agent` and `Referer` headers.
    High,
}

#[derive(Debug, Clone)]
pub struct Options {
    /// Ids from [`CHECKS`]; empty runs all of them except the [`DESTRUCTIVE`] ones, which run only when named.
    pub checks: Vec<String>,
    pub strength: Strength,
    /// Units of work in flight at once (1 to 32).
    pub concurrency: u32,
    /// The least time between two request starts in one unit, milliseconds.
    pub delay_ms: u64,
    /// The most requests the scan may send (1 to 1000000).
    pub max_requests: u64,
    /// Extra headers for every request, merged under the target's own.
    pub headers: Vec<(String, String)>,
    pub verify_tls: bool,
    pub timeout_secs: u64,
    pub max_body: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            checks: Vec::new(),
            strength: Strength::Medium,
            concurrency: 4,
            delay_ms: 0,
            max_requests: 5_000,
            headers: Vec::new(),
            verify_tls: false,
            timeout_secs: 20,
            max_body: 2 << 20,
        }
    }
}

impl Options {
    pub fn validate(&self) -> Result<(), ScanError> {
        let bad = |m: &str| Err(ScanError::BadOption(m.to_string()));
        if !(1..=32).contains(&self.concurrency) {
            return bad("concurrency is 1 to 32");
        }
        if !(1..=1_000_000).contains(&self.max_requests) {
            return bad("max_requests is 1 to 1000000");
        }
        if !(1..=300).contains(&self.timeout_secs) {
            return bad("timeout_secs is 1 to 300");
        }
        if let Some(c) = self.checks.iter().find(|c| !CHECKS.iter().any(|(id, _)| id == c)) {
            return Err(ScanError::BadOption(format!("no such check: {c}")));
        }
        if self.headers.iter().any(|(k, v)| !points::clean_header(k, v)) {
            return bad("headers must be `Name: value` on a single line");
        }
        Ok(())
    }

    fn enabled(&self, id: &str) -> bool {
        if self.checks.is_empty() {
            !is_destructive(id)
        } else {
            self.checks.iter().any(|c| c == id)
        }
    }
}

/// A request to test, as the API takes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    #[serde(default)]
    pub method: Option<String>,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Option<String>,
    /// `application/x-www-form-urlencoded` (the default with a body) or `application/json`; other bodies are sent
    /// but their values are not insertion points yet.
    #[serde(default)]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

/// One weakness a check proved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub check: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// The tested URL, without the payload.
    pub url: String,
    /// Which insertion point, e.g. `query:q`.
    pub point: String,
    pub payload: String,
    pub detail: String,
    pub remediation: String,
    pub cwe: Vec<u32>,
    /// The flow that shows it (what [`Sink::exchange`] returned for the proving request).
    pub flow_id: i64,
}

/// Where a scan's exchanges, findings and progress go. All methods have empty defaults.
pub trait Sink: Send + Sync {
    /// Record an exchange (the API stores it as a flow with source `scanner`); returns the flow id.
    fn exchange(&self, _ex: &Exchange) -> i64 {
        0
    }
    fn finding(&self, _f: &Finding) {}
    /// Units finished so far, of `total`, and requests sent.
    fn progress(&self, _done: usize, _total: usize, _requests: u64) {}
}

impl Sink for () {}

#[derive(Debug, Default)]
struct Flags {
    stop: AtomicBool,
    pause: AtomicBool,
}

/// The pause and stop switches of one scan. Cheap to clone; clones share the switches.
#[derive(Debug, Clone, Default)]
pub struct Control(Arc<Flags>);

impl Control {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn stop(&self) {
        self.0.stop.store(true, Ordering::SeqCst);
    }
    pub fn is_stopped(&self) -> bool {
        self.0.stop.load(Ordering::SeqCst)
    }
    /// No request starts until [`Control::resume`]; requests in flight finish.
    pub fn pause(&self) {
        self.0.pause.store(true, Ordering::SeqCst);
    }
    pub fn resume(&self) {
        self.0.pause.store(false, Ordering::SeqCst);
    }
    pub fn is_paused(&self) -> bool {
        self.0.pause.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub requests: u64,
    /// Units (a target and one insertion point) planned and finished.
    pub units_total: usize,
    pub units_done: usize,
    /// Targets the gate refused (outside the scope): listed, never contacted.
    pub refused: Vec<String>,
    /// The request cap ended the scan with work left.
    pub truncated: bool,
    pub stopped: bool,
    /// Sign-ins the session handling did, and why it stopped signing in (when it did).
    pub sign_ins: u32,
    pub session_error: Option<String>,
}

/// State shared by the units of one scan.
pub(crate) struct Shared {
    engine: Engine,
    opts: Options,
    sink: Arc<dyn Sink>,
    ctl: Control,
    requests: AtomicU64,
    marker: AtomicU64,
    capped: AtomicBool,
    refused: Mutex<HashSet<String>>,
    findings: Mutex<Vec<Finding>>,
    /// `host:port` of the https targets the TLS check has been run for.
    tls_done: Mutex<HashSet<String>>,
    /// Signs in and keeps the scan logged in, when the scan has a login macro.
    session: Option<Arc<bosun_auth::Session>>,
    session_error: Mutex<Option<String>>,
}

/// A response, parsed far enough for checks.
pub(crate) struct Answer {
    pub status: u16,
    /// Header names lowercased, values as text.
    pub headers: Vec<(String, String)>,
    pub elapsed: Duration,
    pub content_type: String,
    pub body: String,
    pub flow_id: i64,
    pub tls: Option<bosun_http::TlsInfo>,
}

impl Shared {
    /// A marker nobody else sends: `bsn` and 10 hex digits.
    pub(crate) fn marker(&self) -> String {
        let n = self.marker.fetch_add(1, Ordering::SeqCst);
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        format!(
            "bsn{:010x}",
            (t ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15)) & 0xff_ffff_ffff
        )
    }

    pub(crate) fn report(&self, f: Finding) {
        self.sink.finding(&f);
        let mut g = self
            .findings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.push(f);
    }

    /// Whether this scan has not yet looked at the TLS of `host:port`; remembers that it now has.
    pub(crate) fn first_tls(&self, req: &Req) -> bool {
        self.tls_done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(format!("{}:{}", req.host, req.port))
    }

    /// Send raw bytes (a TLS hello) to the target's address and read one record of the answer (at most `max`
    /// bytes). Goes through the gate like [`Shared::send`] and counts as a request. `None` when it was refused,
    /// capped or did not answer.
    pub(crate) async fn probe(&self, req: &Req, hello: &[u8], max: usize) -> Option<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let started = Instant::now();
        let pinned = loop {
            while self.ctl.is_paused() && !self.ctl.is_stopped() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            if self.ctl.is_stopped() {
                return None;
            }
            if self.requests.fetch_add(1, Ordering::SeqCst) >= self.opts.max_requests {
                self.requests.fetch_sub(1, Ordering::SeqCst);
                self.capped.store(true, Ordering::SeqCst);
                return None;
            }
            let gate = self.engine.gate().clone();
            let (scheme, host, port) = (req.scheme, req.host.clone(), req.port);
            let checked = tokio::task::spawn_blocking(move || {
                gate.check(FlowSource::Scanner, scheme, &host, port, "/")
            })
            .await
            .ok()?;
            match checked {
                Ok(p) => break p,
                Err(ScopeError::RateLimited(..)) => {
                    self.requests.fetch_sub(1, Ordering::SeqCst);
                    if started.elapsed() > RATE_WAIT {
                        return None;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(ScopeError::Stopped) => {
                    self.ctl.stop();
                    return None;
                }
                Err(_) => {
                    self.requests.fetch_sub(1, Ordering::SeqCst);
                    self.refused
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(req.base_url());
                    return None;
                }
            }
        };
        let wait = Duration::from_secs(self.opts.timeout_secs.min(8));
        let mut s = tokio::time::timeout(wait, tokio::net::TcpStream::connect(pinned.addrs.first()?))
            .await
            .ok()?
            .ok()?;
        s.write_all(hello).await.ok()?;
        let mut got = Vec::new();
        let mut buf = [0u8; 2048];
        while got.len() < max {
            match tokio::time::timeout(wait, s.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => got.extend_from_slice(&buf[..n]),
                _ => break,
            }
            if got.len() >= 5 && got.len() >= 5 + usize::from(u16::from_be_bytes([got[3], got[4]])) {
                break;
            }
        }
        Some(got)
    }

    /// Send one request. `None` when the scan must not go on with this request: stopped, over the request cap, or
    /// the gate refused it. Waits while paused.
    pub(crate) async fn send(&self, req: &Req, raw: Vec<u8>) -> Option<Answer> {
        self.send_with(req, raw, self.opts.verify_tls).await
    }

    /// [`Shared::send`] with the certificate check chosen by the caller (the TLS check must complete a handshake
    /// with a bad certificate to read it).
    pub(crate) async fn send_with(&self, req: &Req, raw: Vec<u8>, verify_tls: bool) -> Option<Answer> {
        let Some(session) = &self.session else {
            return self.send_once(req, raw, verify_tls).await;
        };
        let (headers, generation) = match session.headers().await {
            Ok(h) => h,
            Err(e) => return self.session_failed(e),
        };
        let a = self
            .send_once(req, bosun_auth::with_identity(&raw, &headers), verify_tls)
            .await?;
        if !session.expiry.expired(a.status, &a.headers, &a.body) {
            return Some(a);
        }
        // The session ended: sign in again (once, however many units noticed) and send this request once more.
        if let Err(e) = session.refresh(generation).await {
            return self.session_failed(e);
        }
        let (headers, _) = session.headers().await.ok()?;
        self.send_once(req, bosun_auth::with_identity(&raw, &headers), verify_tls)
            .await
    }

    fn session_failed(&self, e: bosun_auth::SessionError) -> Option<Answer> {
        *self
            .session_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(e.to_string());
        self.ctl.stop();
        None
    }

    async fn send_once(&self, req: &Req, raw: Vec<u8>, verify_tls: bool) -> Option<Answer> {
        let send = SendOptions {
            source: FlowSource::Scanner,
            update_content_length: true,
            verify_tls,
            connect_timeout: Duration::from_secs(self.opts.timeout_secs.min(15)),
            idle_timeout: Duration::from_secs(self.opts.timeout_secs),
            total_timeout: Duration::from_secs(self.opts.timeout_secs),
            max_response: self.opts.max_body,
            reuse: false,
        };
        let target = Origin::new(req.scheme, &req.host, req.port);
        let started = Instant::now();
        loop {
            while self.ctl.is_paused() && !self.ctl.is_stopped() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            if self.ctl.is_stopped() {
                return None;
            }
            if self.requests.fetch_add(1, Ordering::SeqCst) >= self.opts.max_requests {
                self.requests.fetch_sub(1, Ordering::SeqCst);
                self.capped.store(true, Ordering::SeqCst);
                return None;
            }
            if self.opts.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.opts.delay_ms)).await;
            }
            let sent_at = Instant::now();
            match self.engine.send(&target, &raw, &send).await {
                Ok(ex) => {
                    let flow_id = self.sink.exchange(&ex);
                    let r = RawResponse::parse(&ex.response).ok()?;
                    let chunked = r
                        .header("transfer-encoding")
                        .is_some_and(|v| v.to_ascii_lowercase().windows(7).any(|w| w == b"chunked"));
                    let bytes = if chunked {
                        bosun_crawl::dechunk(&r.body).unwrap_or_default()
                    } else {
                        r.body.clone()
                    };
                    return Some(Answer {
                        status: ex.status.unwrap_or(0),
                        headers: r
                            .headers
                            .iter()
                            .map(|(k, v)| (k.to_ascii_lowercase(), String::from_utf8_lossy(v).into_owned()))
                            .collect(),
                        elapsed: sent_at.elapsed(),
                        content_type: r
                            .header("content-type")
                            .map_or(String::new(), |v| String::from_utf8_lossy(v).to_ascii_lowercase()),
                        body: String::from_utf8_lossy(&bytes).into_owned(),
                        flow_id,
                        tls: ex.tls.clone(),
                    });
                }
                Err(SendError::Refused(ScopeError::RateLimited(..))) => {
                    self.requests.fetch_sub(1, Ordering::SeqCst);
                    if started.elapsed() > RATE_WAIT {
                        return None;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(SendError::Refused(ScopeError::Stopped)) => {
                    self.ctl.stop();
                    return None;
                }
                Err(SendError::Refused(_)) => {
                    // Not counted: nothing was sent.
                    self.requests.fetch_sub(1, Ordering::SeqCst);
                    self.refused
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(req.base_url());
                    return None;
                }
                // A connect or timeout failure counts as a request and gives no answer.
                Err(_) => return None,
            }
        }
    }
}

/// Run a scan. Targets are scanned in order; the report lists the findings, the counts and the refused targets.
pub async fn scan(
    engine: &Engine,
    opts: &Options,
    targets: &[Target],
    sink: Arc<dyn Sink>,
    ctl: &Control,
) -> Result<Report, ScanError> {
    scan_with_session(engine, opts, targets, sink, ctl, None).await
}

/// [`scan`] kept signed in: every request carries the session's headers, and an answer that means the session
/// ended makes the scan sign in again and repeat the request. If signing in fails, the scan stops and the report
/// says why.
pub async fn scan_with_session(
    engine: &Engine,
    opts: &Options,
    targets: &[Target],
    sink: Arc<dyn Sink>,
    ctl: &Control,
    session: Option<Arc<bosun_auth::Session>>,
) -> Result<Report, ScanError> {
    opts.validate()?;
    if targets.is_empty() {
        return Err(ScanError::BadOption("give at least one target".into()));
    }
    let mut units: Vec<(Arc<Req>, Point)> = Vec::new();
    for t in targets {
        let req = Arc::new(Req::from_target(t, &opts.headers)?);
        for p in req.points(opts.strength) {
            units.push((req.clone(), p));
        }
        units.push((req.clone(), Point::Whole));
    }
    let total = units.len();
    let shared = Arc::new(Shared {
        engine: engine.clone(),
        opts: opts.clone(),
        sink: sink.clone(),
        ctl: ctl.clone(),
        requests: AtomicU64::new(0),
        marker: AtomicU64::new(0),
        capped: AtomicBool::new(false),
        refused: Mutex::default(),
        findings: Mutex::default(),
        tls_done: Mutex::default(),
        session,
        session_error: Mutex::default(),
    });
    let mut queue = units.into_iter();
    let mut running: JoinSet<()> = JoinSet::new();
    let mut done = 0usize;
    loop {
        while running.len() < opts.concurrency as usize
            && !ctl.is_stopped()
            && !shared.capped.load(Ordering::SeqCst)
        {
            // Paused: start nothing new until resumed (units in flight wait inside `send`).
            if ctl.is_paused() {
                break;
            }
            let Some((req, point)) = queue.next() else { break };
            let sh = shared.clone();
            running.spawn(async move { checks::run(&sh, &req, &point).await });
        }
        if running.is_empty() {
            if ctl.is_paused() && !ctl.is_stopped() {
                tokio::time::sleep(Duration::from_millis(25)).await;
                continue;
            }
            break;
        }
        if running.join_next().await.is_some() {
            done += 1;
            sink.progress(done, total, shared.requests.load(Ordering::SeqCst));
        }
    }
    let mut refused: Vec<String> = shared
        .refused
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .cloned()
        .collect();
    refused.sort();
    let findings = shared
        .findings
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Ok(Report {
        findings,
        requests: shared.requests.load(Ordering::SeqCst),
        units_total: total,
        units_done: done,
        refused,
        truncated: shared.capped.load(Ordering::SeqCst) && done < total,
        stopped: ctl.is_stopped(),
        sign_ins: shared.session.as_ref().map_or(0, |s| s.sign_ins()),
        session_error: shared
            .session_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    })
}
