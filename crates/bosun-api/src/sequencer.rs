//! The Sequencer: collect tokens (by hand, or by sending a request over and over and pulling the token out of each
//! response) and analyse how random they are (see `bosun-sequencer`).
//!
//! A live capture is a background job. Every request goes through the Repeater's engine, so the scope gate (scope,
//! kill switch, per-host rate limit) decides each one, and each is recorded as a flow with source `repeater`.
//! The number of requests is capped, there are few jobs at once, and a stop switch ends a job after the request
//! in flight. The analysis itself is pure computation and needs only the viewer role.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bosun_http::{SendError, SendOptions};
use bosun_model::{FlowSource, Scheme, Target};
use bosun_scope::ScopeError;
use bosun_sequencer::{Analysis, Extractor, TokenSource};
use bosun_store::Role;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::reject;

type R = Result<Response, Response>;

/// The most requests one capture sends.
pub const MAX_CAPTURE: u32 = 5000;
/// The longest pause between requests.
const MAX_DELAY_MS: u64 = 10_000;
const MAX_REQUEST: usize = 1 << 20;
/// Captures that may run at once, and captures kept (finished ones are dropped oldest first).
const MAX_RUNNING: usize = 2;
const MAX_KEPT: usize = 8;
/// A rate-limit refusal is waited out (a second at a time) this many times in a row before the capture gives up.
const MAX_RATE_WAITS: u32 = 60;
/// This many failed requests in a row end the capture.
const MAX_ERRORS_IN_A_ROW: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    Running,
    /// All requested tokens were asked for.
    Done,
    /// The stop switch ended it.
    Stopped,
    /// The gate refused (scope, kill switch, rate limit that did not clear) or the server kept failing.
    Failed,
}

#[derive(Default)]
struct Progress {
    sent: u32,
    missing: u32,
    errors: u32,
    last_error: Option<String>,
    tokens: Vec<String>,
}

struct Job {
    id: u64,
    target: String,
    count: u32,
    stop: AtomicBool,
    state: Mutex<(CaptureState, Progress)>,
}

/// The captures of this run of the server.
#[derive(Default)]
pub struct Captures {
    jobs: Mutex<Vec<Arc<Job>>>,
    next: Mutex<u64>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CaptureBody {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// The request to send each time, as written, base64 (up to 1 MiB).
    pub request: String,
    /// Where the token is in each response.
    pub source: TokenSource,
    /// How many requests to send (1 to 5000).
    pub count: u32,
    /// Pause between requests, milliseconds (0 to 10000).
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub update_content_length: bool,
    #[serde(default)]
    pub verify_tls: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CaptureStarted {
    pub id: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CaptureStatus {
    pub id: u64,
    pub state: CaptureState,
    /// `scheme://host:port` the capture sends to.
    pub target: String,
    /// Requests asked for.
    pub count: u32,
    /// Requests sent so far.
    pub sent: u32,
    /// Tokens extracted so far.
    pub extracted: usize,
    /// Responses that had no token.
    pub missing: u32,
    /// Requests that failed.
    pub errors: u32,
    pub last_error: Option<String>,
    /// The tokens from index `from` on.
    pub tokens: Vec<String>,
    pub from: usize,
}

#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    #[serde(default)]
    pub from: usize,
}

fn status_of(j: &Job, from: usize) -> CaptureStatus {
    let g = lock(&j.state);
    CaptureStatus {
        id: j.id,
        state: g.0,
        target: j.target.clone(),
        count: j.count,
        sent: g.1.sent,
        extracted: g.1.tokens.len(),
        missing: g.1.missing,
        errors: g.1.errors,
        last_error: g.1.last_error.clone(),
        tokens: g.1.tokens.iter().skip(from).cloned().collect(),
        from,
    }
}

fn finish(j: &Job, state: CaptureState, why: Option<String>) {
    let mut g = lock(&j.state);
    g.0 = state;
    if why.is_some() {
        g.1.last_error = why;
    }
}

async fn run(
    st: AppState,
    job: Arc<Job>,
    target: Target,
    raw: Vec<u8>,
    ex: Extractor,
    opts: SendOptions,
    delay: Duration,
) {
    let mut waits = 0u32;
    let mut in_a_row = 0u32;
    let mut i = 0u32;
    while i < job.count {
        if job.stop.load(Ordering::SeqCst) {
            return finish(&job, CaptureState::Stopped, None);
        }
        match st.inner.repeater.send(&target, &raw, &opts).await {
            Ok(x) => {
                waits = 0;
                in_a_row = 0;
                let id = st.project().next_flow_id();
                st.inner.proxy.record(x.to_new_flow(id, FlowSource::Repeater));
                let token = ex.extract(&x.response).filter(|t| !t.is_empty());
                let mut g = lock(&job.state);
                g.1.sent += 1;
                match token {
                    Some(t) => g.1.tokens.push(t),
                    None => g.1.missing += 1,
                }
                if let Some(e) = &x.error {
                    g.1.errors += 1;
                    g.1.last_error = Some(e.clone());
                }
            }
            // The gate's rate limit: wait for the next second and ask again.
            Err(SendError::Refused(ScopeError::RateLimited(..))) if waits < MAX_RATE_WAITS => {
                waits += 1;
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            // Anything else the gate says will not change by asking again.
            Err(SendError::Refused(e)) => return finish(&job, CaptureState::Failed, Some(e.to_string())),
            Err(e) => {
                in_a_row += 1;
                let mut g = lock(&job.state);
                g.1.sent += 1;
                g.1.errors += 1;
                g.1.last_error = Some(e.to_string());
                drop(g);
                if in_a_row >= MAX_ERRORS_IN_A_ROW {
                    return finish(
                        &job,
                        CaptureState::Failed,
                        Some(format!("{e} ({MAX_ERRORS_IN_A_ROW} failures in a row)")),
                    );
                }
            }
        }
        i += 1;
        if i < job.count && !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
    finish(&job, CaptureState::Done, None);
}

pub async fn start_capture(State(st): State<AppState>, caller: Caller, Json(b): Json<CaptureBody>) -> R {
    caller.require(Role::Tester)?;
    if b.count == 0 || b.count > MAX_CAPTURE {
        return Err(reject(StatusCode::BAD_REQUEST, "count must be 1 to 5000"));
    }
    if b.delay_ms > MAX_DELAY_MS {
        return Err(reject(StatusCode::BAD_REQUEST, "the delay is at most 10000 ms"));
    }
    if b.host.is_empty() || b.host.len() > 255 || b.port == 0 {
        return Err(reject(StatusCode::BAD_REQUEST, "that target is not valid"));
    }
    if b.request.len() / 4 * 3 > MAX_REQUEST + 3 {
        return Err(reject(StatusCode::PAYLOAD_TOO_LARGE, "the request is over 1 MiB"));
    }
    let raw = B64
        .decode(b.request.as_bytes())
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "the request is not valid base64"))?;
    if raw.is_empty() || raw.len() > MAX_REQUEST {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "the request is empty or over 1 MiB",
        ));
    }
    let ex = Extractor::new(&b.source).map_err(|e| reject(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let target = Target::new(b.scheme, b.host.clone(), b.port);
    let opts = SendOptions {
        source: FlowSource::Repeater,
        update_content_length: b.update_content_length,
        verify_tls: b.verify_tls,
        ..SendOptions::default()
    };
    let label = format!("{}://{}:{}", b.scheme.as_str(), b.host, b.port);
    let job = {
        let mut jobs = lock(&st.inner.captures.jobs);
        let running = jobs
            .iter()
            .filter(|j| lock(&j.state).0 == CaptureState::Running)
            .count();
        if running >= MAX_RUNNING {
            return Err(reject(
                StatusCode::TOO_MANY_REQUESTS,
                "two captures are already running: stop one or wait",
            ));
        }
        let id = {
            let mut n = lock(&st.inner.captures.next);
            *n += 1;
            *n
        };
        let job = Arc::new(Job {
            id,
            target: label.clone(),
            count: b.count,
            stop: AtomicBool::new(false),
            state: Mutex::new((CaptureState::Running, Progress::default())),
        });
        jobs.push(job.clone());
        // Keep the newest few: drop the oldest finished ones.
        while jobs.len() > MAX_KEPT {
            match jobs
                .iter()
                .position(|j| lock(&j.state).0 != CaptureState::Running)
            {
                Some(p) => {
                    jobs.remove(p);
                }
                None => break,
            }
        }
        job
    };
    caller
        .audit(&st, "sequencer.capture", &format!("{label} x{}", b.count))
        .await;
    let id = job.id;
    tokio::spawn(run(
        st.clone(),
        job,
        target,
        raw,
        ex,
        opts,
        Duration::from_millis(b.delay_ms),
    ));
    Ok((StatusCode::ACCEPTED, Json(CaptureStarted { id })).into_response())
}

fn find(st: &AppState, id: u64) -> Result<Arc<Job>, Response> {
    lock(&st.inner.captures.jobs)
        .iter()
        .find(|j| j.id == id)
        .cloned()
        .ok_or_else(|| reject(StatusCode::NOT_FOUND, "no such capture"))
}

pub async fn capture_status(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<u64>,
    Query(q): Query<StatusQuery>,
) -> R {
    caller.require(Role::Viewer)?;
    let job = find(&st, id)?;
    Ok(Json(status_of(&job, q.from)).into_response())
}

pub async fn stop_capture(State(st): State<AppState>, caller: Caller, Path(id): Path<u64>) -> R {
    caller.require(Role::Tester)?;
    let job = find(&st, id)?;
    job.stop.store(true, Ordering::SeqCst);
    caller
        .audit(&st, "sequencer.stop", &format!("capture {id}"))
        .await;
    Ok(Json(status_of(&job, usize::MAX)).into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AnalyzeBody {
    /// The tokens, one string each (20 to 10000, each up to 1024 characters).
    pub tokens: Vec<String>,
}

pub async fn analyze(caller: Caller, Json(b): Json<AnalyzeBody>) -> R {
    caller.require(Role::Viewer)?;
    let r: Result<Analysis, bosun_sequencer::Error> =
        tokio::task::spawn_blocking(move || bosun_sequencer::analyze(&b.tokens))
            .await
            .map_err(|_| reject(StatusCode::INTERNAL_SERVER_ERROR, "the analysis failed"))?;
    match r {
        Ok(a) => Ok(Json(a).into_response()),
        Err(e) => Err(reject(StatusCode::BAD_REQUEST, &e.to_string())),
    }
}
