//! Content and parameter discovery (WP-81): forced browsing of paths and parameter names (see `bosun-discover`).
//!
//! A run is a background job of this run of the server (a few are kept). Every request goes through the Repeater's
//! engine, so the scope gate decides each one first. Only the hits are recorded as flows (source `intruder`), so a
//! wordlist of thousands does not fill the history. Starting and stopping are audited.

use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bosun_crawl::Stop;
use bosun_discover::{Hit, Mode, Options, Report, Sink};
use bosun_http::Exchange;
use bosun_model::{FlowSource, now_ms};
use bosun_store::Role;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::reject;

type R = Result<Response, Response>;

const MAX_RUNNING: usize = 2;
const MAX_KEPT: usize = 8;
const MAX_REQUESTS: u32 = 200_000;
const MAX_WORDS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = DiscoverState)]
pub enum RunState {
    Running,
    /// Every word was tried (or the request limit was reached: see `truncated`).
    Done,
    /// The stop switch, or the gate's kill switch, ended it.
    Stopped,
    /// A refused request or a host that does not answer ended it: see `error`.
    Failed,
}

#[derive(Default)]
struct Inner {
    state: Option<RunState>,
    hits: Vec<Hit>,
    requests: u64,
    error: Option<String>,
    report: Option<Report>,
}

struct Job {
    id: u64,
    base: String,
    mode: Mode,
    created_ms: i64,
    stop: Stop,
    inner: Mutex<Inner>,
}

/// The discovery runs of this run of the server.
#[derive(Default)]
pub struct Runs {
    jobs: Mutex<Vec<Arc<Job>>>,
    next: Mutex<u64>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn state_of(j: &Job) -> RunState {
    lock(&j.inner).state.unwrap_or(RunState::Running)
}

#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = DiscoverStartBody)]
pub struct StartBody {
    /// Paths: the directory to probe (`http://host/app/`). Params: the page whose parameters to find.
    pub base: String,
    /// `paths` (default) or `params`.
    #[serde(default)]
    pub mode: Option<String>,
    /// Names to try (at most 100000). Empty: the built-in list for the mode.
    #[serde(default)]
    pub words: Vec<String>,
    /// Paths: also try each word with these endings, written without the dot (`php`, `bak`).
    #[serde(default)]
    pub extensions: Vec<String>,
    /// Paths: probe the directories found too, down to this depth (0 to 10, default 2).
    #[serde(default)]
    pub max_depth: Option<u32>,
    /// Most requests, the baselines included (10 to 200000, default 5000).
    #[serde(default)]
    pub max_requests: Option<u32>,
    /// Requests in flight at once (1 to 32, default 8).
    #[serde(default)]
    pub concurrency: Option<u32>,
    /// The least time between two request starts, milliseconds (at most 60000).
    #[serde(default)]
    pub delay_ms: Option<u64>,
    /// Params: send the names in a `POST` body instead of the query.
    #[serde(default)]
    pub post: bool,
    /// Extra headers for every request, each `Name: value`.
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub verify_tls: bool,
}

fn options(b: &StartBody) -> Result<Options, Response> {
    let bad = |m: &str| reject(StatusCode::BAD_REQUEST, m);
    let mode = match b.mode.as_deref() {
        None | Some("paths") => Mode::Paths,
        Some("params") => Mode::Params,
        Some(_) => return Err(bad("mode is `paths` or `params`")),
    };
    let mut headers = Vec::new();
    for h in &b.headers {
        let (k, v) = h
            .split_once(':')
            .ok_or_else(|| bad("a header is `Name: value`"))?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    if b.words.len() > MAX_WORDS {
        return Err(bad("at most 100000 words"));
    }
    let d = Options::default();
    let o = Options {
        base: b.base.clone(),
        mode,
        words: b.words.clone(),
        extensions: b.extensions.clone(),
        max_depth: b.max_depth.unwrap_or(d.max_depth),
        max_requests: b.max_requests.unwrap_or(d.max_requests),
        concurrency: b.concurrency.unwrap_or(d.concurrency),
        delay_ms: b.delay_ms.unwrap_or(0).min(60_000),
        post: b.post && mode == Mode::Params,
        headers,
        verify_tls: b.verify_tls,
        ..d
    };
    if o.max_requests > MAX_REQUESTS {
        return Err(bad("max_requests is at most 200000"));
    }
    o.validate().map_err(|e| bad(&e.to_string()))?;
    if bosun_crawl::parse_url(&o.base).is_none() {
        return Err(bad("not a usable URL"));
    }
    Ok(o)
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(as = DiscoverHit)]
pub struct HitOut {
    /// `path` or `param`.
    pub kind: String,
    pub url: String,
    pub word: String,
    pub status: u16,
    pub bytes: usize,
    pub words: usize,
    pub content_type: Option<String>,
    pub location: Option<String>,
    /// Hits with the same answer share a cluster number.
    pub cluster: u32,
    pub depth: u32,
    /// Why it stands out: `directory`, `reflected`, `answer differs`.
    pub note: Option<String>,
}

fn hit_out(h: &Hit) -> HitOut {
    HitOut {
        kind: h.kind.clone(),
        url: h.url.clone(),
        word: h.word.clone(),
        status: h.status,
        bytes: h.bytes,
        words: h.words,
        content_type: h.content_type.clone(),
        location: h.location.clone(),
        cluster: h.cluster,
        depth: h.depth,
        note: h.note.clone(),
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(as = DiscoverInfo)]
pub struct Info {
    pub id: u64,
    pub state: RunState,
    pub base: String,
    /// `paths` or `params`.
    pub mode: String,
    pub created_ms: i64,
    pub requests: u64,
    pub hits: usize,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(as = DiscoverList)]
pub struct List {
    pub runs: Vec<Info>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(as = DiscoverDetail)]
pub struct Detail {
    #[serde(flatten)]
    pub info: Info,
    pub results: Vec<HitOut>,
    /// Directories probed, or the page (params). Filled when the run has ended.
    pub directories: Vec<String>,
    /// Hits left out because they came in a wildcard cluster.
    pub noise: u64,
    /// The request limit ended the run with words left.
    pub truncated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(as = DiscoverStopReply)]
pub struct StopReply {
    /// False when the run was not running.
    pub stopped: bool,
}

fn info(j: &Job) -> Info {
    let g = lock(&j.inner);
    Info {
        id: j.id,
        state: g.state.unwrap_or(RunState::Running),
        base: j.base.clone(),
        mode: if j.mode == Mode::Params { "params" } else { "paths" }.into(),
        created_ms: j.created_ms,
        requests: g.requests,
        hits: g.hits.len(),
        error: g.error.clone(),
    }
}

struct ApiSink {
    st: AppState,
    job: Arc<Job>,
}

impl Sink for ApiSink {
    fn hit(&self, ex: &Exchange, hit: &Hit) {
        let id = self.st.project().next_flow_id();
        self.st
            .inner
            .proxy
            .record(ex.to_new_flow(id, FlowSource::Intruder));
        lock(&self.job.inner).hits.push(hit.clone());
    }

    fn progress(&self, requests: u64, _hits: usize) {
        lock(&self.job.inner).requests = requests;
    }
}

async fn run(st: AppState, job: Arc<Job>, opts: Options) {
    let sink = ApiSink {
        st: st.clone(),
        job: job.clone(),
    };
    let result = bosun_discover::discover(&st.inner.repeater, &opts, &sink, &job.stop).await;
    let mut g = lock(&job.inner);
    match result {
        Ok(r) => {
            g.requests = r.requests;
            g.error = r.error.clone();
            g.state = Some(if r.error.is_some() {
                RunState::Failed
            } else if r.stopped || job.stop.is_stopped() {
                RunState::Stopped
            } else {
                RunState::Done
            });
            g.report = Some(r);
        }
        Err(e) => {
            g.error = Some(e.to_string());
            g.state = Some(RunState::Failed);
        }
    }
}

pub async fn start(State(st): State<AppState>, caller: Caller, Json(b): Json<StartBody>) -> R {
    caller.require(Role::Tester)?;
    let opts = options(&b)?;
    let job = {
        let mut jobs = lock(&st.inner.discoveries.jobs);
        if jobs.iter().filter(|j| state_of(j) == RunState::Running).count() >= MAX_RUNNING {
            return Err(reject(
                StatusCode::TOO_MANY_REQUESTS,
                "two discovery runs are already running: stop one or wait",
            ));
        }
        let id = {
            let mut n = lock(&st.inner.discoveries.next);
            *n += 1;
            *n
        };
        let job = Arc::new(Job {
            id,
            base: opts.base.clone(),
            mode: opts.mode,
            created_ms: now_ms(),
            stop: Stop::new(),
            inner: Mutex::new(Inner::default()),
        });
        jobs.push(job.clone());
        while jobs.len() > MAX_KEPT {
            match jobs.iter().position(|j| state_of(j) != RunState::Running) {
                Some(p) => {
                    jobs.remove(p);
                }
                None => break,
            }
        }
        job
    };
    caller
        .audit(
            &st,
            "discover.start",
            &format!(
                "discovery {}: {} {} ({} words, up to {} requests)",
                job.id,
                if opts.mode == Mode::Params {
                    "parameters of"
                } else {
                    "paths under"
                },
                opts.base,
                if opts.words.is_empty() {
                    "built-in".to_string()
                } else {
                    opts.words.len().to_string()
                },
                opts.max_requests
            ),
        )
        .await;
    let out = info(&job);
    tokio::spawn(run(st.clone(), job, opts));
    Ok(Json(out).into_response())
}

pub async fn list(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let jobs = lock(&st.inner.discoveries.jobs).clone();
    Ok(Json(List {
        runs: jobs.iter().rev().map(|j| info(j)).collect(),
    })
    .into_response())
}

fn find(st: &AppState, id: u64) -> Result<Arc<Job>, Response> {
    lock(&st.inner.discoveries.jobs)
        .iter()
        .find(|j| j.id == id)
        .cloned()
        .ok_or_else(|| reject(StatusCode::NOT_FOUND, "no such discovery run"))
}

pub async fn get(State(st): State<AppState>, caller: Caller, Path(id): Path<u64>) -> R {
    caller.require(Role::Viewer)?;
    let job = find(&st, id)?;
    let (results, directories, noise, truncated) = {
        let g = lock(&job.inner);
        let r = g.report.clone().unwrap_or_default();
        (
            g.hits.iter().map(hit_out).collect(),
            r.directories,
            r.noise,
            r.truncated,
        )
    };
    Ok(Json(Detail {
        info: info(&job),
        results,
        directories,
        noise,
        truncated,
    })
    .into_response())
}

pub async fn stop(State(st): State<AppState>, caller: Caller, Path(id): Path<u64>) -> R {
    caller.require(Role::Tester)?;
    let job = find(&st, id)?;
    let running = state_of(&job) == RunState::Running;
    if running {
        job.stop.stop();
        caller
            .audit(&st, "discover.stop", &format!("discovery {id}"))
            .await;
    }
    Ok(Json(StopReply { stopped: running }).into_response())
}
