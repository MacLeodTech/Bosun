//! The spider: crawl from start URLs, following links, forms, `robots.txt` and sitemaps (see `bosun-crawl`).
//!
//! A crawl is a background job of this run of the server (a few are kept, finished ones are dropped oldest first).
//! Every request goes through the Repeater's engine, so the scope gate (scope, kill switch, per-host rate limit)
//! decides each one first: a link outside the scope is listed, never requested. Each exchange is recorded as a flow
//! with source `crawler`, so the pages show up in the history and the site map. `POST` forms are sent only when
//! the request asks for it. Starting and stopping are audited.

use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bosun_crawl::{Options, Page, Report, Sink, Stop};
use bosun_http::Exchange;
use bosun_model::{FlowSource, now_ms};
use bosun_store::Role;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::reject;

type R = Result<Response, Response>;

/// Crawls that may run at once, and crawls kept.
const MAX_RUNNING: usize = 2;
const MAX_KEPT: usize = 8;
/// The most pages one crawl may ask for.
const MAX_PAGES: u32 = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CrawlState {
    Running,
    /// The queue ran dry (or the page limit was reached: see `truncated`).
    Done,
    /// The stop switch, or the gate's kill switch, ended it.
    Stopped,
    Failed,
}

#[derive(Default)]
struct Inner {
    state: Option<CrawlState>,
    pages: Vec<Page>,
    requests: u64,
    error: Option<String>,
    report: Option<Report>,
}

struct Job {
    id: u64,
    start: Vec<String>,
    created_ms: i64,
    stop: Stop,
    inner: Mutex<Inner>,
}

/// The crawls of this run of the server.
#[derive(Default)]
pub struct Crawls {
    jobs: Mutex<Vec<Arc<Job>>>,
    next: Mutex<u64>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn state_of(j: &Job) -> CrawlState {
    lock(&j.inner).state.unwrap_or(CrawlState::Running)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CrawlStartBody {
    /// Where to begin: absolute `http` or `https` URLs (at least one).
    pub start: Vec<String>,
    /// Links followed from a start URL (0 to 100, default 5).
    #[serde(default)]
    pub max_depth: Option<u32>,
    /// Most page requests (1 to 20000, default 1000).
    #[serde(default)]
    pub max_pages: Option<u32>,
    /// Requests in flight at once (1 to 32, default 5).
    #[serde(default)]
    pub concurrency: Option<u32>,
    /// The least time between two request starts, milliseconds (at most 60000).
    #[serde(default)]
    pub delay_ms: Option<u64>,
    /// Do not fetch what `robots.txt` disallows (default true).
    #[serde(default)]
    pub respect_robots: Option<bool>,
    /// Read sitemaps and queue what they list (default true).
    #[serde(default)]
    pub use_sitemap: Option<bool>,
    /// Follow `script`, `img` and similar sources too (default true).
    #[serde(default)]
    pub follow_resources: Option<bool>,
    /// Send `GET` forms with the values the page gives them (default true).
    #[serde(default)]
    pub submit_get_forms: Option<bool>,
    /// Send `POST` forms with their default values. Off by default: a form can change data.
    #[serde(default)]
    pub submit_post_forms: bool,
    /// Extra headers for every request, each `Name: value`.
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub verify_tls: bool,
}

fn options(b: &CrawlStartBody) -> Result<Options, Response> {
    let bad = |m: &str| reject(StatusCode::BAD_REQUEST, m);
    let mut headers = Vec::new();
    for h in &b.headers {
        let (k, v) = h.split_once(':').ok_or_else(|| bad("a header is `Name: value`"))?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    let d = Options::default();
    let o = Options {
        start: b.start.clone(),
        max_depth: b.max_depth.unwrap_or(d.max_depth),
        max_pages: b.max_pages.unwrap_or(d.max_pages),
        concurrency: b.concurrency.unwrap_or(d.concurrency),
        delay_ms: b.delay_ms.unwrap_or(d.delay_ms).min(60_000),
        respect_robots: b.respect_robots.unwrap_or(d.respect_robots),
        use_sitemap: b.use_sitemap.unwrap_or(d.use_sitemap),
        follow_resources: b.follow_resources.unwrap_or(d.follow_resources),
        submit_get_forms: b.submit_get_forms.unwrap_or(d.submit_get_forms),
        submit_post_forms: b.submit_post_forms,
        headers,
        verify_tls: b.verify_tls,
        ..d
    };
    if o.max_pages > MAX_PAGES {
        return Err(bad("max_pages is at most 20000"));
    }
    o.validate().map_err(|e| bad(&e.to_string()))?;
    for s in &o.start {
        if bosun_crawl::parse_url(s).is_none() {
            return Err(bad(&format!("not a usable start URL: {s}")));
        }
    }
    Ok(o)
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CrawlPage {
    pub url: String,
    pub method: String,
    pub depth: u32,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub bytes: usize,
    pub title: Option<String>,
    /// The page that led here.
    pub found_on: Option<String>,
    /// Where a redirect pointed.
    pub location: Option<String>,
    /// Why there is no answer, or why it is partial.
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CrawlField {
    pub name: String,
    pub value: String,
    pub kind: String,
    pub submitted: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CrawlForm {
    pub page: String,
    pub action: String,
    pub method: String,
    pub enctype: String,
    pub fields: Vec<CrawlField>,
}

/// The engine's types and these mirror each other field for field.
fn conv<A: Serialize, B: serde::de::DeserializeOwned>(a: &A) -> Option<B> {
    serde_json::from_value(serde_json::to_value(a).ok()?).ok()
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CrawlInfo {
    pub id: u64,
    pub state: CrawlState,
    pub start: Vec<String>,
    pub created_ms: i64,
    /// Pages the crawl has finished with so far.
    pub pages: usize,
    /// Requests sent, robots and sitemaps included.
    pub requests: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CrawlList {
    pub crawls: Vec<CrawlInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CrawlDetail {
    #[serde(flatten)]
    pub info: CrawlInfo,
    /// The pages from index `from` on.
    pub results: Vec<CrawlPage>,
    pub from: usize,
    /// The lists below are filled when the crawl has ended.
    pub forms: Vec<CrawlForm>,
    /// Links outside the scope, or that the gate refused. Never requested.
    pub out_of_scope: Vec<String>,
    pub robots_blocked: Vec<String>,
    pub robots_paths: Vec<String>,
    pub sitemap_urls: Vec<String>,
    /// The crawl ended at the page limit with links left over.
    pub truncated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CrawlStopReply {
    /// False when the crawl was not running.
    pub stopped: bool,
}

#[derive(Debug, Deserialize)]
pub struct FromQuery {
    #[serde(default)]
    pub from: usize,
}

fn info(j: &Job) -> CrawlInfo {
    let g = lock(&j.inner);
    CrawlInfo {
        id: j.id,
        state: g.state.unwrap_or(CrawlState::Running),
        start: j.start.clone(),
        created_ms: j.created_ms,
        pages: g.pages.len(),
        requests: g.requests,
        error: g.error.clone(),
    }
}

fn detail(j: &Job, from: usize) -> CrawlDetail {
    let g = lock(&j.inner);
    let r = g.report.clone().unwrap_or_default();
    CrawlDetail {
        info: CrawlInfo {
            id: j.id,
            state: g.state.unwrap_or(CrawlState::Running),
            start: j.start.clone(),
            created_ms: j.created_ms,
            pages: g.pages.len(),
            requests: g.requests,
            error: g.error.clone(),
        },
        results: g.pages.iter().skip(from).filter_map(conv).collect(),
        from,
        forms: r.forms.iter().filter_map(conv).collect(),
        out_of_scope: r.out_of_scope,
        robots_blocked: r.robots_blocked,
        robots_paths: r.robots_paths,
        sitemap_urls: r.sitemap_urls,
        truncated: r.truncated,
    }
}

/// Records every exchange as a flow and keeps the pages for the status.
struct ApiSink {
    st: AppState,
    job: Arc<Job>,
}

impl Sink for ApiSink {
    fn exchange(&self, ex: &Exchange) {
        let id = self.st.project().next_flow_id();
        self.st.inner.proxy.record(ex.to_new_flow(id, FlowSource::Crawler));
        lock(&self.job.inner).requests += 1;
    }

    fn page(&self, page: &Page) {
        lock(&self.job.inner).pages.push(page.clone());
    }
}

async fn run(st: AppState, job: Arc<Job>, opts: Options) {
    let sink = ApiSink {
        st: st.clone(),
        job: job.clone(),
    };
    let result = bosun_crawl::crawl(&st.inner.repeater, &opts, &sink, &job.stop).await;
    let mut g = lock(&job.inner);
    match result {
        Ok(r) => {
            g.requests = r.requests;
            g.state = Some(if r.stopped || job.stop.is_stopped() {
                CrawlState::Stopped
            } else {
                CrawlState::Done
            });
            g.report = Some(r);
        }
        Err(e) => {
            g.error = Some(e.to_string());
            g.state = Some(CrawlState::Failed);
        }
    }
}

pub async fn start(State(st): State<AppState>, caller: Caller, Json(b): Json<CrawlStartBody>) -> R {
    caller.require(Role::Tester)?;
    let opts = options(&b)?;
    let job = {
        let mut jobs = lock(&st.inner.crawls.jobs);
        if jobs.iter().filter(|j| state_of(j) == CrawlState::Running).count() >= MAX_RUNNING {
            return Err(reject(
                StatusCode::TOO_MANY_REQUESTS,
                "two crawls are already running: stop one or wait",
            ));
        }
        let id = {
            let mut n = lock(&st.inner.crawls.next);
            *n += 1;
            *n
        };
        let job = Arc::new(Job {
            id,
            start: opts.start.clone(),
            created_ms: now_ms(),
            stop: Stop::new(),
            inner: Mutex::new(Inner::default()),
        });
        jobs.push(job.clone());
        while jobs.len() > MAX_KEPT {
            match jobs.iter().position(|j| state_of(j) != CrawlState::Running) {
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
            "crawl.start",
            &format!(
                "crawl {}: {} (depth {}, up to {} pages{})",
                job.id,
                opts.start.join(", "),
                opts.max_depth,
                opts.max_pages,
                if opts.submit_post_forms { ", POST forms on" } else { "" }
            ),
        )
        .await;
    let out = info(&job);
    tokio::spawn(run(st.clone(), job, opts));
    Ok(Json(out).into_response())
}

pub async fn list(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let jobs = lock(&st.inner.crawls.jobs).clone();
    Ok(Json(CrawlList {
        crawls: jobs.iter().rev().map(|j| info(j)).collect(),
    })
    .into_response())
}

fn find(st: &AppState, id: u64) -> Result<Arc<Job>, Response> {
    lock(&st.inner.crawls.jobs)
        .iter()
        .find(|j| j.id == id)
        .cloned()
        .ok_or_else(|| reject(StatusCode::NOT_FOUND, "no such crawl"))
}

pub async fn get(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<u64>,
    Query(q): Query<FromQuery>,
) -> R {
    caller.require(Role::Viewer)?;
    let job = find(&st, id)?;
    Ok(Json(detail(&job, q.from)).into_response())
}

pub async fn stop(State(st): State<AppState>, caller: Caller, Path(id): Path<u64>) -> R {
    caller.require(Role::Tester)?;
    let job = find(&st, id)?;
    let running = state_of(&job) == CrawlState::Running;
    if running {
        job.stop.stop();
        caller.audit(&st, "crawl.stop", &format!("crawl {id}")).await;
    }
    Ok(Json(CrawlStopReply { stopped: running }).into_response())
}
