//! The active scanner: start, watch, pause, resume and stop (see `bosun-active`).
//!
//! A scan is a background job of this run of the server (a few are kept, finished ones are dropped oldest first).
//! Every request goes through the Repeater's engine, so the scope gate (scope, kill switch, per-host rate limit)
//! decides each one first: a target outside the scope is listed in `refused`, never contacted. Each exchange is
//! recorded as a flow with source `scanner`, and each finding becomes an issue (rule = the check id) that points at
//! the flow that proves it. Starting, pausing, resuming and stopping are audited. Active scanning sends attack
//! probes, so starting one needs the tester role.

use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bosun_active::{Control, Finding, Options, Report, Sink, Strength, Target};
use bosun_http::Exchange;
use bosun_model::{FlowSource, now_ms};
use bosun_proxy::ProxyEvent;

use bosun_store::{Confidence, NewIssue, Role, Severity};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::reject;

type R = Result<Response, Response>;

/// Scans that may run at once, and scans kept.
const MAX_RUNNING: usize = 2;
const MAX_KEPT: usize = 8;
const MAX_TARGETS: usize = 2_000;
const MAX_REQUESTS: u64 = 200_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    Running,
    /// No request starts until it is resumed.
    Paused,
    /// Every unit was run (or the request cap ended it: see `truncated`).
    Done,
    /// The stop switch, or the gate's kill switch, ended it.
    Stopped,
    Failed,
}

#[derive(Default)]
struct Inner {
    done: bool,
    stopped: bool,
    units_done: usize,
    units_total: usize,
    requests: u64,
    findings: Vec<ScanFinding>,
    error: Option<String>,
    report: Option<Report>,
    last_event: Option<std::time::Instant>,
}

struct Job {
    id: u64,
    targets: usize,
    created_ms: i64,
    ctl: Control,
    inner: Mutex<Inner>,
}

/// The scans of this run of the server.
#[derive(Default)]
pub struct Scans {
    jobs: Mutex<Vec<Arc<Job>>>,
    next: Mutex<u64>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn state_of(j: &Job) -> ScanState {
    let g = lock(&j.inner);
    if !g.done {
        return if j.ctl.is_paused() {
            ScanState::Paused
        } else {
            ScanState::Running
        };
    }
    if g.error.is_some() {
        ScanState::Failed
    } else if g.stopped {
        ScanState::Stopped
    } else {
        ScanState::Done
    }
}

fn live(j: &Job) -> bool {
    !lock(&j.inner).done
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ScanTarget {
    /// Absolute `http` or `https` URL; its query values are insertion points.
    pub url: String,
    /// Default `GET`.
    #[serde(default)]
    pub method: Option<String>,
    /// Each `Name: value`. A `Cookie` header makes its cookies insertion points.
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub body: Option<String>,
    /// `application/x-www-form-urlencoded` (default with a body) or `application/json`: their values are
    /// insertion points.
    #[serde(default)]
    pub content_type: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ScanStartBody {
    /// The requests to test (1 to 2000).
    pub targets: Vec<ScanTarget>,
    /// Check ids (see scan_checks); empty runs every check that is not destructive, and a destructive one (it saves data in the target) runs only when named.
    #[serde(default)]
    pub checks: Vec<String>,
    /// `low`, `medium` (default) or `high`: more insertion points and probes.
    #[serde(default)]
    pub strength: Option<String>,
    /// Units of work in flight at once (1 to 32, default 4).
    #[serde(default)]
    pub concurrency: Option<u32>,
    /// The least time between two request starts in one unit, milliseconds (at most 60000).
    #[serde(default)]
    pub delay_ms: Option<u64>,
    /// The most requests the scan may send (1 to 200000, default 5000).
    #[serde(default)]
    pub max_requests: Option<u64>,
    /// Extra headers for every request, each `Name: value`.
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub verify_tls: bool,
}

fn header_pair(h: &str) -> Result<(String, String), Response> {
    let (k, v) = h
        .split_once(':')
        .ok_or_else(|| reject(StatusCode::BAD_REQUEST, "a header is `Name: value`"))?;
    Ok((k.trim().to_string(), v.trim().to_string()))
}

fn build(b: &ScanStartBody) -> Result<(Options, Vec<Target>), Response> {
    let bad = |m: &str| reject(StatusCode::BAD_REQUEST, m);
    if b.targets.is_empty() || b.targets.len() > MAX_TARGETS {
        return Err(bad("give 1 to 2000 targets"));
    }
    let strength = match b.strength.as_deref() {
        None | Some("medium") => Strength::Medium,
        Some("low") => Strength::Low,
        Some("high") => Strength::High,
        Some(_) => return Err(bad("strength is low, medium or high")),
    };
    let d = Options::default();
    let o = Options {
        checks: b.checks.clone(),
        strength,
        concurrency: b.concurrency.unwrap_or(d.concurrency),
        delay_ms: b.delay_ms.unwrap_or(0).min(60_000),
        max_requests: b.max_requests.unwrap_or(d.max_requests),
        headers: b
            .headers
            .iter()
            .map(|h| header_pair(h))
            .collect::<Result<_, _>>()?,
        verify_tls: b.verify_tls,
        ..d
    };
    if o.max_requests > MAX_REQUESTS {
        return Err(bad("max_requests is at most 200000"));
    }
    o.validate().map_err(|e| bad(&e.to_string()))?;
    let mut targets = Vec::new();
    for t in &b.targets {
        targets.push(Target {
            method: t.method.clone(),
            url: t.url.clone(),
            headers: t
                .headers
                .iter()
                .map(|h| header_pair(h))
                .collect::<Result<_, _>>()?,
            body: t.body.clone(),
            content_type: t.content_type.clone(),
        });
    }
    // Every target must parse now, so a typo is a 400 and not a failed scan.
    for t in &targets {
        bosun_active::Req::from_target(t, &o.headers).map_err(|e| bad(&e.to_string()))?;
    }
    Ok((o, targets))
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanFinding {
    pub check: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub url: String,
    pub point: String,
    pub payload: String,
    pub detail: String,
    /// The flow that proves it; the issue list shows the finding too.
    pub flow_id: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanInfo {
    pub id: u64,
    pub state: ScanState,
    pub targets: usize,
    pub created_ms: i64,
    /// Units of work (a target and one insertion point) finished, and planned.
    pub units_done: usize,
    pub units_total: usize,
    pub requests: u64,
    pub findings: usize,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanList {
    pub scans: Vec<ScanInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanDetail {
    #[serde(flatten)]
    pub info: ScanInfo,
    pub results: Vec<ScanFinding>,
    /// Targets the gate refused (outside the scope). Never contacted. Filled when the scan has ended.
    pub refused: Vec<String>,
    /// The request cap ended the scan with work left.
    pub truncated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanCheck {
    pub id: String,
    pub description: String,
    /// Saves data in the target application: off unless named in `checks`.
    pub destructive: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanChecks {
    pub checks: Vec<ScanCheck>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanControlReply {
    /// False when the scan was not running (or, for resume, not paused).
    pub changed: bool,
}

fn info(j: &Job) -> ScanInfo {
    let state = state_of(j);
    let g = lock(&j.inner);
    ScanInfo {
        id: j.id,
        state,
        targets: j.targets,
        created_ms: j.created_ms,
        units_done: g.units_done,
        units_total: g.units_total,
        requests: g.requests,
        findings: g.findings.len(),
        error: g.error.clone(),
    }
}

fn detail(j: &Job) -> ScanDetail {
    let info = info(j);
    let g = lock(&j.inner);
    let r = g.report.clone().unwrap_or_default();
    ScanDetail {
        info,
        results: g.findings.clone(),
        refused: r.refused,
        truncated: r.truncated,
    }
}

fn shown(f: &Finding) -> ScanFinding {
    let word = |v: &serde_json::Value| v.as_str().unwrap_or("").to_string();
    let sev = serde_json::to_value(f.severity).unwrap_or_default();
    let conf = serde_json::to_value(f.confidence).unwrap_or_default();
    ScanFinding {
        check: f.check.clone(),
        title: f.title.clone(),
        severity: word(&sev),
        confidence: word(&conf),
        url: f.url.clone(),
        point: f.point.clone(),
        payload: f.payload.clone(),
        detail: f.detail.clone(),
        flow_id: f.flow_id,
    }
}

fn issue_of(f: &Finding) -> Option<NewIssue> {
    let u = bosun_crawl::parse_url(&f.url)?;
    let path = u.path.split('?').next().unwrap_or("/").to_string();
    let sev = match f.severity {
        bosun_active::Severity::Info => Severity::Info,
        bosun_active::Severity::Low => Severity::Low,
        bosun_active::Severity::Medium => Severity::Medium,
        bosun_active::Severity::High => Severity::High,
    };
    let conf = match f.confidence {
        bosun_active::Confidence::Tentative => Confidence::Tentative,
        bosun_active::Confidence::Firm => Confidence::Firm,
        bosun_active::Confidence::Certain => Confidence::Certain,
    };
    Some(NewIssue {
        rule: f.check.clone(),
        title: format!("{} ({})", f.title, f.point),
        severity: sev,
        confidence: conf,
        flow_id: f.flow_id,
        scheme: u.scheme.as_str().to_string(),
        host: u.host,
        port: u.port,
        path: path.clone(),
        detail: format!("{}\nPayload: {}", f.detail, f.payload),
        evidence: Vec::new(),
        remediation: f.remediation.clone(),
        cwe: f.cwe.clone(),
        owasp: Vec::new(),
        fingerprint: format!("{}|{}|{}", f.check, f.url, f.point),
        time_ms: now_ms(),
    })
}

/// Records every exchange as a flow and keeps the findings and counts for the status.
struct ApiSink {
    st: AppState,
    job: Arc<Job>,
}

impl Sink for ApiSink {
    fn exchange(&self, ex: &Exchange) -> i64 {
        let id = self.st.project().next_flow_id();
        self.st
            .inner
            .proxy
            .record(ex.to_new_flow(id, FlowSource::Scanner));
        id
    }

    fn finding(&self, f: &Finding) {
        lock(&self.job.inner).findings.push(shown(f));
    }

    fn progress(&self, done: usize, total: usize, requests: u64) {
        let ev = {
            let mut g = lock(&self.job.inner);
            g.units_done = done;
            g.units_total = total;
            g.requests = requests;
            // At most four events a second (the last unit always goes out).
            let quiet = g
                .last_event
                .is_some_and(|t| t.elapsed() < std::time::Duration::from_millis(250));
            if quiet && done < total {
                return;
            }
            g.last_event = Some(std::time::Instant::now());
            ProxyEvent::ScanProgress {
                id: self.job.id,
                units_done: done as u64,
                units_total: total as u64,
                requests,
                findings: g.findings.len() as u64,
            }
        };
        self.st.inner.events.send(ev);
    }
}

async fn run(st: AppState, job: Arc<Job>, opts: Options, targets: Vec<Target>) {
    let sink = Arc::new(ApiSink {
        st: st.clone(),
        job: job.clone(),
    });
    let result = bosun_active::scan(&st.inner.repeater, &opts, &targets, sink, &job.ctl).await;
    let mut stored = Vec::new();
    {
        let mut g = lock(&job.inner);
        match &result {
            Ok(r) => {
                g.requests = r.requests;
                g.units_done = r.units_done;
                g.units_total = r.units_total;
                g.stopped = r.stopped;
                stored = r.findings.iter().filter_map(issue_of).collect();
            }
            Err(e) => g.error = Some(e.to_string()),
        }
        g.report = result.ok();
    }
    if !stored.is_empty() {
        let p = st.project();
        let _ = tokio::task::spawn_blocking(move || p.scan_commit(&[], &stored)).await;
    }
    let ev = {
        let mut g = lock(&job.inner);
        g.done = true;
        ProxyEvent::ScanDone {
            id: job.id,
            state: match (&g.error, g.stopped) {
                (Some(_), _) => "failed",
                (None, true) => "stopped",
                (None, false) => "done",
            }
            .into(),
            requests: g.requests,
            findings: g.findings.len() as u64,
            error: g.error.clone(),
        }
    };
    st.inner.events.send(ev);
}

pub async fn start(State(st): State<AppState>, caller: Caller, Json(b): Json<ScanStartBody>) -> R {
    caller.require(Role::Tester)?;
    let (opts, targets) = build(&b)?;
    let job = {
        let mut jobs = lock(&st.inner.scans.jobs);
        if jobs.iter().filter(|j| live(j)).count() >= MAX_RUNNING {
            return Err(reject(
                StatusCode::TOO_MANY_REQUESTS,
                "two scans are already running: stop one or wait",
            ));
        }
        let id = {
            let mut n = lock(&st.inner.scans.next);
            *n += 1;
            *n
        };
        let job = Arc::new(Job {
            id,
            targets: targets.len(),
            created_ms: now_ms(),
            ctl: Control::new(),
            inner: Mutex::new(Inner::default()),
        });
        jobs.push(job.clone());
        while jobs.len() > MAX_KEPT {
            match jobs.iter().position(|j| !live(j)) {
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
            "scan.start",
            &format!(
                "scan {}: {} targets, strength {:?}, up to {} requests",
                job.id,
                targets.len(),
                opts.strength,
                opts.max_requests
            ),
        )
        .await;
    let out = info(&job);
    st.inner.events.send(ProxyEvent::ScanStarted {
        id: job.id,
        targets: targets.len() as u64,
    });
    tokio::spawn(run(st.clone(), job, opts, targets));
    Ok(Json(out).into_response())
}

pub async fn list(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let jobs = lock(&st.inner.scans.jobs).clone();
    Ok(Json(ScanList {
        scans: jobs.iter().rev().map(|j| info(j)).collect(),
    })
    .into_response())
}

pub async fn checks(caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(ScanChecks {
        checks: bosun_active::CHECKS
            .iter()
            .map(|(id, d)| ScanCheck {
                id: (*id).into(),
                description: (*d).into(),
                destructive: bosun_active::is_destructive(id),
            })
            .collect(),
    })
    .into_response())
}

fn find(st: &AppState, id: u64) -> Result<Arc<Job>, Response> {
    lock(&st.inner.scans.jobs)
        .iter()
        .find(|j| j.id == id)
        .cloned()
        .ok_or_else(|| reject(StatusCode::NOT_FOUND, "no such scan"))
}

pub async fn get(State(st): State<AppState>, caller: Caller, Path(id): Path<u64>) -> R {
    caller.require(Role::Viewer)?;
    let job = find(&st, id)?;
    Ok(Json(detail(&job)).into_response())
}

pub async fn stop(State(st): State<AppState>, caller: Caller, Path(id): Path<u64>) -> R {
    caller.require(Role::Tester)?;
    let job = find(&st, id)?;
    let running = live(&job);
    if running {
        job.ctl.stop();
        caller.audit(&st, "scan.stop", &format!("scan {id}")).await;
    }
    Ok(Json(ScanControlReply { changed: running }).into_response())
}

pub async fn pause(State(st): State<AppState>, caller: Caller, Path(id): Path<u64>) -> R {
    caller.require(Role::Tester)?;
    let job = find(&st, id)?;
    let changed = live(&job) && !job.ctl.is_paused();
    if changed {
        job.ctl.pause();
        caller.audit(&st, "scan.pause", &format!("scan {id}")).await;
    }
    Ok(Json(ScanControlReply { changed }).into_response())
}

pub async fn resume(State(st): State<AppState>, caller: Caller, Path(id): Path<u64>) -> R {
    caller.require(Role::Tester)?;
    let job = find(&st, id)?;
    let changed = live(&job) && job.ctl.is_paused();
    if changed {
        job.ctl.resume();
        caller.audit(&st, "scan.resume", &format!("scan {id}")).await;
    }
    Ok(Json(ScanControlReply { changed }).into_response())
}
