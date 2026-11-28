//! The Intruder: attacks that fill marked positions of a request with payloads and send every combination.
//!
//! The engine is [`bosun_intruder`]; this module is the API around it. Every request goes through the scope gate
//! (automated tools never leave scope: there is no out-of-scope setting for the Intruder), is recorded as a flow with
//! source `intruder`, and its result is stored in the project and sent over the event stream as it arrives. Starting,
//! stopping and deleting an attack are audited.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bosun_http::Exchange;
use bosun_intruder::{
    Attack, AttackType, Finish, Greps, Options, PayloadSet, Plan, Progress, Row, Sink, Stop, Template,
};
use bosun_model::{FlowSource, Scheme, Target, now_ms};
use bosun_proxy::ProxyEvent;
use bosun_store::{NewAttack, Project, Role, StoredAttack, StoredRow};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::reject;

type R = Result<Response, Response>;

/// Attacks that may run at once.
const MAX_RUNNING: usize = 3;
/// Results returned in one page.
const MAX_PAGE: u64 = 5_000;
/// How often results are written and progress is reported while an attack runs.
const FLUSH_EVERY: Duration = Duration::from_millis(250);

/// The attacks running now.
#[derive(Debug, Default)]
pub struct Attacks {
    running: Mutex<HashMap<i64, Running>>,
}

#[derive(Debug, Clone)]
struct Running {
    stop: Stop,
    progress: Arc<Progress>,
}

impl Attacks {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<i64, Running>> {
        self.running.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Halt every running attack (a project is being switched).
    pub fn stop_all(&self) {
        for r in self.lock().values() {
            r.stop.stop();
        }
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct StartBody {
    /// A label for the attack (defaults to the host and attack type).
    #[serde(default)]
    pub name: Option<String>,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// The request, base64, with `§` around each position (`§value§`: the text between is what is sent when the
    /// position is not being attacked).
    pub request: String,
    pub attack_type: AttackType,
    /// One set for sniper and battering ram; one per position for pitchfork and cluster bomb.
    pub payload_sets: Vec<PayloadSet>,
    #[serde(default)]
    pub options: Options,
    #[serde(default)]
    pub greps: Greps,
}

/// What the attack is stored with besides its request (so it can be opened again).
#[derive(Debug, Serialize, Deserialize)]
struct Config {
    attack_type: AttackType,
    payload_sets: Vec<PayloadSet>,
    options: Options,
    greps: Greps,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PlanPreview {
    /// The payloads of one request (one per position, or one for sniper and battering ram).
    pub index: u64,
    pub payloads: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PlanReply {
    /// Requests the attack would make (after the maximum, before skipped payloads are left out).
    pub total: u64,
    pub positions: u32,
    /// The first few requests' payloads.
    pub preview: Vec<PlanPreview>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AttackInfo {
    pub id: i64,
    pub name: String,
    pub created_ms: i64,
    pub finished_ms: Option<i64>,
    /// `running`, `completed`, `stopped`, `failed` or `interrupted` (the engine ended while it ran).
    pub state: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub attack_type: String,
    pub total: u64,
    /// Requests that finished.
    pub done: u64,
    /// Requests left out because a payload was skipped.
    pub skipped: u64,
    /// Requests that got no answer.
    pub errors: u64,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AttackList {
    pub attacks: Vec<AttackInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AttackDetail {
    #[serde(flatten)]
    pub info: AttackInfo,
    /// The request with its position markers, base64.
    pub request: String,
    /// The payload sets, options and grep rules it was started with.
    pub config: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ResultsReply {
    pub rows: Vec<Row>,
}

#[derive(Debug, Deserialize)]
pub struct Page {
    #[serde(default)]
    offset: u64,
    limit: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StopReply {
    /// False when the attack was not running.
    pub stopped: bool,
}

fn info(a: &StoredAttack, live: Option<&Running>) -> AttackInfo {
    let (done, skipped, errors) = match live {
        Some(r) => (
            r.progress.done.load(Ordering::SeqCst),
            r.progress.skipped.load(Ordering::SeqCst),
            r.progress.errors.load(Ordering::SeqCst),
        ),
        None => (a.done, a.skipped, a.errors),
    };
    AttackInfo {
        id: a.id,
        name: a.name.clone(),
        created_ms: a.created_ms,
        finished_ms: a.finished_ms,
        state: a.state.clone(),
        scheme: a.scheme.clone(),
        host: a.host.clone(),
        port: a.port,
        attack_type: a.kind.clone(),
        total: a.total,
        done,
        skipped,
        errors,
        error: a.error.clone(),
    }
}

fn row_out(r: StoredRow) -> Row {
    Row {
        index: r.index,
        position: r.position,
        payloads: r.payloads,
        status: r.status,
        length: r.length,
        time_ms: r.time_ms,
        flow_id: r.flow_id,
        error: r.error,
        matches: r.matches,
        extracts: r.extracts,
        attempts: r.attempts,
    }
}

fn stored(r: &Row) -> StoredRow {
    StoredRow {
        index: r.index,
        position: r.position,
        payloads: r.payloads.clone(),
        status: r.status,
        length: r.length,
        time_ms: r.time_ms,
        flow_id: r.flow_id,
        error: r.error.clone(),
        matches: r.matches.clone(),
        extracts: r.extracts.clone(),
        attempts: r.attempts,
    }
}

fn internal<E: std::fmt::Display>(e: E) -> Response {
    tracing::error!(error = %e, "an Intruder database task failed");
    reject(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error (see the server log)",
    )
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Response> {
    tokio::task::spawn_blocking(f).await.map_err(internal)
}

/// The checks every start and preview share. Nothing is sent.
fn build(b: &StartBody) -> Result<(Template, Plan, Vec<u8>), Response> {
    let bad = |m: &str| reject(StatusCode::BAD_REQUEST, m);
    if b.host.is_empty() || b.host.len() > 255 || b.port == 0 {
        return Err(bad("that target is not valid"));
    }
    let raw = B64
        .decode(b.request.as_bytes())
        .map_err(|_| bad("the request is not valid base64"))?;
    let template = Template::parse(&raw).map_err(|e| bad(&e.to_string()))?;
    b.options.validate().map_err(|e| bad(&e.to_string()))?;
    b.greps.validate().map_err(|e| bad(&e.to_string()))?;
    let plan =
        Plan::new(template.clone(), b.attack_type, &b.payload_sets).map_err(|e| bad(&e.to_string()))?;
    Ok((template, plan, raw))
}

#[derive(Debug, Deserialize)]
pub struct PlanQuery {
    /// How many requests to list (default 10, at most 1000).
    limit: Option<u32>,
}

pub async fn plan(
    State(_st): State<AppState>,
    caller: Caller,
    Query(q): Query<PlanQuery>,
    Json(b): Json<StartBody>,
) -> R {
    caller.require(Role::Tester)?;
    let (_, plan, _) = build(&b)?;
    let total = plan.total().min(b.options.max_requests.unwrap_or(u64::MAX));
    let limit = q.limit.unwrap_or(10).clamp(1, 1000) as usize;
    let mut preview = Vec::new();
    for i in 0..plan.total() {
        if preview.len() >= limit {
            break;
        }
        if let Some(j) = plan.job(i) {
            preview.push(PlanPreview {
                index: i,
                payloads: j
                    .payloads
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect(),
            });
        }
    }
    Ok(Json(PlanReply {
        total,
        positions: plan.positions() as u32,
        preview,
    })
    .into_response())
}

/// Records, buffers and announces what an attack produces.
struct ApiSink {
    st: AppState,
    project: Arc<Project>,
    attack_id: i64,
    buffer: Mutex<Vec<StoredRow>>,
}

impl Sink for ApiSink {
    fn record(&self, ex: &Exchange) -> Option<i64> {
        let id = self.project.next_flow_id();
        self.st
            .inner
            .proxy
            .record(ex.to_new_flow(id, FlowSource::Intruder));
        Some(id)
    }

    fn row(&self, r: Row) {
        self.st.inner.events.send(ProxyEvent::IntruderResult {
            attack_id: self.attack_id,
            index: r.index,
            position: r.position,
            payloads: r.payloads.clone(),
            status: r.status,
            length: r.length,
            time_ms: r.time_ms,
            flow_id: r.flow_id,
            error: r.error.clone(),
            matches: r.matches.clone(),
            extracts: r.extracts.clone(),
            attempts: r.attempts,
        });
        self.buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(stored(&r));
    }
}

fn state_event(id: i64, state: &str, total: u64, p: (u64, u64, u64), error: Option<String>) -> ProxyEvent {
    ProxyEvent::IntruderState {
        attack_id: id,
        state: state.to_string(),
        total,
        done: p.0,
        skipped: p.1,
        errors: p.2,
        error,
    }
}

fn counts(p: &Progress) -> (u64, u64, u64) {
    (
        p.done.load(Ordering::SeqCst),
        p.skipped.load(Ordering::SeqCst),
        p.errors.load(Ordering::SeqCst),
    )
}

/// Write what has piled up, and the counters.
async fn flush(sink: &ApiSink, progress: &Progress) {
    let rows = std::mem::take(&mut *sink.buffer.lock().unwrap_or_else(|e| e.into_inner()));
    let (p, id) = (sink.project.clone(), sink.attack_id);
    let (done, skipped, errors) = counts(progress);
    let r = tokio::task::spawn_blocking(move || {
        if !rows.is_empty() {
            p.intruder_add_rows(id, &rows)?;
        }
        p.intruder_progress(id, done, skipped, errors)
    })
    .await;
    match r {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!(error = %e, attack = id, "could not store Intruder results"),
        Err(e) => tracing::error!(error = %e, attack = id, "an Intruder storage task failed"),
    }
}

async fn drive(
    st: AppState,
    project: Arc<Project>,
    id: i64,
    attack: Attack,
    stop: Stop,
    progress: Arc<Progress>,
    total: u64,
) {
    let sink = Arc::new(ApiSink {
        st: st.clone(),
        project: project.clone(),
        attack_id: id,
        buffer: Mutex::new(Vec::new()),
    });
    let fut = bosun_intruder::run(attack, sink.clone(), progress.clone(), stop);
    tokio::pin!(fut);
    let mut tick = tokio::time::interval(FLUSH_EVERY);
    let mut last = (u64::MAX, 0, 0);
    let result = loop {
        tokio::select! {
            r = &mut fut => break r,
            _ = tick.tick() => {
                flush(&sink, &progress).await;
                let c = counts(&progress);
                if c != last {
                    last = c;
                    st.inner.events.send(state_event(id, "running", total, c, None));
                }
            }
        }
    };
    flush(&sink, &progress).await;
    let (state, error) = match &result {
        Ok(s) => match &s.finish {
            Finish::Completed => ("completed", None),
            Finish::Stopped => ("stopped", None),
            Finish::Failed(e) => ("failed", Some(e.clone())),
        },
        Err(e) => ("failed", Some(e.to_string())),
    };
    let c = counts(&progress);
    let (p, e2) = (project, error.clone());
    let r = tokio::task::spawn_blocking(move || {
        p.intruder_finish(id, state, e2.as_deref(), now_ms(), c.0, c.1, c.2)
    })
    .await;
    if !matches!(r, Ok(Ok(()))) {
        tracing::error!(attack = id, "could not store the end of an Intruder attack");
    }
    st.inner.intruder.lock().remove(&id);
    st.inner.events.send(state_event(id, state, total, c, error));
}

pub async fn start(State(st): State<AppState>, caller: Caller, Json(b): Json<StartBody>) -> R {
    caller.require(Role::Tester)?;
    let (_, plan, raw) = build(&b)?;
    let total = plan.total().min(b.options.max_requests.unwrap_or(u64::MAX));
    if total == 0 {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "the attack would send no requests: the payload sets are empty",
        ));
    }
    let project = st.project();
    let name = b
        .name
        .clone()
        .map(|n| n.chars().take(100).collect::<String>())
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| format!("{} {}", b.host, b.attack_type.as_str().replace('_', " ")));
    let config = serde_json::to_string(&Config {
        attack_type: b.attack_type,
        payload_sets: b.payload_sets.clone(),
        options: b.options.clone(),
        greps: b.greps.clone(),
    })
    .map_err(internal)?;
    let new = NewAttack {
        name,
        created_ms: now_ms(),
        scheme: b.scheme.as_str().to_string(),
        host: b.host.clone(),
        port: b.port,
        kind: b.attack_type.as_str().to_string(),
        request: raw,
        config,
        total,
    };
    let (stop, progress) = (Stop::new(), Arc::new(Progress::default()));
    let id = {
        // Two starts at the same moment can both pass this check; one attack more than the limit is harmless.
        if st.inner.intruder.lock().len() >= MAX_RUNNING {
            return Err(reject(
                StatusCode::CONFLICT,
                &format!("{MAX_RUNNING} attacks are already running: stop one first"),
            ));
        }
        let p = project.clone();
        let id = blocking(move || p.intruder_create(&new))
            .await?
            .map_err(|e| match e {
                bosun_store::StoreError::Conflict(m) => reject(StatusCode::CONFLICT, &m),
                e => internal(e),
            })?;
        st.inner.intruder.lock().insert(
            id,
            Running {
                stop: stop.clone(),
                progress: progress.clone(),
            },
        );
        id
    };
    let attack = Attack {
        engine: st.inner.repeater.clone(),
        target: Target::new(b.scheme, b.host.clone(), b.port),
        plan: Arc::new(plan),
        options: b.options.clone(),
        greps: b.greps.clone(),
    };
    st.inner
        .events
        .send(state_event(id, "running", total, (0, 0, 0), None));
    tokio::spawn(drive(
        st.clone(),
        project.clone(),
        id,
        attack,
        stop,
        progress,
        total,
    ));
    caller
        .audit(
            &st,
            "intruder.start",
            &format!(
                "attack {id}: {} {}://{}:{} ({total} requests)",
                b.attack_type.as_str(),
                b.scheme.as_str(),
                b.host,
                b.port
            ),
        )
        .await;
    let a = blocking(move || project.intruder_attack(id))
        .await?
        .map_err(internal)?
        .ok_or_else(|| internal("the attack just created is gone"))?;
    let live = st.inner.intruder.lock().get(&id).cloned();
    Ok(Json(info(&a, live.as_ref())).into_response())
}

pub async fn list(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let p = st.project();
    let all = blocking(move || p.intruder_attacks()).await?.map_err(internal)?;
    let live = st.inner.intruder.lock().clone();
    Ok(Json(AttackList {
        attacks: all.iter().map(|a| info(a, live.get(&a.id))).collect(),
    })
    .into_response())
}

async fn find(st: &AppState, id: i64) -> Result<StoredAttack, Response> {
    let p = st.project();
    blocking(move || p.intruder_attack(id))
        .await?
        .map_err(internal)?
        .ok_or_else(|| reject(StatusCode::NOT_FOUND, "no such attack"))
}

pub async fn get(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Viewer)?;
    let a = find(&st, id).await?;
    let live = st.inner.intruder.lock().get(&id).cloned();
    let config = serde_json::from_str(&a.config).unwrap_or(serde_json::Value::Null);
    Ok(Json(AttackDetail {
        info: info(&a, live.as_ref()),
        request: B64.encode(&a.request),
        config,
    })
    .into_response())
}

pub async fn results(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<i64>,
    Query(q): Query<Page>,
) -> R {
    caller.require(Role::Viewer)?;
    find(&st, id).await?;
    let limit = q.limit.unwrap_or(1000).clamp(1, MAX_PAGE);
    let p = st.project();
    let rows = blocking(move || p.intruder_rows(id, q.offset, limit))
        .await?
        .map_err(internal)?;
    Ok(Json(ResultsReply {
        rows: rows.into_iter().map(row_out).collect(),
    })
    .into_response())
}

pub async fn stop(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Tester)?;
    let running = st.inner.intruder.lock().get(&id).cloned();
    let stopped = running.is_some();
    if let Some(r) = running {
        r.stop.stop();
        caller.audit(&st, "intruder.stop", &format!("attack {id}")).await;
    } else {
        find(&st, id).await?;
    }
    Ok(Json(StopReply { stopped }).into_response())
}

pub async fn delete(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Tester)?;
    if st.inner.intruder.lock().contains_key(&id) {
        return Err(reject(
            StatusCode::CONFLICT,
            "that attack is running: stop it before deleting it",
        ));
    }
    let p = st.project();
    let found = blocking(move || p.intruder_delete(id)).await?.map_err(internal)?;
    if !found {
        return Err(reject(StatusCode::NOT_FOUND, "no such attack"));
    }
    caller
        .audit(&st, "intruder.delete", &format!("attack {id}"))
        .await;
    Ok(crate::security::empty(StatusCode::NO_CONTENT))
}
