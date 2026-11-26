//! Sending an attack: the resource pool, grep, and the stop switch.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bosun_http::{Engine, Exchange, SendError, SendOptions};
use bosun_model::{FlowSource, Target};
use bosun_scope::ScopeError;
use regex::bytes::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;
use utoipa::ToSchema;

use crate::plan::{Job, Plan};
use crate::{PlanError, invalid};

/// How much of a response grep looks at.
const GREP_WINDOW: usize = 1 << 20;
/// How much of an extracted value is kept.
const EXTRACT_MAX: usize = 256;
/// How long a request waits for the gate's rate limit before it gives up.
const RATE_WAIT: Duration = Duration::from_secs(60);

/// The resource pool and the sending options.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(default)]
pub struct Options {
    /// Requests in flight at once (1 to 64). The gate's per-host rate limit still applies on top of this.
    pub concurrency: u32,
    /// The least time between the starts of two requests, milliseconds, whatever the concurrency.
    pub delay_ms: u64,
    /// How often a request that could not be sent or got no answer is tried again (0 to 10).
    pub retries: u32,
    /// Stop after this many requests (at most one million).
    pub max_requests: Option<u64>,
    /// Rewrite `Content-Length` to match each request, which is almost always wanted when a payload changes the body.
    pub update_content_length: bool,
    pub verify_tls: bool,
    /// The longest one request may take, seconds (1 to 300).
    pub timeout_secs: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            concurrency: 5,
            delay_ms: 0,
            retries: 0,
            max_requests: None,
            update_content_length: true,
            verify_tls: false,
            timeout_secs: 30,
        }
    }
}

impl Options {
    pub fn validate(&self) -> Result<(), PlanError> {
        if !(1..=64).contains(&self.concurrency) {
            return invalid("concurrency is 1 to 64");
        }
        if self.retries > 10 {
            return invalid("retries are 0 to 10");
        }
        if self.delay_ms > 3_600_000 {
            return invalid("the delay is at most an hour");
        }
        if !(1..=300).contains(&self.timeout_secs) {
            return invalid("the timeout is 1 to 300 seconds");
        }
        Ok(())
    }
}

/// Mark a response as a match when this is found in it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct GrepMatch {
    pub pattern: String,
    /// A regular expression rather than plain text.
    #[serde(default)]
    pub regex: bool,
    #[serde(default)]
    pub case_insensitive: bool,
}

/// Pull a value out of the response: the first group of the regular expression, or the whole match without one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct GrepExtract {
    pub pattern: String,
}

/// The grep rules of an attack.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct Greps {
    #[serde(default)]
    pub matches: Vec<GrepMatch>,
    #[serde(default)]
    pub extracts: Vec<GrepExtract>,
}

struct CompiledGreps {
    matches: Vec<Regex>,
    extracts: Vec<Regex>,
}

impl Greps {
    /// Check that every pattern is valid and within limits.
    pub fn validate(&self) -> Result<(), PlanError> {
        self.compile().map(|_| ())
    }

    fn compile(&self) -> Result<CompiledGreps, PlanError> {
        if self.matches.len() > 20 || self.extracts.len() > 20 {
            return invalid("at most 20 grep rules of each kind");
        }
        let build = |p: &str, ci: bool| {
            if p.len() > 4096 {
                return invalid("a grep pattern is over 4096 bytes");
            }
            RegexBuilder::new(p)
                .case_insensitive(ci)
                .size_limit(1 << 20)
                .dfa_size_limit(4 << 20)
                .build()
                .map_err(|e| PlanError::Invalid(format!("not a valid grep pattern ({p:?}): {e}")))
        };
        Ok(CompiledGreps {
            matches: self
                .matches
                .iter()
                .map(|m| {
                    let pat = if m.regex {
                        m.pattern.clone()
                    } else {
                        regex::escape(&m.pattern)
                    };
                    build(&pat, m.case_insensitive)
                })
                .collect::<Result<_, _>>()?,
            extracts: self
                .extracts
                .iter()
                .map(|e| build(&e.pattern, false))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// The outcome of one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Row {
    /// Which request of the attack (0-based).
    pub index: u64,
    /// The position that was attacked, for a sniper attack.
    pub position: Option<u32>,
    /// The payloads used, as text (bytes that are not UTF-8 are replaced).
    pub payloads: Vec<String>,
    pub status: Option<u16>,
    /// Response size in bytes.
    pub length: u64,
    pub time_ms: u64,
    /// The recorded flow, when something was sent.
    pub flow_id: Option<i64>,
    pub error: Option<String>,
    /// One entry per grep match rule.
    pub matches: Vec<bool>,
    /// One entry per grep extract rule.
    pub extracts: Vec<Option<String>>,
    /// How many tries it took (1 when the first worked).
    pub attempts: u32,
}

/// Where requests and results go.
pub trait Sink: Send + Sync {
    /// Record the exchange as a flow with source intruder; returns its id.
    fn record(&self, ex: &Exchange) -> Option<i64>;
    /// A request finished.
    fn row(&self, row: Row);
}

/// Counters the caller can read while the attack runs.
#[derive(Debug, Default)]
pub struct Progress {
    /// Requests that finished (with or without an answer).
    pub done: AtomicU64,
    /// Requests left out because a payload was skipped.
    pub skipped: AtomicU64,
    /// Requests that got no answer.
    pub errors: AtomicU64,
}

#[derive(Debug, Default)]
struct StopInner {
    flag: AtomicBool,
    notify: Notify,
}

/// The stop switch of an attack. Cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct Stop(Arc<StopInner>);

impl Stop {
    pub fn new() -> Self {
        Self::default()
    }

    /// Halt the attack: no request starts after this, and the ones in flight are dropped.
    pub fn stop(&self) {
        self.0.flag.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    pub fn is_stopped(&self) -> bool {
        self.0.flag.load(Ordering::SeqCst)
    }

    /// Resolves once the switch is thrown.
    pub async fn stopped(&self) {
        loop {
            let n = self.0.notify.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            if self.is_stopped() {
                return;
            }
            n.await;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finish {
    Completed,
    /// The stop switch (or the kill switch) ended it.
    Stopped,
    /// Something every further request would hit too: out of scope, an invalid request.
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub finish: Finish,
    pub done: u64,
    pub skipped: u64,
    pub errors: u64,
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn row_of(job: &Job, attempts: u32) -> Row {
    Row {
        index: job.index,
        position: job.position.map(|p| p as u32),
        payloads: job.payloads.iter().map(|p| lossy(p)).collect(),
        status: None,
        length: 0,
        time_ms: 0,
        flow_id: None,
        error: None,
        matches: Vec::new(),
        extracts: Vec::new(),
        attempts,
    }
}

fn fill(row: &mut Row, ex: &Exchange, flow_id: Option<i64>, g: &CompiledGreps) {
    row.status = ex.status;
    row.length = ex.response.len() as u64;
    row.time_ms = ex.timings.total_ms;
    row.flow_id = flow_id;
    row.error = ex.error.clone();
    let hay = &ex.response[..ex.response.len().min(GREP_WINDOW)];
    row.matches = g.matches.iter().map(|r| r.is_match(hay)).collect();
    row.extracts = g
        .extracts
        .iter()
        .map(|r| {
            let c = r.captures(hay)?;
            let m = c.get(1).or_else(|| c.get(0))?;
            let s = lossy(m.as_bytes());
            Some(s.chars().take(EXTRACT_MAX).collect())
        })
        .collect();
}

enum Sent {
    Done(Box<Exchange>, u32),
    /// Could not send: the reason, and how many tries were made.
    Failed(String, u32),
    /// Stop the whole attack, and say why.
    Fatal(String),
    /// The kill switch is on: stop the whole attack as if asked to.
    Halt,
}

async fn send_job(engine: &Engine, target: &Target, job: &Job, opts: &SendOptions, retries: u32) -> Sent {
    let started = Instant::now();
    let mut attempt = 0u32;
    loop {
        match engine.send(target, &job.request, opts).await {
            Ok(ex) => {
                if ex.response.is_empty() && ex.error.is_some() && attempt < retries {
                    attempt += 1;
                    backoff(attempt).await;
                    continue;
                }
                return Sent::Done(Box::new(ex), attempt + 1);
            }
            // The gate's per-host rate limit: wait for the window to move rather than drop the request.
            Err(SendError::Refused(ScopeError::RateLimited(..))) => {
                if started.elapsed() > RATE_WAIT {
                    return Sent::Failed("waited a minute for the rate limit".into(), attempt + 1);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(SendError::Refused(ScopeError::Stopped)) => {
                return Sent::Halt;
            }
            Err(SendError::Refused(e)) => return Sent::Fatal(e.to_string()),
            Err(SendError::BadRequest(e)) => return Sent::Fatal(format!("the request is not valid: {e}")),
            Err(e) => {
                if attempt < retries {
                    attempt += 1;
                    backoff(attempt).await;
                    continue;
                }
                return Sent::Failed(e.to_string(), attempt + 1);
            }
        }
    }
}

async fn backoff(attempt: u32) {
    tokio::time::sleep(Duration::from_millis(200u64 << attempt.min(5))).await;
}

/// Everything an attack needs besides where its results go.
#[derive(Debug, Clone)]
pub struct Attack {
    pub engine: Engine,
    pub target: Target,
    pub plan: Arc<Plan>,
    pub options: Options,
    pub greps: Greps,
}

/// Send the attack. Returns when every request has finished, the stop switch is thrown, or a request fails in a
/// way that every other would too (the target is out of scope, say).
///
/// Every request goes through the attack's `engine`, so through the scope gate (its per-host rate limit, its kill switch and its
/// address checks) and the memory budget the engine shares with the proxy. `sink` records and receives the results.
pub async fn run(
    attack: Attack,
    sink: Arc<dyn Sink>,
    progress: Arc<Progress>,
    stop: Stop,
) -> Result<Summary, PlanError> {
    let Attack {
        engine,
        target,
        plan,
        options: opts,
        greps,
    } = attack;
    opts.validate()?;
    let greps = Arc::new(greps.compile()?);
    let total = plan.total().min(opts.max_requests.unwrap_or(u64::MAX));
    let send_opts = SendOptions {
        source: FlowSource::Intruder,
        update_content_length: opts.update_content_length,
        verify_tls: opts.verify_tls,
        connect_timeout: Duration::from_secs(opts.timeout_secs.min(15)),
        idle_timeout: Duration::from_secs(opts.timeout_secs),
        total_timeout: Duration::from_secs(opts.timeout_secs),
        max_response: 4 << 20,
        reuse: false,
    };
    let fatal: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let slots = Arc::new(Semaphore::new(opts.concurrency as usize));
    let delay = Duration::from_millis(opts.delay_ms);
    let mut next_start = Instant::now();
    let mut tasks: JoinSet<()> = JoinSet::new();

    'dispatch: for i in 0..total {
        if stop.is_stopped() {
            break;
        }
        let Some(job) = plan.job(i) else {
            progress.skipped.fetch_add(1, Ordering::SeqCst);
            continue;
        };
        let permit = tokio::select! {
            p = slots.clone().acquire_owned() => match p { Ok(p) => p, Err(_) => break 'dispatch },
            _ = stop.stopped() => break 'dispatch,
        };
        if !delay.is_zero() {
            let now = Instant::now();
            let at = next_start.max(now);
            next_start = at + delay;
            if at > now {
                tokio::select! {
                    _ = tokio::time::sleep_until(at.into()) => {}
                    _ = stop.stopped() => break 'dispatch,
                }
            }
        }
        // Keep the set small: collect what has finished.
        while tasks.try_join_next().is_some() {}
        let (engine, target, send_opts, greps, sink, progress, fatal, stop2) = (
            engine.clone(),
            target.clone(),
            send_opts.clone(),
            greps.clone(),
            sink.clone(),
            progress.clone(),
            fatal.clone(),
            stop.clone(),
        );
        let retries = opts.retries;
        tasks.spawn(async move {
            let _permit = permit;
            let sent = tokio::select! {
                s = send_job(&engine, &target, &job, &send_opts, retries) => s,
                // Dropping the request here closes its connection: nothing more is sent or waited for.
                _ = stop2.stopped() => return,
            };
            let mut row;
            match sent {
                Sent::Done(ex, attempts) => {
                    row = row_of(&job, attempts);
                    let flow_id = sink.record(&ex);
                    fill(&mut row, &ex, flow_id, &greps);
                    if ex.status.is_none() {
                        progress.errors.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Sent::Failed(e, attempts) => {
                    row = row_of(&job, attempts);
                    row.error = Some(e);
                    row.matches = vec![false; greps.matches.len()];
                    row.extracts = vec![None; greps.extracts.len()];
                    progress.errors.fetch_add(1, Ordering::SeqCst);
                }
                Sent::Halt => {
                    stop2.stop();
                    return;
                }
                Sent::Fatal(e) => {
                    fatal.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert(e);
                    stop2.stop();
                    return;
                }
            }
            progress.done.fetch_add(1, Ordering::SeqCst);
            sink.row(row);
        });
    }
    if stop.is_stopped() {
        tasks.abort_all();
    }
    while tasks.join_next().await.is_some() {}
    let fatal = fatal.lock().unwrap_or_else(|p| p.into_inner()).take();
    let finish = match fatal {
        Some(e) => Finish::Failed(e),
        None if stop.is_stopped() => Finish::Stopped,
        None => Finish::Completed,
    };
    Ok(Summary {
        finish,
        done: progress.done.load(Ordering::SeqCst),
        skipped: progress.skipped.load(Ordering::SeqCst),
        errors: progress.errors.load(Ordering::SeqCst),
    })
}
