//! Content and parameter discovery (forced browsing).
//!
//! [`discover`] tries a wordlist of paths (optionally with extensions, recursing into the directories it finds) or
//! of parameter names against one URL, and reports what answers differently from a request for something that
//! does not exist.
//!
//! "Differently" is learned, not assumed: before a directory is probed, a few random names that cannot exist are
//! requested. Their answers (status, size, a hash of the body with the probed name taken out) are the baseline, so
//! a site that answers 200 "not found" to everything (a soft 404) produces no hits, and a page whose size varies
//! gets a matching tolerance. Hits that share one answer are clustered, and a cluster of many is a wildcard, not a
//! find: it is counted in [`Report::noise`] and not listed.
//!
//! Every request goes through [`bosun_http::Engine::send`], so [`bosun_scope::Gate::check`] decides first, the kill
//! switch ends the run and the per-host rate limit is waited out. Only hits are shown to the [`Sink`] (to be stored
//! as flows), so thousands of 404s do not fill the history.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use bosun_crawl::{Stop, dechunk, parse_url};
use bosun_http::redirect::Url;
use bosun_http::{Engine, Exchange, SendError, SendOptions};
use bosun_model::{FlowSource, RawResponse, Target};
use bosun_scope::ScopeError;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

mod words;

pub use words::{PARAMS, PATHS};

const RATE_WAIT: Duration = Duration::from_secs(60);
/// Random names asked for to learn what "not found" looks like.
const BASELINES: usize = 3;
/// A cluster at least this big is a wildcard.
const NOISE_CLUSTER: usize = 8;
/// Failed requests in a row that end the run (the host is down or not talking).
const MAX_FAILS: u32 = 25;

#[derive(Debug, thiserror::Error)]
pub enum DiscoverError {
    #[error("not a usable URL: {0}")]
    BadUrl(String),
    #[error("{0}")]
    BadOption(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Paths below the URL (a directory).
    #[default]
    Paths,
    /// Parameter names on the URL.
    Params,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    /// Paths mode: the directory to probe (`http://host/` or `http://host/app/`). Params mode: the page.
    pub base: String,
    pub mode: Mode,
    /// Names to try. Empty: the built-in list for the mode.
    pub words: Vec<String>,
    /// Paths mode: also try each word with these endings (`php`, `bak`: written without the dot).
    pub extensions: Vec<String>,
    /// Paths mode: directories found are probed too, down to this depth (0: the base only).
    pub max_depth: u32,
    /// Most requests, baselines included.
    pub max_requests: u32,
    pub concurrency: u32,
    pub delay_ms: u64,
    /// Params mode: send the names in a `POST` body instead of the query.
    pub post: bool,
    pub headers: Vec<(String, String)>,
    pub user_agent: String,
    pub verify_tls: bool,
    pub timeout_secs: u64,
    pub max_body: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            base: String::new(),
            mode: Mode::Paths,
            words: Vec::new(),
            extensions: Vec::new(),
            max_depth: 2,
            max_requests: 5000,
            concurrency: 8,
            delay_ms: 0,
            post: false,
            headers: Vec::new(),
            user_agent: "bosun-discover".into(),
            verify_tls: false,
            timeout_secs: 20,
            max_body: 256 * 1024,
        }
    }
}

impl Options {
    pub fn validate(&self) -> Result<(), DiscoverError> {
        let bad = |m: &str| Err(DiscoverError::BadOption(m.to_string()));
        if !(1..=32).contains(&self.concurrency) {
            return bad("concurrency is 1 to 32");
        }
        if !(10..=1_000_000).contains(&self.max_requests) {
            return bad("max_requests is 10 to 1000000");
        }
        if self.max_depth > 10 {
            return bad("max_depth is at most 10");
        }
        if !(1..=300).contains(&self.timeout_secs) {
            return bad("timeout_secs is 1 to 300");
        }
        let word_ok = |w: &str| !w.is_empty() && !w.contains(['\r', '\n', '\0', ' ', '#', '?', '&', '=']);
        if self.words.iter().any(|w| !word_ok(w))
            || self.extensions.iter().any(|e| !word_ok(e) || e.contains('/'))
        {
            return bad("words and extensions are single tokens without spaces, #, ?, & or =");
        }
        let clean = |s: &str| !s.contains(['\r', '\n', '\0']);
        if !clean(&self.user_agent)
            || self
                .headers
                .iter()
                .any(|(k, v)| !clean(k) || !clean(v) || k.is_empty() || k.contains([':', ' ']))
        {
            return bad("headers and the user agent must be single lines");
        }
        Ok(())
    }
}

/// One thing that answered differently from "not found".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hit {
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
    /// How deep in the recursion (0 is the base).
    pub depth: u32,
    /// Why it stands out: `directory`, `reflected`, `size differs`, `status differs`.
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub hits: Vec<Hit>,
    pub requests: u64,
    /// Hits dropped because they came in a wildcard cluster.
    pub noise: u64,
    /// Directories probed (paths mode).
    pub directories: Vec<String>,
    /// The request limit ended the run with words left.
    pub truncated: bool,
    pub stopped: bool,
    /// Why the run ended early, if it did (a refused request, a host that does not answer).
    pub error: Option<String>,
}

/// Told about every hit as it is found, so the caller can store it as a flow.
pub trait Sink: Send + Sync {
    fn hit(&self, _exchange: &Exchange, _hit: &Hit) {}
    fn progress(&self, _requests: u64, _hits: usize) {}
}

impl Sink for () {}

/// What an answer looks like, with the probed name taken out so an echoed name does not make two answers differ.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sig {
    status: u16,
    len: usize,
    words: usize,
    hash: u64,
    location: Option<String>,
    content_type: Option<String>,
    reflected: bool,
}

fn signature(ex: &Exchange, needles: &[&str]) -> Option<Sig> {
    let r = RawResponse::parse(&ex.response).ok()?;
    let chunked = r
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().windows(7).any(|w| w == b"chunked"));
    let body = if chunked {
        dechunk(&r.body).unwrap_or_default()
    } else {
        r.body.clone()
    };
    let mut text = String::from_utf8_lossy(&body).into_owned();
    let reflected = needles.iter().any(|n| !n.is_empty() && text.contains(n));
    // Longest first, so the whole path goes before the name inside it.
    let mut needles: Vec<&str> = needles.iter().copied().filter(|n| !n.is_empty()).collect();
    needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
    for n in needles {
        text = text.replace(n, "");
    }
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    let header = |n: &str| r.header(n).map(|v| String::from_utf8_lossy(v).into_owned());
    Some(Sig {
        status: r.status,
        len: text.len(),
        words: text.split_whitespace().count(),
        hash: h.finish(),
        location: header("location"),
        content_type: header("content-type"),
        reflected,
    })
}

/// What "not found" looks like here.
#[derive(Debug, Default)]
struct Baseline {
    sigs: Vec<Sig>,
    /// How much the size of one kind of answer varies.
    tolerance: usize,
}

impl Baseline {
    fn new(sigs: Vec<Sig>) -> Self {
        let (min, max) = sigs
            .iter()
            .fold((usize::MAX, 0), |(lo, hi), s| (lo.min(s.len), hi.max(s.len)));
        let spread = if sigs.is_empty() { 0 } else { max - min };
        let big = sigs.iter().map(|s| s.len).max().unwrap_or(0);
        // Answers that are identical once the name is taken out need an identical answer to match. Only a page that
        // varies from request to request (a clock, a token) earns a tolerance.
        let steady = sigs.windows(2).all(|w| w[0].hash == w[1].hash);
        Self {
            tolerance: if steady {
                0
            } else {
                (spread * 2).max(16).max(big / 33)
            },
            sigs,
        }
    }

    /// The same answer as for a name that does not exist.
    fn matches(&self, s: &Sig) -> bool {
        self.sigs.iter().any(|b| {
            b.status == s.status
                && (b.hash == s.hash
                    || b.len.abs_diff(s.len) <= self.tolerance
                        && b.words.abs_diff(s.words) <= self.tolerance / 4 + 2)
        })
    }
}

#[derive(Debug)]
enum Fail {
    Halt,
    Refused(String),
    Failed(String),
}

fn build(u: &Url, o: &Options, body: Option<&str>) -> Vec<u8> {
    let mut r = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        if body.is_some() { "POST" } else { "GET" },
        u.path,
        u.authority(),
        o.user_agent
    );
    for (k, v) in &o.headers {
        r.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        r.push_str(&format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    r.push_str("\r\n");
    r.push_str(body.unwrap_or(""));
    r.into_bytes()
}

async fn fetch(
    engine: &Engine,
    u: &Url,
    o: &Options,
    body: Option<String>,
    stop: &Stop,
) -> Result<Exchange, Fail> {
    let raw = build(u, o, body.as_deref());
    let send = SendOptions {
        source: FlowSource::Intruder,
        update_content_length: false,
        verify_tls: o.verify_tls,
        connect_timeout: Duration::from_secs(o.timeout_secs.min(15)),
        idle_timeout: Duration::from_secs(o.timeout_secs),
        total_timeout: Duration::from_secs(o.timeout_secs),
        max_response: o.max_body,
        reuse: false,
    };
    let target = Target::new(u.scheme, &u.host, u.port);
    let started = Instant::now();
    loop {
        if stop.is_stopped() {
            return Err(Fail::Halt);
        }
        match engine.send(&target, &raw, &send).await {
            Ok(ex) => return Ok(ex),
            Err(SendError::Refused(ScopeError::RateLimited(..))) => {
                if started.elapsed() > RATE_WAIT {
                    return Err(Fail::Failed("waited a minute for the rate limit".into()));
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(SendError::Refused(ScopeError::Stopped)) => return Err(Fail::Halt),
            Err(SendError::Refused(e)) => return Err(Fail::Refused(e.to_string())),
            Err(e) => return Err(Fail::Failed(e.to_string())),
        }
    }
}

/// A name that cannot exist, different every time.
fn random_name(n: usize) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    n.hash(&mut h);
    std::thread::current().id().hash(&mut h);
    format!("bosun{:012x}", h.finish() & 0xffff_ffff_ffff)
}

/// The query separator for `path`.
fn with_query(path: &str, name: &str, value: &str) -> String {
    format!(
        "{path}{}{name}={value}",
        if path.contains('?') { '&' } else { '?' }
    )
}

fn show(u: &Url) -> String {
    format!("{}://{}{}", u.scheme.as_str(), u.authority(), u.path)
}

/// One request to make, and what it was for.
#[derive(Debug, Clone)]
struct Job {
    url: Url,
    body: Option<String>,
    word: String,
    needles: Vec<String>,
    depth: u32,
}

struct Run<'a> {
    engine: &'a Engine,
    opts: &'a Options,
    sink: &'a dyn Sink,
    stop: &'a Stop,
    report: Report,
    fails: u32,
    planned: u64,
}

impl Run<'_> {
    fn room(&self) -> u64 {
        u64::from(self.opts.max_requests).saturating_sub(self.planned)
    }

    /// Send `jobs` with the run's concurrency and delay; the answers come back with their jobs.
    async fn send_all(&mut self, jobs: Vec<Job>) -> Vec<(Job, Option<Exchange>)> {
        let mut out = Vec::new();
        let mut queue = jobs.into_iter();
        let mut running: JoinSet<(Job, Result<Exchange, Fail>)> = JoinSet::new();
        let mut last: Option<Instant> = None;
        let delay = Duration::from_millis(self.opts.delay_ms);
        loop {
            while running.len() < self.opts.concurrency as usize
                && !self.stop.is_stopped()
                && self.report.error.is_none()
            {
                if self.room() == 0 {
                    if queue.len() > 0 {
                        self.report.truncated = true;
                    }
                    break;
                }
                let Some(job) = queue.next() else { break };
                if let Some(t) = last {
                    let wait = delay.saturating_sub(t.elapsed());
                    if !wait.is_zero() {
                        tokio::time::sleep(wait).await;
                    }
                }
                last = Some(Instant::now());
                self.planned += 1;
                let (engine, opts, stop) = (self.engine.clone(), self.opts.clone(), self.stop.clone());
                running.spawn(async move {
                    let r = fetch(&engine, &job.url, &opts, job.body.clone(), &stop).await;
                    (job, r)
                });
            }
            let Some(done) = running.join_next().await else {
                break;
            };
            let Ok((job, result)) = done else { continue };
            self.report.requests += 1;
            match result {
                Ok(ex) => {
                    self.fails = 0;
                    out.push((job, Some(ex)));
                }
                Err(Fail::Halt) => self.report.stopped = true,
                Err(Fail::Refused(why)) => {
                    // The same gate decides for every request to this host: stop rather than ask a thousand times.
                    self.report.error.get_or_insert(format!("refused: {why}"));
                }
                Err(Fail::Failed(why)) => {
                    self.fails += 1;
                    if self.fails >= MAX_FAILS {
                        self.report
                            .error
                            .get_or_insert(format!("the host is not answering ({why})"));
                    }
                    out.push((job, None));
                }
            }
            if self.stop.is_stopped() {
                self.report.stopped = true;
            }
            self.sink.progress(self.report.requests, self.report.hits.len());
            if self.report.stopped || self.report.error.is_some() {
                running.abort_all();
                while running.join_next().await.is_some() {}
                break;
            }
        }
        out
    }

    async fn baseline(&mut self, jobs: Vec<Job>) -> Option<Baseline> {
        let answers = self.send_all(jobs).await;
        let sigs: Vec<Sig> = answers
            .iter()
            .filter_map(|(j, ex)| {
                let needles: Vec<&str> = j.needles.iter().map(String::as_str).collect();
                signature(ex.as_ref()?, &needles)
            })
            .collect();
        if sigs.is_empty() {
            if self.report.error.is_none() && !self.report.stopped {
                self.report.error = Some("the host did not answer the baseline requests".into());
            }
            return None;
        }
        Some(Baseline::new(sigs))
    }

    /// Cluster the answers, drop wildcard clusters, record the rest.
    fn record(&mut self, found: Vec<(Job, Exchange, Sig)>, kind: &str) -> Vec<(Job, Sig)> {
        let mut clusters: HashMap<(u16, u64), Vec<usize>> = HashMap::new();
        for (i, (_, _, s)) in found.iter().enumerate() {
            clusters.entry((s.status, s.hash)).or_default().push(i);
        }
        let mut numbered: Vec<_> = clusters.into_iter().collect();
        numbered.sort_by_key(|(_, v)| v[0]);
        let mut keep = Vec::new();
        let mut cluster_of = vec![0u32; found.len()];
        for (n, (_, members)) in numbered.iter().enumerate() {
            if members.len() >= NOISE_CLUSTER {
                self.report.noise += members.len() as u64;
                continue;
            }
            for &m in members {
                cluster_of[m] = n as u32 + 1;
                keep.push(m);
            }
        }
        keep.sort_unstable();
        let mut dirs = Vec::new();
        for i in keep {
            let (job, ex, sig) = &found[i];
            let dir = kind == "path" && is_dir(job, sig);
            let note = if kind == "param" {
                Some(
                    if sig.reflected {
                        "reflected"
                    } else {
                        "answer differs"
                    }
                    .to_string(),
                )
            } else if dir {
                Some("directory".to_string())
            } else {
                None
            };
            let hit = Hit {
                kind: kind.into(),
                url: show(&job.url),
                word: job.word.clone(),
                status: sig.status,
                bytes: sig.len,
                words: sig.words,
                content_type: sig.content_type.clone(),
                location: sig.location.clone(),
                cluster: cluster_of[i],
                depth: job.depth,
                note,
            };
            self.sink.hit(ex, &hit);
            self.report.hits.push(hit);
            if dir {
                dirs.push((job.clone(), sig.clone()));
            }
        }
        dirs
    }
}

/// A hit that is a directory: the word ends in `/`, or the server sends it to the same path with a `/`.
fn is_dir(job: &Job, sig: &Sig) -> bool {
    if job.word.ends_with('/') {
        return true;
    }
    let (Some(loc), true) = (&sig.location, (300..400).contains(&sig.status)) else {
        return false;
    };
    let path = job.url.path.split('?').next().unwrap_or("");
    loc.split('?').next().unwrap_or("").ends_with(&format!("{path}/"))
}

/// Discover content or parameters on `opts.base`.
pub async fn discover(
    engine: &Engine,
    opts: &Options,
    sink: &dyn Sink,
    stop: &Stop,
) -> Result<Report, DiscoverError> {
    opts.validate()?;
    let base = parse_url(&opts.base).ok_or_else(|| DiscoverError::BadUrl(opts.base.clone()))?;
    let mut run = Run {
        engine,
        opts,
        sink,
        stop,
        report: Report::default(),
        fails: 0,
        planned: 0,
    };
    match opts.mode {
        Mode::Paths => run.paths(base).await,
        Mode::Params => run.params(base).await,
    }
    Ok(run.report)
}

impl Run<'_> {
    async fn paths(&mut self, base: Url) {
        let words: Vec<String> = if self.opts.words.is_empty() {
            PATHS.iter().map(|s| (*s).to_string()).collect()
        } else {
            self.opts.words.clone()
        };
        let mut dir = base.clone();
        if !dir.path.ends_with('/') {
            dir.path.push('/');
        }
        dir.path = dir.path.split('?').next().unwrap_or("/").to_string();
        let mut todo = vec![(dir, 0u32)];
        let mut seen: HashSet<String> = HashSet::new();
        while let Some((dir, depth)) = todo.pop() {
            if self.stop.is_stopped() || self.report.error.is_some() || self.room() == 0 {
                self.report.truncated |= self.room() == 0 && !todo.is_empty();
                break;
            }
            if !seen.insert(dir.path.clone()) {
                continue;
            }
            self.report.directories.push(show(&dir));
            let at = |name: &str| {
                let mut u = dir.clone();
                u.path = format!("{}{name}", dir.path);
                u
            };
            // What "not found" looks like in this directory: a random name, and one with each extension.
            let mut base_jobs: Vec<Job> = (0..BASELINES)
                .map(|i| {
                    let n = random_name(i);
                    let url = at(&n);
                    Job {
                        needles: vec![n.clone(), url.path.clone()],
                        url,
                        body: None,
                        word: n,
                        depth,
                    }
                })
                .collect();
            for e in &self.opts.extensions {
                let n = random_name(base_jobs.len());
                let url = at(&format!("{n}.{e}"));
                base_jobs.push(Job {
                    needles: vec![n.clone(), url.path.clone()],
                    url,
                    body: None,
                    word: n,
                    depth,
                });
            }
            let Some(baseline) = self.baseline(base_jobs).await else {
                break;
            };
            let mut jobs = Vec::new();
            for w in &words {
                let w = w.trim_start_matches('/');
                if w.is_empty() {
                    continue;
                }
                let bare = w.trim_end_matches('/');
                let mut names = vec![w.to_string()];
                if !w.ends_with('/') {
                    names.extend(self.opts.extensions.iter().map(|e| format!("{w}.{e}")));
                }
                for n in names {
                    let url = at(&n);
                    jobs.push(Job {
                        needles: vec![bare.to_string(), url.path.clone()],
                        url,
                        body: None,
                        word: n,
                        depth,
                    });
                }
            }
            let answers = self.send_all(jobs).await;
            let found: Vec<(Job, Exchange, Sig)> = answers
                .into_iter()
                .filter_map(|(j, ex)| {
                    let ex = ex?;
                    let needles: Vec<&str> = j.needles.iter().map(String::as_str).collect();
                    let sig = signature(&ex, &needles)?;
                    let gone = matches!(sig.status, 404 | 410 | 429 | 503);
                    (!gone && !baseline.matches(&sig)).then_some((j, ex, sig))
                })
                .collect();
            let dirs = self.record(found, "path");
            if depth < self.opts.max_depth {
                for (job, _) in dirs.into_iter().rev() {
                    let mut u = job.url.clone();
                    if !u.path.ends_with('/') {
                        u.path.push('/');
                    }
                    todo.push((u, depth + 1));
                }
            }
        }
    }

    async fn params(&mut self, base: Url) {
        let words: Vec<String> = if self.opts.words.is_empty() {
            PARAMS.iter().map(|s| (*s).to_string()).collect()
        } else {
            self.opts.words.clone()
        };
        const VALUE: &str = "bosunval1";
        let post = self.opts.post;
        let make = |name: &str, depth: u32| {
            let mut u = base.clone();
            let body = if post {
                Some(format!("{name}={VALUE}"))
            } else {
                u.path = with_query(&u.path, name, VALUE);
                None
            };
            Job {
                url: u,
                body,
                word: name.to_string(),
                needles: vec![name.to_string(), VALUE.to_string()],
                depth,
            }
        };
        self.report.directories.push(show(&base));
        let base_jobs: Vec<Job> = (0..BASELINES).map(|i| make(&random_name(i), 0)).collect();
        let Some(baseline) = self.baseline(base_jobs).await else {
            return;
        };
        let jobs: Vec<Job> = words.iter().map(|w| make(w, 0)).collect();
        let answers = self.send_all(jobs).await;
        let found: Vec<(Job, Exchange, Sig)> = answers
            .into_iter()
            .filter_map(|(j, ex)| {
                let ex = ex?;
                let needles: Vec<&str> = j.needles.iter().map(String::as_str).collect();
                let sig = signature(&ex, &needles)?;
                // A parameter the page reads changes the answer; one that is only echoed does not count by itself
                // (the baselines echo their random names too), so `reflected` is a note, not the reason.
                (!baseline.matches(&sig)).then_some((j, ex, sig))
            })
            .collect();
        self.record(found, "param");
    }
}
