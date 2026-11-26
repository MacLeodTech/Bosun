//! The HTTP spider.
//!
//! Starts from one or more URLs and follows links, frames, redirects and forms, reads `robots.txt` and sitemaps,
//! and stays inside the scope, the depth and the page limit it is given.
//!
//! Every request, including `robots.txt` and sitemaps, goes through [`bosun_http::Engine::send`], so
//! [`bosun_scope::Gate::check`] decides it first: a link to a host outside the scope is never requested (and is
//! listed in [`Report::out_of_scope`]), the kill switch ends the crawl, and the gate's per-host rate limit is
//! waited out, never worked around. Redirects are not followed by the engine: a `Location` is just another link,
//! queued and checked like the rest.
//!
//! Nothing here runs script. Links that only a browser can find are for the browser crawler.

mod html;
mod robots;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bosun_http::redirect::{self, Url};
use bosun_http::{Engine, Exchange, SendError, SendOptions};
use bosun_model::{FlowSource, RawResponse, Scheme, Target};
use bosun_scope::ScopeError;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

pub use html::{Doc, Field, Link, LinkKind, RawForm, scan, sitemap_locs};
pub use robots::Robots;

/// How long a request waits for the gate's rate limit before it gives up.
const RATE_WAIT: Duration = Duration::from_secs(60);
/// Sitemap files read per origin, so a sitemap index cannot keep the crawl busy.
const MAX_SITEMAPS: usize = 20;

#[derive(Debug, thiserror::Error)]
pub enum CrawlError {
    #[error("not a usable start URL: {0}")]
    BadStart(String),
    #[error("{0}")]
    BadOption(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    /// Where to begin: absolute `http` or `https` URLs.
    pub start: Vec<String>,
    /// Links followed from a start URL: 0 fetches only the start URLs.
    pub max_depth: u32,
    /// Most requests for pages (robots and sitemap files not counted).
    pub max_pages: u32,
    /// Requests in flight at once (1 to 32). The gate's per-host rate limit applies on top.
    pub concurrency: u32,
    /// The least time between the starts of two requests, milliseconds.
    pub delay_ms: u64,
    /// Do not fetch what `robots.txt` disallows (it is still listed in the report).
    pub respect_robots: bool,
    /// Read sitemaps (named in `robots.txt`, or `/sitemap.xml`) and queue what they list.
    pub use_sitemap: bool,
    /// Follow `script`, `img` and similar sources too.
    pub follow_resources: bool,
    /// Send `GET` forms with the values the page gives them.
    pub submit_get_forms: bool,
    /// Send `POST` forms with their default values. Off: a form can change data, so this is the tester's call.
    pub submit_post_forms: bool,
    /// Extra request headers, such as `Cookie` or `Authorization`, sent to every request.
    pub headers: Vec<(String, String)>,
    pub user_agent: String,
    pub verify_tls: bool,
    pub timeout_secs: u64,
    /// Response bytes kept (and read for links).
    pub max_body: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            start: Vec::new(),
            max_depth: 5,
            max_pages: 1000,
            concurrency: 5,
            delay_ms: 0,
            respect_robots: true,
            use_sitemap: true,
            follow_resources: true,
            submit_get_forms: true,
            submit_post_forms: false,
            headers: Vec::new(),
            user_agent: "bosun-crawler".into(),
            verify_tls: false,
            timeout_secs: 30,
            max_body: 2 * 1024 * 1024,
        }
    }
}

impl Options {
    pub fn validate(&self) -> Result<(), CrawlError> {
        let bad = |m: &str| Err(CrawlError::BadOption(m.to_string()));
        if self.start.is_empty() {
            return bad("give at least one start URL");
        }
        if !(1..=32).contains(&self.concurrency) {
            return bad("concurrency is 1 to 32");
        }
        if !(1..=1_000_000).contains(&self.max_pages) {
            return bad("max_pages is 1 to 1000000");
        }
        if self.max_depth > 100 {
            return bad("max_depth is at most 100");
        }
        if !(1..=300).contains(&self.timeout_secs) {
            return bad("timeout_secs is 1 to 300");
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

/// A page the crawl asked for, and what came back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    pub url: String,
    pub method: String,
    pub depth: u32,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub bytes: usize,
    pub title: Option<String>,
    /// The page (or `robots.txt`, or sitemap) that led here.
    pub found_on: Option<String>,
    /// Where a redirect pointed.
    pub location: Option<String>,
    /// Why there is no answer, or why it is partial.
    pub error: Option<String>,
}

/// A form seen on a page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormFound {
    pub page: String,
    /// The action, resolved against the page.
    pub action: String,
    pub method: String,
    pub enctype: String,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub pages: Vec<Page>,
    pub forms: Vec<FormFound>,
    /// Links that point outside the scope, or that the gate refused. Never requested.
    pub out_of_scope: Vec<String>,
    /// Links that `robots.txt` disallows. Not requested while `respect_robots` is on.
    pub robots_blocked: Vec<String>,
    /// Plain paths named by `Disallow` rules: often where the interesting things are.
    pub robots_paths: Vec<String>,
    /// URLs listed in sitemaps.
    pub sitemap_urls: Vec<String>,
    /// Requests sent, robots and sitemaps included.
    pub requests: u64,
    /// The crawl ended at the page limit with links left unvisited.
    pub truncated: bool,
    /// The crawl was stopped, or the gate's kill switch was on.
    pub stopped: bool,
}

/// Told about every exchange as it happens, so the caller can store it as a flow with [`FlowSource::Crawler`].
pub trait Sink: Send + Sync {
    fn exchange(&self, _exchange: &Exchange) {}
    fn page(&self, _page: &Page) {}
}

impl Sink for () {}

#[derive(Debug, Clone, Default)]
pub struct Stop(Arc<AtomicBool>);

impl Stop {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
enum Fail {
    Halt,
    Refused(String),
    Failed(String),
}

#[derive(Debug, Clone)]
struct Item {
    url: Url,
    depth: u32,
    found_on: Option<String>,
    /// Form body for a `POST` (and its content type is always urlencoded).
    body: Option<Vec<u8>>,
}

type Origin = (Scheme, String, u16);

fn origin(u: &Url) -> Origin {
    (u.scheme, u.host.clone(), u.port)
}

fn path_only(u: &Url) -> &str {
    u.path.split('?').next().unwrap_or("/")
}

fn show(u: &Url) -> String {
    format!("{}://{}{}", u.scheme.as_str(), u.authority(), u.path)
}

/// Resolve `link` against `base`; `None` for fragments, other schemes (`mailto:`, `javascript:`) and junk.
pub fn join(base: &Url, link: &str) -> Option<Url> {
    let link: String = link
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let link = link.trim();
    if link.is_empty() || link.starts_with('#') {
        return None;
    }
    if let Some(colon) = link.find(':')
        && !link[..colon].contains(['/', '?', '#'])
        && !link[..colon].eq_ignore_ascii_case("http")
        && !link[..colon].eq_ignore_ascii_case("https")
    {
        return None;
    }
    let mut u = redirect::resolve(&Target::new(base.scheme, &base.host, base.port), &base.path, link)?;
    u.host = u.host.to_ascii_lowercase();
    u.path = u
        .path
        .bytes()
        .map(|b| {
            if b <= b' '
                || b >= 0x7f
                || matches!(b, b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}')
            {
                format!("%{b:02X}")
            } else {
                (b as char).to_string()
            }
        })
        .collect();
    Some(u)
}

pub fn parse_url(s: &str) -> Option<Url> {
    let u = redirect::resolve(
        &Target::new(Scheme::Http, "x", 80),
        "/",
        s.trim().split_once("://").map(|_| s.trim())?,
    )?;
    join(&u, s)
}

fn form_encode(fields: &[(&str, &str)]) -> String {
    fn enc(s: &str, out: &mut String) {
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
    }
    let mut out = String::new();
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        enc(k, &mut out);
        out.push('=');
        enc(v, &mut out);
    }
    out
}

/// The body of a chunked message (a cut-off one yields what there is).
pub fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n")?;
        let size = std::str::from_utf8(&b[..eol]).ok()?.split(';').next()?.trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        b = &b[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        if b.len() < size {
            // Cut off at the response cap: keep what there is.
            out.extend_from_slice(b);
            return Some(out);
        }
        out.extend_from_slice(&b[..size]);
        b = b.get(size + 2..).unwrap_or(&[]);
    }
}

fn request(u: &Url, o: &Options, body: Option<&[u8]>) -> Vec<u8> {
    let target: String = u.path.clone();
    let mut r = format!(
        "{} {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: text/html,application/xhtml+xml,*/*;q=0.8\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        if body.is_some() { "POST" } else { "GET" },
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
    let mut out = r.into_bytes();
    out.extend_from_slice(body.unwrap_or(&[]));
    out
}

async fn fetch(
    engine: &Engine,
    u: &Url,
    o: &Options,
    body: Option<&[u8]>,
    stop: &Stop,
) -> Result<Exchange, Fail> {
    let send = SendOptions {
        source: FlowSource::Crawler,
        update_content_length: false,
        verify_tls: o.verify_tls,
        connect_timeout: Duration::from_secs(o.timeout_secs.min(15)),
        idle_timeout: Duration::from_secs(o.timeout_secs),
        total_timeout: Duration::from_secs(o.timeout_secs),
        max_response: o.max_body,
        reuse: false,
    };
    let raw = request(u, o, body);
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

/// The body of an exchange as text, if it is plain enough to read.
fn body_of(ex: &Exchange) -> Option<(RawResponse, Vec<u8>)> {
    let r = RawResponse::parse(&ex.response).ok()?;
    if r.header("content-encoding")
        .is_some_and(|v| !v.eq_ignore_ascii_case(b"identity"))
    {
        return Some((r, Vec::new()));
    }
    let chunked = r
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().windows(7).any(|w| w == b"chunked"));
    let body = if chunked {
        dechunk(&r.body).unwrap_or_default()
    } else {
        r.body.clone()
    };
    Some((r, body))
}

struct Crawler<'a> {
    engine: &'a Engine,
    opts: &'a Options,
    sink: &'a dyn Sink,
    stop: &'a Stop,
    queue: VecDeque<Item>,
    seen: HashSet<(Url, Option<Vec<u8>>)>,
    origins: HashMap<Origin, Robots>,
    out_of_scope: HashSet<String>,
    report: Report,
    planned: u32,
}

/// Crawl from `opts.start` and report what was found.
pub async fn crawl(
    engine: &Engine,
    opts: &Options,
    sink: &dyn Sink,
    stop: &Stop,
) -> Result<Report, CrawlError> {
    opts.validate()?;
    let mut c = Crawler {
        engine,
        opts,
        sink,
        stop,
        queue: VecDeque::new(),
        seen: HashSet::new(),
        origins: HashMap::new(),
        out_of_scope: HashSet::new(),
        report: Report::default(),
        planned: 0,
    };
    for s in &opts.start {
        let u = parse_url(s).ok_or_else(|| CrawlError::BadStart(s.clone()))?;
        c.enqueue(u, 0, None, None).await;
    }
    c.run().await;
    let mut out_of_scope: Vec<String> = c.out_of_scope.into_iter().collect();
    out_of_scope.sort();
    c.report.out_of_scope = out_of_scope;
    Ok(c.report)
}

impl Crawler<'_> {
    async fn run(&mut self) {
        let mut running: JoinSet<(Item, Result<Exchange, Fail>)> = JoinSet::new();
        let mut last_start: Option<Instant> = None;
        let delay = Duration::from_millis(self.opts.delay_ms);
        loop {
            while running.len() < self.opts.concurrency as usize && !self.stop.is_stopped() {
                let Some(item) = self.queue.pop_front() else { break };
                if let Some(t) = last_start {
                    let wait = delay.saturating_sub(t.elapsed());
                    if !wait.is_zero() {
                        tokio::time::sleep(wait).await;
                    }
                }
                last_start = Some(Instant::now());
                let (engine, opts, stop) = (self.engine.clone(), self.opts.clone(), self.stop.clone());
                running.spawn(async move {
                    let r = fetch(&engine, &item.url, &opts, item.body.as_deref(), &stop).await;
                    (item, r)
                });
            }
            let Some(done) = running.join_next().await else {
                break;
            };
            let Ok((item, result)) = done else { continue };
            self.finish(item, result).await;
            if self.report.stopped {
                running.abort_all();
                while running.join_next().await.is_some() {}
                break;
            }
        }
        if self.stop.is_stopped() {
            self.report.stopped = true;
        }
    }

    async fn finish(&mut self, item: Item, result: Result<Exchange, Fail>) {
        let mut page = Page {
            url: show(&item.url),
            method: if item.body.is_some() { "POST" } else { "GET" }.into(),
            depth: item.depth,
            status: None,
            content_type: None,
            bytes: 0,
            title: None,
            found_on: item.found_on.clone(),
            location: None,
            error: None,
        };
        let ex = match result {
            Ok(ex) => ex,
            Err(Fail::Halt) => {
                self.report.stopped = true;
                return;
            }
            Err(Fail::Refused(why)) => {
                // The gate said no: the link is out of scope (or resolves somewhere it must not go).
                let _ = why;
                self.out_of_scope.insert(page.url);
                return;
            }
            Err(Fail::Failed(why)) => {
                page.error = Some(why);
                self.sink.page(&page);
                self.report.pages.push(page);
                return;
            }
        };
        self.report.requests += 1;
        self.sink.exchange(&ex);
        page.status = ex.status;
        page.error = ex.error.clone();
        let parsed = body_of(&ex);
        let mut html = None;
        if let Some((r, body)) = parsed {
            page.bytes = body.len();
            page.content_type = r
                .header("content-type")
                .map(|v| String::from_utf8_lossy(v).trim().to_string());
            let is_html = page.content_type.as_deref().is_none_or(|t| {
                let t = t.to_ascii_lowercase();
                t.starts_with("text/html") || t.starts_with("application/xhtml")
            });
            if is_html && !body.is_empty() {
                html = Some(String::from_utf8_lossy(&body).into_owned());
            }
            if (300..400).contains(&r.status)
                && let Some(loc) = r.header("location")
            {
                let loc = String::from_utf8_lossy(loc).trim().to_string();
                if let Some(next) = join(&item.url, &loc) {
                    page.location = Some(show(&next));
                    // A redirect costs no depth: it is the same page under another name.
                    self.enqueue(next, item.depth, Some(page.url.clone()), None).await;
                }
            }
        }
        if let Some(text) = html {
            let doc = scan(&text);
            page.title = doc.title.clone();
            self.follow(&item, &page.url, doc).await;
        }
        self.sink.page(&page);
        self.report.pages.push(page);
    }

    async fn follow(&mut self, item: &Item, from: &str, doc: Doc) {
        if item.depth >= self.opts.max_depth {
            // Forms are still worth listing at the last level.
            self.record_forms(item, from, &doc, None);
            return;
        }
        let base = doc
            .base
            .as_deref()
            .and_then(|b| join(&item.url, b))
            .unwrap_or_else(|| item.url.clone());
        for l in &doc.links {
            if l.kind == LinkKind::Resource && !self.opts.follow_resources {
                continue;
            }
            if let Some(u) = join(&base, &l.target) {
                self.enqueue(u, item.depth + 1, Some(from.to_string()), None)
                    .await;
            }
        }
        let forms = self.record_forms(item, from, &doc, Some(&base));
        for (action, method, body) in forms {
            match (method.as_str(), body) {
                ("GET", Some(q)) if self.opts.submit_get_forms => {
                    let mut u = action;
                    u.path = format!("{}?{q}", path_only(&u));
                    self.enqueue(u, item.depth + 1, Some(from.to_string()), None)
                        .await;
                }
                ("POST", Some(q)) if self.opts.submit_post_forms => {
                    self.enqueue(
                        action,
                        item.depth + 1,
                        Some(from.to_string()),
                        Some(q.into_bytes()),
                    )
                    .await;
                }
                _ => {}
            }
        }
    }

    /// Record the forms of a page; with a base, also return `(action, method, encoded fields)` for the ones that
    /// can be sent as they are (urlencoded).
    fn record_forms(
        &mut self,
        item: &Item,
        from: &str,
        doc: &Doc,
        base: Option<&Url>,
    ) -> Vec<(Url, String, Option<String>)> {
        let base = base.unwrap_or(&item.url);
        let mut sendable = Vec::new();
        for f in &doc.forms {
            let action = if f.action.trim().is_empty() {
                Some(item.url.clone())
            } else {
                join(base, &f.action)
            };
            let Some(action) = action else { continue };
            let fields: Vec<(&str, &str)> = f
                .fields
                .iter()
                .filter(|f| f.submitted)
                .map(|f| (f.name.as_str(), f.value.as_str()))
                .collect();
            let encoded = f
                .enctype
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
                .then(|| form_encode(&fields));
            let found = FormFound {
                page: from.to_string(),
                action: show(&action),
                method: f.method.clone(),
                enctype: f.enctype.clone(),
                fields: f.fields.clone(),
            };
            if !self.report.forms.contains(&found) {
                self.report.forms.push(found);
            }
            sendable.push((action, f.method.clone(), encoded));
        }
        sendable
    }

    async fn enqueue(&mut self, url: Url, depth: u32, found_on: Option<String>, body: Option<Vec<u8>>) {
        let key = (url.clone(), body.clone());
        if self.seen.contains(&key) {
            return;
        }
        let name = show(&url);
        // The gate has the last word on every request; this only keeps out-of-scope links from being queued.
        if !self
            .engine
            .gate()
            .scope()
            .contains(url.scheme, &url.host, url.port, path_only(&url))
        {
            self.out_of_scope.insert(name);
            return;
        }
        self.seen.insert(key);
        self.ensure_origin(&url).await;
        let robots_wanted = self.opts.respect_robots;
        if robots_wanted
            && self
                .origins
                .get(&origin(&url))
                .is_some_and(|r| !r.allowed(&url.path))
        {
            self.report.robots_blocked.push(name);
            return;
        }
        if self.planned >= self.opts.max_pages {
            self.report.truncated = true;
            return;
        }
        self.planned += 1;
        self.queue.push_back(Item {
            url,
            depth,
            found_on,
            body,
        });
    }

    /// First time an origin is seen: read its `robots.txt` and sitemaps.
    async fn ensure_origin(&mut self, u: &Url) {
        let o = origin(u);
        if self.origins.contains_key(&o) {
            return;
        }
        self.origins.insert(o, Robots::default());
        if !self.opts.respect_robots && !self.opts.use_sitemap {
            return;
        }
        let root = Url {
            scheme: u.scheme,
            host: u.host.clone(),
            port: u.port,
            path: "/robots.txt".into(),
        };
        let mut robots = Robots::default();
        if let Some((text, status)) = self.get_text(&root).await
            && status == 200
        {
            robots = Robots::parse(&text);
            for p in robots.disallowed_paths() {
                let full = format!("{}://{}{p}", root.scheme.as_str(), root.authority());
                if !self.report.robots_paths.contains(&full) {
                    self.report.robots_paths.push(full);
                }
            }
        }
        let mut maps: VecDeque<Url> = robots.sitemaps.iter().filter_map(|s| join(&root, s)).collect();
        if maps.is_empty() {
            maps.extend(join(&root, "/sitemap.xml"));
        }
        self.origins.insert(origin(u), robots);
        if self.opts.use_sitemap {
            self.read_sitemaps(maps).await;
        }
    }

    async fn read_sitemaps(&mut self, mut maps: VecDeque<Url>) {
        let mut read = 0;
        let mut done = HashSet::new();
        while let Some(m) = maps.pop_front() {
            if read >= MAX_SITEMAPS || !done.insert(m.clone()) {
                continue;
            }
            if !self
                .engine
                .gate()
                .scope()
                .contains(m.scheme, &m.host, m.port, path_only(&m))
            {
                self.out_of_scope.insert(show(&m));
                continue;
            }
            read += 1;
            let Some((text, 200)) = self.get_text(&m).await else {
                continue;
            };
            let (locs, index) = sitemap_locs(&text);
            for l in locs {
                let Some(u) = join(&m, &l) else { continue };
                if index {
                    maps.push_back(u);
                } else {
                    let name = show(&u);
                    if !self.report.sitemap_urls.contains(&name) {
                        self.report.sitemap_urls.push(name.clone());
                    }
                    // Boxed: `enqueue` can reach here again through `ensure_origin`, and only for a new origin.
                    Box::pin(self.enqueue(u, self.opts.max_depth.min(1), Some(show(&m)), None)).await;
                }
            }
        }
    }

    async fn get_text(&mut self, u: &Url) -> Option<(String, u16)> {
        match fetch(self.engine, u, self.opts, None, self.stop).await {
            Ok(ex) => {
                self.report.requests += 1;
                self.sink.exchange(&ex);
                let (r, body) = body_of(&ex)?;
                Some((String::from_utf8_lossy(&body).into_owned(), r.status))
            }
            Err(Fail::Halt) => {
                self.report.stopped = true;
                None
            }
            Err(Fail::Refused(_)) => {
                self.out_of_scope.insert(show(u));
                None
            }
            Err(Fail::Failed(_)) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        parse_url("http://h.test:8080/a/b.html?x=1").unwrap()
    }

    #[test]
    fn joins_links() {
        let b = base();
        let j = |l| join(&b, l).map(|u| show(&u));
        assert_eq!(j("c.html").as_deref(), Some("http://h.test:8080/a/c.html"));
        assert_eq!(j("../d?q=1#f").as_deref(), Some("http://h.test:8080/d?q=1"));
        assert_eq!(j("//Other.test/x").as_deref(), Some("http://other.test/x"));
        assert_eq!(j("https://s.test/p q").as_deref(), Some("https://s.test/p%20q"));
        assert_eq!(j("/ro ot").as_deref(), Some("http://h.test:8080/ro%20ot"));
        assert_eq!(j("?y=2").as_deref(), Some("http://h.test:8080/a/b.html?y=2"));
        for no in [
            "mailto:a@b",
            "javascript:void(0)",
            "#top",
            "",
            "data:text/html,x",
            "tel:1",
        ] {
            assert_eq!(j(no), None, "{no}");
        }
    }

    #[test]
    fn rejects_bad_starts() {
        assert!(parse_url("ftp://x/").is_none());
        assert!(parse_url("/relative").is_none());
        assert!(parse_url("http://ok.test/").is_some());
    }

    #[test]
    fn dechunks() {
        assert_eq!(
            dechunk(b"3\r\nabc\r\n2;x=1\r\nde\r\n0\r\n\r\n").unwrap(),
            b"abcde"
        );
        assert_eq!(dechunk(b"5\r\nab").unwrap(), b"ab");
        assert!(dechunk(b"zz\r\n").is_none());
    }

    #[test]
    fn encodes_forms() {
        assert_eq!(form_encode(&[("a b", "c&d"), ("e", "")]), "a+b=c%26d&e=");
    }

    #[test]
    fn options_are_checked() {
        let ok = Options {
            start: vec!["http://x.test/".into()],
            ..Options::default()
        };
        assert!(ok.validate().is_ok());
        assert!(Options::default().validate().is_err());
        let mut bad = ok.clone();
        bad.headers = vec![("X".into(), "a\r\nEvil: 1".into())];
        assert!(bad.validate().is_err());
        bad = ok;
        bad.concurrency = 0;
        assert!(bad.validate().is_err());
    }
}
