//! `bosun scan`: a headless scan for CI. It crawls a URL (or reads an API definition or a HAR file), runs the
//! active scanner over what it found, prints the findings, optionally writes a SARIF file, and sets the exit
//! code from a severity threshold.
//!
//! Without `--server` (or `$BOSUN_SERVER`) it runs an engine inside the process, in a throwaway data directory,
//! listening on loopback only; with one it drives that engine through the API and adds the target to its scope.
//! Either way the scope gate decides every request: the scope is the target's host (plus `--also-scope`).
//!
//! Exit codes: 0 nothing at or above the threshold, 1 error, 2 findings at or above the threshold, 4 the scan did
//! not finish (failed, stopped or timed out).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bosun_client::Client;
use bosun_client::{Scheme, ScopeRule as RuleSpec, ScopeSpec};
use serde_json::{Value, json};

use crate::{Config, Engine};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FailOn {
    /// Never fail on findings.
    None,
    Info,
    Low,
    Medium,
    High,
}

impl FailOn {
    /// The lowest severity (1 info .. 4 high) that fails the run; 5 never.
    fn rank(self) -> u8 {
        match self {
            FailOn::Info => 1,
            FailOn::Low => 2,
            FailOn::Medium => 3,
            FailOn::High => 4,
            FailOn::None => 5,
        }
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

#[derive(clap::Args, Debug)]
pub struct ScanArgs {
    /// The site to scan (`http` or `https`). It is crawled, and its host becomes the scope. Optional with --import
    /// when --base-url is given.
    pub url: Option<String>,
    /// Scan the requests of this API definition or recording instead of crawling (`-` reads stdin).
    #[arg(long)]
    pub import: Option<PathBuf>,
    /// Format of --import.
    #[arg(long, default_value = "openapi", value_parser = ["openapi", "graphql", "postman", "har", "urls", "burp"])]
    pub import_format: String,
    /// The server to use when the imported file has none or to override it; its host is the scope.
    #[arg(long)]
    pub base_url: Option<String>,
    /// Scan a running engine instead of one inside this process (else $BOSUN_SERVER, else a profile).
    #[arg(long)]
    pub server: Option<String>,
    /// The saved profile to use with --server.
    #[arg(long)]
    pub profile: Option<String>,
    /// Exit 2 when a finding is at or above this severity.
    #[arg(long, value_enum, default_value = "high")]
    pub fail_on: FailOn,
    /// Write the issues as a SARIF 2.1.0 file here.
    #[arg(long)]
    pub sarif: Option<PathBuf>,
    /// Write the scan result (findings and counts) as JSON here.
    #[arg(long)]
    pub json: Option<PathBuf>,
    /// low, medium or high: more insertion points and probes.
    #[arg(long, value_parser = ["low", "medium", "high"], default_value = "medium")]
    pub strength: String,
    /// Run only these check ids (repeatable; `GET /scan/checks` lists them); default all.
    #[arg(long = "check")]
    pub checks: Vec<String>,
    /// The most requests the scan may send.
    #[arg(long, default_value_t = 5000)]
    pub max_requests: u64,
    #[arg(long, default_value_t = 4)]
    pub concurrency: u32,
    /// Crawl depth.
    #[arg(long, default_value_t = 3)]
    pub max_depth: u32,
    /// Most pages the crawl fetches.
    #[arg(long, default_value_t = 200)]
    pub max_pages: u32,
    /// Do not crawl: scan only the URL itself.
    #[arg(long)]
    pub no_crawl: bool,
    /// Also scan POST forms found by the crawl (and let the crawl submit them). They can change data on the target.
    #[arg(long)]
    pub post_forms: bool,
    /// Extra header for every request, `Name: value` (repeatable), such as an Authorization header.
    #[arg(short = 'H', long = "header")]
    pub headers: Vec<String>,
    /// Let the scope reach loopback and private addresses (needed for a service on localhost or in a CI network).
    #[arg(long)]
    pub allow_private: bool,
    /// Another host to put in the scope, a glob such as `api.example.com` (repeatable).
    #[arg(long)]
    pub also_scope: Vec<String>,
    /// Verify TLS certificates of the target.
    #[arg(long)]
    pub verify_tls: bool,
    /// Stop the scan after this many seconds (exit 4 unless a finding already reaches the threshold).
    #[arg(long)]
    pub timeout: Option<u64>,
    /// No progress lines on stderr.
    #[arg(long)]
    pub quiet: bool,
}

/// The engine we talk to: ours (stopped at the end) or somebody else's.
struct Session {
    client: Client,
    engine: Option<Engine>,
    _dir: Option<tempfile::TempDir>,
}

async fn connect(a: &ScanArgs, mut cfg: Config, data_dir: Option<PathBuf>) -> Result<Session> {
    if a.server.is_some() || a.profile.is_some() || std::env::var_os("BOSUN_SERVER").is_some() {
        let (url, token) = crate::client_cmd::resolve(a.server.as_deref(), a.profile.as_deref())?;
        return Ok(Session {
            client: crate::client_cmd::client(&url, token)?,
            engine: None,
            _dir: None,
        });
    }
    let dir = match data_dir {
        Some(d) => {
            cfg.data_dir = Some(d);
            None
        }
        None => {
            let t = tempfile::tempdir().context("could not make a data directory")?;
            cfg.data_dir = Some(t.path().to_path_buf());
            Some(t)
        }
    };
    cfg.proxy.listen = ([127, 0, 0, 1], 0).into();
    cfg.api.listen = ([127, 0, 0, 1], 0).into();
    cfg.api.tls = false;
    cfg.metrics_listen = None;
    cfg.proxy.validate().map_err(anyhow::Error::msg)?;
    let engine = Engine::start_with(&cfg, true).await?;
    let client = Client::new(engine.api_url())?;
    let ticket = engine
        .login_ticket
        .clone()
        .context("the engine gave no login ticket")?;
    client.login_ticket(&ticket).await?;
    Ok(Session {
        client,
        engine: Some(engine),
        _dir: dir,
    })
}

fn rule_for(u: &url::Url, allow_private: bool) -> Result<RuleSpec> {
    let scheme = match u.scheme() {
        "http" => Some(Scheme::Http),
        "https" => Some(Scheme::Https),
        s => bail!("only http and https can be scanned, not {s}"),
    };
    Ok(RuleSpec {
        scheme,
        host: u
            .host_str()
            .context("the URL has no host")?
            .trim_matches(['[', ']'])
            .to_string(),
        port: u.port_or_known_default(),
        path: None,
        allow_private,
    })
}

fn target_json(method: &str, url: &str, headers: &[(String, String)], body: Option<String>) -> Value {
    let ct = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_string());
    // The engine finds insertion points in form and JSON bodies only.
    let ct = ct.filter(|c| c == "application/json" || c == "application/x-www-form-urlencoded");
    let hs: Vec<String> = headers
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("content-type") && !k.eq_ignore_ascii_case("content-length"))
        .map(|(k, v)| format!("{k}: {v}"))
        .collect();
    json!({ "method": method, "url": url, "headers": hs, "body": body, "content_type": ct })
}

/// A key for targets that would test the same thing: method, path and parameter names.
fn shape(method: &str, u: &url::Url) -> String {
    let mut names: Vec<String> = u.query_pairs().map(|(k, _)| k.into_owned()).collect();
    names.sort();
    format!(
        "{method} {}://{}:{}{}?{}",
        u.scheme(),
        u.host_str().unwrap_or(""),
        u.port_or_known_default().unwrap_or(0),
        u.path(),
        names.join("&")
    )
}

fn is_page(p: &Value) -> bool {
    let ok = p["status"].as_u64().is_some_and(|s| (200..400).contains(&s));
    let ct = p["content_type"].as_str().unwrap_or("").to_ascii_lowercase();
    ok && p["method"].as_str().unwrap_or("GET") == "GET"
        && (ct.is_empty() || ["html", "json", "xml", "text/plain"].iter().any(|k| ct.contains(k)))
}

/// What to scan after a crawl: its pages, its GET forms filled with their default values, and (on request) its
/// POST forms.
fn crawl_targets(done: &Value, post_forms: bool) -> Vec<Value> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut add = |method: &str, u: &str, body: Option<String>, ct: Option<&str>| {
        let Ok(parsed) = url::Url::parse(u) else { return };
        if !seen.insert(shape(method, &parsed)) {
            return;
        }
        let headers: Vec<(String, String)> = ct
            .map(|c| vec![("Content-Type".to_string(), c.to_string())])
            .unwrap_or_default();
        out.push(target_json(method, u, &headers, body));
    };
    for p in done["results"].as_array().into_iter().flatten().filter(|p| is_page(p)) {
        if let Some(u) = p["url"].as_str() {
            add("GET", u, None, None);
        }
    }
    for f in done["forms"].as_array().into_iter().flatten() {
        let Some(action) = f["action"].as_str() else { continue };
        let method = f["method"].as_str().unwrap_or("GET").to_ascii_uppercase();
        let pairs: Vec<(&str, &str)> = f["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| Some((x["name"].as_str()?, x["value"].as_str().unwrap_or(""))))
            .filter(|(n, _)| !n.is_empty())
            .collect();
        let enc = f["enctype"].as_str().unwrap_or("");
        if method == "GET" {
            let Ok(mut u) = url::Url::parse(action) else { continue };
            u.set_query(None);
            u.query_pairs_mut().extend_pairs(pairs.iter().copied());
            add("GET", u.as_str(), None, None);
        } else if method == "POST" && post_forms && !enc.contains("multipart") {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs.iter().copied())
                .finish();
            add("POST", action, Some(body), Some("application/x-www-form-urlencoded"));
        }
    }
    out
}

fn import_targets(a: &ScanArgs, path: &PathBuf) -> Result<(Vec<Value>, Vec<String>)> {
    let raw = if path.as_os_str() == "-" {
        let mut b = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut b)?;
        b
    } else {
        std::fs::read(path).with_context(|| format!("could not read {}", path.display()))?
    };
    let format: bosun_import::Format = a.import_format.parse().map_err(anyhow::Error::msg)?;
    let opts = bosun_import::Options {
        base_url: a.base_url.clone(),
    };
    let got = bosun_import::parse(format, &raw, &opts).context("could not import the file")?;
    let targets = got
        .items
        .iter()
        .map(|i| {
            let body = (!i.body.is_empty()).then(|| String::from_utf8_lossy(&i.body).into_owned());
            target_json(&i.method, &i.url, &i.headers, body)
        })
        .collect();
    Ok((targets, got.notes))
}

async fn wait_crawl(c: &Client, id: u64, limit: Option<Instant>) -> Result<Value> {
    loop {
        let d = c.crawl_get(id, 0).await?;
        if d["state"].as_str() != Some("running") {
            return Ok(d);
        }
        if limit.is_some_and(|t| Instant::now() > t) {
            let _ = c.crawl_stop(id).await;
            bail!("timed out while crawling");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub async fn run(a: ScanArgs, cfg: Config, data_dir: Option<PathBuf>) -> Result<ExitCode> {
    let base = match (&a.url, &a.base_url) {
        (Some(u), _) => u.clone(),
        (None, Some(b)) if a.import.is_some() => b.clone(),
        _ => bail!("give the URL to scan (or --import FILE with --base-url)"),
    };
    let base = url::Url::parse(&base).with_context(|| format!("not a URL: {base}"))?;
    let mut rules = vec![rule_for(&base, a.allow_private)?];
    for h in &a.also_scope {
        rules.push(RuleSpec {
            scheme: None,
            host: h.clone(),
            port: None,
            path: None,
            allow_private: a.allow_private,
        });
    }
    let imported = match &a.import {
        Some(p) => {
            let (t, notes) = import_targets(&a, p)?;
            for n in notes {
                eprintln!("import: skipped: {n}");
            }
            Some(t)
        }
        None => None,
    };
    let limit = a.timeout.map(|s| Instant::now() + Duration::from_secs(s));

    let sess = connect(&a, cfg, data_dir).await?;
    let result = scan(&a, &sess.client, rules, &base, imported, limit).await;
    if let Some(e) = sess.engine {
        e.shutdown().await;
    }
    result
}

async fn scan(
    a: &ScanArgs,
    c: &Client,
    rules: Vec<RuleSpec>,
    base: &url::Url,
    imported: Option<Vec<Value>>,
    limit: Option<Instant>,
) -> Result<ExitCode> {
    // The scope: this host, added to whatever an engine we did not start already allows.
    let mut spec: ScopeSpec = c.scope().await?;
    for r in rules {
        if !spec.include.contains(&r) {
            spec.include.push(r);
        }
    }
    c.put_scope(&spec).await?;

    let mut targets = match imported {
        Some(t) => t,
        None if a.no_crawl => vec![target_json("GET", base.as_str(), &[], None)],
        None => {
            let started = c
                .crawl_start(&json!({
                    "start": [base.as_str()], "max_depth": a.max_depth, "max_pages": a.max_pages,
                    "submit_post_forms": a.post_forms, "headers": a.headers, "verify_tls": a.verify_tls,
                }))
                .await?;
            let id = started["id"].as_u64().context("the engine did not return a crawl id")?;
            if !a.quiet {
                eprintln!("crawling {base}");
            }
            let done = wait_crawl(c, id, limit).await?;
            if done["state"].as_str() == Some("failed") {
                bail!("the crawl failed: {}", done["error"].as_str().unwrap_or("unknown error"));
            }
            let mut found = crawl_targets(&done, a.post_forms);
            if !a.quiet {
                eprintln!(
                    "crawled {} pages, {} to scan",
                    done["results"].as_array().map_or(0, Vec::len),
                    found.len()
                );
            }
            // The start page is always tested, even when the crawl could not read it.
            if found.is_empty() {
                found.push(target_json("GET", base.as_str(), &[], None));
            }
            found
        }
    };
    targets.truncate(2000);

    let started = c
        .scan_start(&json!({
            "targets": targets, "checks": a.checks, "strength": a.strength,
            "concurrency": a.concurrency, "max_requests": a.max_requests,
            "headers": a.headers, "verify_tls": a.verify_tls,
        }))
        .await?;
    let id = started["id"].as_u64().context("the engine did not return a scan id")?;
    let mut last_line = String::new();
    let mut last_print = Instant::now() - Duration::from_secs(10);
    let mut timed_out = false;
    let detail = loop {
        let d = c.scan_get(id).await?;
        let state = d["state"].as_str().unwrap_or("?").to_string();
        if !a.quiet {
            let line = format!(
                "scan {id}: {state} {}/{} units, {} requests, {} findings",
                d["units_done"], d["units_total"], d["requests"], d["findings"]
            );
            if line != last_line && (last_print.elapsed() >= Duration::from_secs(2) || state != "running") {
                eprintln!("{line}");
                last_line = line;
                last_print = Instant::now();
            }
        }
        if state != "running" && state != "paused" {
            break d;
        }
        if !timed_out && limit.is_some_and(|t| Instant::now() > t) {
            timed_out = true;
            eprintln!("error: the scan timed out; stopping it");
            let _ = c.scan_stop(id).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    };
    finish(a, c, &detail, timed_out).await
}

async fn finish(a: &ScanArgs, c: &Client, d: &Value, timed_out: bool) -> Result<ExitCode> {
    let findings = d["results"].as_array().cloned().unwrap_or_default();
    for f in &findings {
        println!(
            "{:<6} {} {} [{}] {}",
            f["severity"].as_str().unwrap_or("?").to_ascii_uppercase(),
            f["check"].as_str().unwrap_or("?"),
            f["url"].as_str().unwrap_or("?"),
            f["point"].as_str().unwrap_or("?"),
            f["title"].as_str().unwrap_or("")
        );
    }
    let refused = d["refused"].as_array().map_or(0, Vec::len);
    if refused > 0 {
        eprintln!("{refused} target(s) outside the scope were not contacted");
    }
    if d["truncated"] == true {
        eprintln!("the request limit ended the scan with work left; raise --max-requests");
    }
    if let Some(p) = &a.json {
        std::fs::write(p, serde_json::to_string_pretty(d)? + "\n")
            .with_context(|| format!("could not write {}", p.display()))?;
    }
    if let Some(p) = &a.sarif {
        let bytes = c
            .issues_report(&bosun_client::IssueQuery::default(), "sarif", true)
            .await?;
        std::fs::write(p, &bytes).with_context(|| format!("could not write {}", p.display()))?;
    }
    let worst = findings
        .iter()
        .map(|f| severity_rank(f["severity"].as_str().unwrap_or("info")))
        .max()
        .unwrap_or(0);
    let state = d["state"].as_str().unwrap_or("?");
    eprintln!("{} findings, scan {state}", findings.len());
    // Findings that reach the threshold count even when the scan did not finish.
    if worst >= a.fail_on.rank() {
        return Ok(ExitCode::from(2));
    }
    if timed_out || state != "done" {
        if let Some(e) = d["error"].as_str() {
            eprintln!("error: {e}");
        }
        return Ok(ExitCode::from(4));
    }
    Ok(ExitCode::SUCCESS)
}
