//! Client commands on the engine's data: history, scope, rules, intercept, the CA and the event stream.
//! Output is a table, `--json` (one document) or `--ndjson` (one JSON value per line); `--quiet` drops headers,
//! notes and confirmations. Exit codes: 0 done, 1 error, 2 bad usage, 3 the scope gate refused, 4 nothing found.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bosun_client::{
    Client, Decision, Event, FlowQuery, FlowSummary, InterceptSettings, MatchRule, Part, ScopeRule, ScopeSpec,
};
use serde_json::{Value, json};

use crate::client_cmd::{client, resolve};

/// How to print, and how much.
#[derive(clap::Args, Debug, Clone, Copy)]
pub struct Out {
    /// One JSON document.
    #[arg(long, global = true, conflicts_with = "ndjson")]
    pub json: bool,
    /// One JSON value per line.
    #[arg(long, global = true)]
    pub ndjson: bool,
    /// No headers, notes or confirmations.
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

impl Out {
    fn note(&self, s: impl std::fmt::Display) {
        if !self.quiet {
            eprintln!("{s}");
        }
    }

    fn machine(&self) -> bool {
        self.json || self.ndjson
    }

    /// Print rows: a table by default, a JSON array, or one object per line.
    fn rows(&self, head: &[&str], values: &[Value], cells: impl Fn(&Value) -> Vec<String>) {
        if self.json {
            println!("{}", Value::Array(values.to_vec()));
        } else if self.ndjson {
            for v in values {
                println!("{v}");
            }
        } else {
            let rows: Vec<Vec<String>> = values.iter().map(cells).collect();
            table(head, &rows, self.quiet);
        }
    }

    /// A single value: JSON as is, else `text`.
    fn value(&self, v: &Value, text: impl FnOnce() -> String) {
        if self.machine() {
            println!("{v}");
        } else {
            println!("{}", text());
        }
    }
}

fn table(head: &[&str], rows: &[Vec<String>], quiet: bool) {
    let mut w: Vec<usize> = head.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |r: &[String]| {
        let mut s = String::new();
        for (i, c) in r.iter().enumerate() {
            if i + 1 == r.len() {
                s.push_str(c);
            } else {
                s.push_str(&format!("{c:<width$}  ", width = w[i]));
            }
        }
        println!("{}", s.trim_end());
    };
    if !quiet {
        line(&head.iter().map(|h| h.to_string()).collect::<Vec<_>>());
    }
    for r in rows {
        line(r);
    }
}

fn connect(server: Option<&str>, profile: Option<&str>) -> Result<Client> {
    let (url, token) = resolve(server, profile)?;
    client(&url, token)
}

fn flow_json(f: &FlowSummary) -> Value {
    serde_json::to_value(f).unwrap_or(Value::Null)
}

fn flow_cells(v: &Value) -> Vec<String> {
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    let host = if matches!(
        (v["scheme"].as_str(), v["port"].as_u64()),
        (Some("http"), Some(80)) | (Some("https"), Some(443))
    ) {
        s("host")
    } else {
        format!("{}:{}", s("host"), v["port"])
    };
    vec![
        v["id"].to_string(),
        v["status"].as_u64().map_or("-".into(), |x| x.to_string()),
        s("method"),
        format!("{}://{}{}", s("scheme"), host, s("path")),
        v["response_len"].as_i64().map_or("-".into(), |x| x.to_string()),
        v["duration_ms"]
            .as_i64()
            .map_or("-".into(), |x| format!("{x} ms")),
    ]
}

const FLOW_HEAD: [&str; 6] = ["ID", "STATUS", "METHOD", "URL", "BYTES", "TIME"];

#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub query: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub status_min: Option<u16>,
    pub status_max: Option<u16>,
    pub in_scope: bool,
    pub source: Option<String>,
    pub limit: u32,
    pub sort: Option<String>,
    pub asc: bool,
}

impl Filter {
    fn query(&self) -> FlowQuery {
        FlowQuery {
            q: self.query.clone(),
            host: self.host.clone(),
            methods: self.method.clone(),
            status_min: self.status_min,
            status_max: self.status_max,
            in_scope_only: self.in_scope,
            source: self.source.clone(),
            sort: self.sort.clone(),
            asc: self.asc,
            ..Default::default()
        }
    }
}

/// Up to `limit` flows matching the filter, newest first (or as sorted), fetched in pages.
async fn fetch_flows(c: &Client, f: &Filter) -> Result<Vec<FlowSummary>> {
    let mut out: Vec<FlowSummary> = Vec::new();
    let mut offset = 0u32;
    while (out.len() as u32) < f.limit {
        let mut q = f.query();
        q.limit = Some((f.limit - out.len() as u32).min(500));
        q.offset = Some(offset);
        let page = c.flows(&q).await?;
        let n = page.len() as u32;
        out.extend(page);
        if n == 0 {
            break;
        }
        offset += n;
    }
    out.truncate(f.limit as usize);
    Ok(out)
}

/// `history list` and `history search`. Search exits 4 when nothing matches.
pub async fn history_list(
    server: Option<&str>,
    profile: Option<&str>,
    out: Out,
    f: Filter,
    search: bool,
) -> Result<ExitCode> {
    let c = connect(server, profile)?;
    let flows = fetch_flows(&c, &f).await?;
    let values: Vec<Value> = flows.iter().map(flow_json).collect();
    out.rows(&FLOW_HEAD, &values, flow_cells);
    Ok(if search && flows.is_empty() {
        ExitCode::from(4)
    } else {
        ExitCode::SUCCESS
    })
}

/// One flow: its summary and the head of each message, or one message (and its body) with `--part`.
pub async fn history_show(
    server: Option<&str>,
    profile: Option<&str>,
    out: Out,
    id: i64,
    part: Option<String>,
    body_only: bool,
    decoded: bool,
) -> Result<ExitCode> {
    let c = connect(server, profile)?;
    let meta = c.flow(id).await?;
    let which = match part.as_deref() {
        None => None,
        Some("request") => Some(Part::Request),
        Some("response") => Some(Part::Response),
        Some("original-request") => Some(Part::OriginalRequest),
        Some("original-response") => Some(Part::OriginalResponse),
        Some(o) => bail!("unknown part `{o}`: request, response, original-request or original-response"),
    };
    if let Some(p) = which {
        let head = match p {
            Part::Request => Some(&meta.request),
            Part::Response => meta.response.as_ref(),
            Part::OriginalRequest => meta.original_request.as_ref(),
            Part::OriginalResponse => meta.original_response.as_ref(),
        }
        .context("the flow has no such message")?;
        let body = c.flow_body(id, p, decoded).await?;
        let mut o = std::io::stdout().lock();
        if out.machine() {
            let v = json!({"head": String::from_utf8_lossy(&head.head), "body": B64.encode(&body)});
            writeln!(o, "{v}")?;
        } else {
            if !body_only {
                o.write_all(&head.head)?;
            }
            o.write_all(&body)?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    let mut v = flow_json(&meta.summary);
    v["request_head"] = String::from_utf8_lossy(&meta.request.head).into_owned().into();
    v["response_head"] = meta
        .response
        .as_ref()
        .map(|r| String::from_utf8_lossy(&r.head).into_owned())
        .into();
    out.value(&v, || {
        let r = flow_cells(&flow_json(&meta.summary));
        let mut s = format!("flow {id}\n{} {} {}\n", r[2], r[3], r[1]);
        if let Some(e) = &meta.summary.error {
            s += &format!("error: {e}\n");
        }
        s += &format!("\n{}", String::from_utf8_lossy(&meta.request.head));
        if let Some(r) = &meta.response {
            s += &format!("\n{}", String::from_utf8_lossy(&r.head));
        }
        s.trim_end().to_string()
    });
    Ok(ExitCode::SUCCESS)
}

/// The head split into its first line and `(name, value)` pairs.
fn parse_head(head: &[u8]) -> (String, Vec<(String, String)>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("").to_string();
    let hs = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    (first, hs)
}

fn har_headers(hs: &[(String, String)]) -> Value {
    hs.iter().map(|(n, v)| json!({"name": n, "value": v})).collect()
}

fn rfc3339(ms: i64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn flow_url(f: &FlowSummary) -> String {
    let s = f.scheme.as_str();
    let default = if s == "https" { 443 } else { 80 };
    if f.port == default {
        format!("{s}://{}{}", f.host, f.path)
    } else {
        format!("{s}://{}:{}{}", f.host, f.port, f.path)
    }
}

/// One flow as a HAR 1.2 entry.
async fn har_entry(c: &Client, f: &FlowSummary) -> Result<Value> {
    let meta = c.flow(f.id).await?;
    let (_, req_headers) = parse_head(&meta.request.head);
    let req_body = c.flow_body(f.id, Part::Request, false).await?;
    let url = flow_url(f);
    let query: Vec<Value> = url
        .split_once('?')
        .map_or("", |(_, q)| q.split('#').next().unwrap_or(""))
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (n, v) = p.split_once('=').unwrap_or((p, ""));
            json!({"name": n, "value": v})
        })
        .collect();
    let mut request = json!({
        "method": f.method, "url": url, "httpVersion": f.http_version, "cookies": [],
        "headers": har_headers(&req_headers), "queryString": query,
        "headersSize": meta.request.head.len(), "bodySize": req_body.len(),
    });
    if !req_body.is_empty() {
        let mime = req_headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
            .map_or("", |(_, v)| v.as_str());
        request["postData"] = json!({"mimeType": mime, "text": String::from_utf8_lossy(&req_body)});
    }
    let response = match &meta.response {
        Some(r) => {
            let (first, hs) = parse_head(&r.head);
            let body = c.flow_body(f.id, Part::Response, true).await?;
            let mut content = json!({"size": body.len(), "mimeType": f.mime.clone().unwrap_or_default()});
            match std::str::from_utf8(&body) {
                Ok(t) => content["text"] = t.into(),
                Err(_) => {
                    content["text"] = B64.encode(&body).into();
                    content["encoding"] = "base64".into();
                }
            }
            let reason = first.splitn(3, ' ').nth(2).unwrap_or("");
            let loc = hs
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("location"))
                .map_or("", |(_, v)| v.as_str());
            json!({
                "status": f.status.unwrap_or(0), "statusText": reason, "httpVersion": f.http_version,
                "cookies": [], "headers": har_headers(&hs), "content": content, "redirectURL": loc,
                "headersSize": r.head.len(), "bodySize": r.body_len,
            })
        }
        None => json!({
            "status": 0, "statusText": f.error.clone().unwrap_or_default(), "httpVersion": f.http_version,
            "cookies": [], "headers": [], "content": {"size": 0, "mimeType": ""}, "redirectURL": "",
            "headersSize": -1, "bodySize": -1,
        }),
    };
    let ms = f.duration_ms.unwrap_or(0);
    Ok(json!({
        "startedDateTime": rfc3339(f.started_ms), "time": ms, "request": request, "response": response,
        "cache": {}, "timings": {"send": 0, "wait": ms, "receive": 0},
        "comment": f.note.clone().unwrap_or_default(),
    }))
}

/// One flow as an ndjson record: the summary, the message heads as text and the bodies in base64.
async fn ndjson_entry(c: &Client, f: &FlowSummary) -> Result<Value> {
    let meta = c.flow(f.id).await?;
    let mut v = flow_json(f);
    v["request_head"] = String::from_utf8_lossy(&meta.request.head).into_owned().into();
    v["request_body"] = B64.encode(c.flow_body(f.id, Part::Request, false).await?).into();
    if let Some(r) = &meta.response {
        v["response_head"] = String::from_utf8_lossy(&r.head).into_owned().into();
        v["response_body"] = B64.encode(c.flow_body(f.id, Part::Response, false).await?).into();
    }
    Ok(v)
}

/// `history export`: HAR 1.2 or ndjson, oldest flow first, to a file or stdout.
pub async fn history_export(
    server: Option<&str>,
    profile: Option<&str>,
    out: Out,
    f: Filter,
    format: &str,
    file: Option<PathBuf>,
) -> Result<ExitCode> {
    let c = connect(server, profile)?;
    let mut flows = fetch_flows(&c, &f).await?;
    flows.sort_by_key(|f| f.id);
    let mut sink: Box<dyn Write> = match &file {
        Some(p) if p.as_os_str() != "-" => Box::new(std::io::BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("cannot write {}", p.display()))?,
        )),
        _ => Box::new(std::io::stdout().lock()),
    };
    if format == "har" {
        let mut entries = Vec::with_capacity(flows.len());
        for f in &flows {
            entries.push(har_entry(&c, f).await?);
        }
        let har = json!({"log": {
            "version": "1.2", "creator": {"name": "bosun", "version": env!("CARGO_PKG_VERSION")}, "entries": entries,
        }});
        serde_json::to_writer_pretty(&mut sink, &har)?;
        writeln!(sink)?;
    } else {
        for f in &flows {
            writeln!(sink, "{}", ndjson_entry(&c, f).await?)?;
        }
    }
    sink.flush()?;
    out.note(format!("exported {} flows", flows.len()));
    Ok(ExitCode::SUCCESS)
}

fn read_input(file: &Path) -> Result<String> {
    if file.as_os_str() == "-" {
        let mut s = String::new();
        std::io::stdin().lock().read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(file).with_context(|| format!("could not read {}", file.display()))
    }
}

fn rule_text(r: &ScopeRule) -> String {
    format!(
        "{}{}{}{}{}",
        r.scheme.map_or(String::new(), |s| format!("{}://", s.as_str())),
        r.host,
        r.port.map_or(String::new(), |p| format!(":{p}")),
        r.path.clone().unwrap_or_default(),
        if r.allow_private {
            "  (private addresses allowed)"
        } else {
            ""
        }
    )
}

fn print_scope(out: Out, s: &ScopeSpec) -> Result<()> {
    out.value(&serde_json::to_value(s)?, || {
        let mut lines = Vec::new();
        for r in &s.include {
            lines.push(format!("include  {}", rule_text(r)));
        }
        for r in &s.exclude {
            lines.push(format!("exclude  {}", rule_text(r)));
        }
        if lines.is_empty() {
            lines.push("(empty: nothing is in scope)".into());
        }
        lines.join("\n")
    });
    Ok(())
}

pub async fn scope_get(server: Option<&str>, profile: Option<&str>, out: Out) -> Result<ExitCode> {
    print_scope(out, &connect(server, profile)?.scope().await?)?;
    Ok(ExitCode::SUCCESS)
}

/// Replace the scope with a JSON document (`{"include": [...], "exclude": [...]}`) from a file or stdin.
pub async fn scope_set(
    server: Option<&str>,
    profile: Option<&str>,
    out: Out,
    file: &Path,
) -> Result<ExitCode> {
    let spec: ScopeSpec = serde_json::from_str(&read_input(file)?).context("the scope is not valid JSON")?;
    let now = connect(server, profile)?.put_scope(&spec).await?;
    if out.machine() {
        print_scope(out, &now)?;
    } else {
        out.note(format!(
            "scope set: {} include, {} exclude",
            now.include.len(),
            now.exclude.len()
        ));
    }
    Ok(ExitCode::SUCCESS)
}

pub struct ScopeAdd {
    pub host: String,
    pub exclude: bool,
    pub scheme: Option<String>,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub allow_private: bool,
}

/// Add one rule to the include (or exclude) list, keeping the rest.
pub async fn scope_add(
    server: Option<&str>,
    profile: Option<&str>,
    out: Out,
    a: ScopeAdd,
) -> Result<ExitCode> {
    let scheme = match a.scheme.as_deref() {
        None => None,
        Some(s) => Some(serde_json::from_value(json!(s)).context("the scheme must be http or https")?),
    };
    let rule = ScopeRule {
        scheme,
        host: a.host,
        port: a.port,
        path: a.path,
        allow_private: a.allow_private,
    };
    let c = connect(server, profile)?;
    let mut spec = c.scope().await?;
    if a.exclude {
        spec.exclude.push(rule);
    } else {
        spec.include.push(rule);
    }
    let now = c.put_scope(&spec).await?;
    if out.machine() {
        print_scope(out, &now)?;
    } else {
        out.note(format!(
            "scope now has {} include, {} exclude",
            now.include.len(),
            now.exclude.len()
        ));
    }
    Ok(ExitCode::SUCCESS)
}

fn print_rules(out: Out, rules: &[MatchRule]) {
    let values: Vec<Value> = rules
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
        .collect();
    out.rows(&["ON", "TARGET", "MATCH", "REPLACE"], &values, |v| {
        vec![
            if v["enabled"] == true { "yes" } else { "no" }.into(),
            v["target"].as_str().unwrap_or("").into(),
            format!(
                "{}{}",
                v["match"].as_str().unwrap_or(""),
                if v["regex"] == true { " (regex)" } else { "" }
            ),
            v["replace"].as_str().unwrap_or("").into(),
        ]
    });
}

pub async fn rules_get(server: Option<&str>, profile: Option<&str>, out: Out) -> Result<ExitCode> {
    print_rules(out, &connect(server, profile)?.rules().await?);
    Ok(ExitCode::SUCCESS)
}

/// `set` replaces the rules with a JSON array; `import` adds the array's rules after the existing ones.
pub async fn rules_write(
    server: Option<&str>,
    profile: Option<&str>,
    out: Out,
    file: &Path,
    import: bool,
) -> Result<ExitCode> {
    let mut rules: Vec<MatchRule> =
        serde_json::from_str(&read_input(file)?).context("the rules are not a valid JSON array")?;
    let c = connect(server, profile)?;
    if import {
        let mut all = c.rules().await?;
        all.append(&mut rules);
        rules = all;
    }
    let now = c.put_rules(&rules).await?;
    if out.machine() {
        print_rules(out, &now);
    } else {
        out.note(format!("{} rules now", now.len()));
    }
    Ok(ExitCode::SUCCESS)
}

pub struct InterceptOn {
    pub responses: bool,
    pub in_scope_only: Option<bool>,
}

fn print_intercept(out: Out, s: &InterceptSettings) {
    out.value(
        &json!({"requests": s.requests, "responses": s.responses, "in_scope_only": s.in_scope_only}),
        || {
            format!(
                "requests {}, responses {}{}",
                if s.requests { "held" } else { "not held" },
                if s.responses { "held" } else { "not held" },
                if s.in_scope_only { ", in scope only" } else { "" }
            )
        },
    );
}

/// `intercept on` holds requests (and responses with `--responses`); `off` holds nothing.
pub async fn intercept_set(
    server: Option<&str>,
    profile: Option<&str>,
    out: Out,
    on: Option<InterceptOn>,
) -> Result<ExitCode> {
    let c = connect(server, profile)?;
    let mut s = c.intercept().await?;
    match on {
        Some(o) => {
            s.requests = true;
            s.responses = o.responses;
            if let Some(i) = o.in_scope_only {
                s.in_scope_only = i;
            }
        }
        None => {
            s.requests = false;
            s.responses = false;
        }
    }
    let now = c.put_intercept(&s).await?;
    if !out.quiet {
        print_intercept(out, &now);
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn intercept_status(server: Option<&str>, profile: Option<&str>, out: Out) -> Result<ExitCode> {
    print_intercept(out, &connect(server, profile)?.intercept().await?);
    Ok(ExitCode::SUCCESS)
}

pub async fn intercept_queue(server: Option<&str>, profile: Option<&str>, out: Out) -> Result<ExitCode> {
    let q = connect(server, profile)?.intercept_queue().await?;
    let values: Vec<Value> = q
        .iter()
        .map(|i| {
            json!({"id": i.id, "flow_id": i.flow_id, "phase": format!("{:?}", i.phase).to_lowercase(),
                "method": i.method, "url": i.url, "status": i.status, "queued_ms": i.queued_ms})
        })
        .collect();
    out.rows(
        &["ID", "PHASE", "METHOD", "URL", "STATUS", "HELD"],
        &values,
        |v| {
            vec![
                v["id"].to_string(),
                v["phase"].as_str().unwrap_or("").into(),
                v["method"].as_str().unwrap_or("").into(),
                v["url"].as_str().unwrap_or("").into(),
                v["status"].as_u64().map_or("-".into(), |s| s.to_string()),
                format!("{} ms", v["queued_ms"]),
            ]
        },
    );
    Ok(ExitCode::SUCCESS)
}

/// Forward one held message, or all of them when no id is given.
pub async fn intercept_forward(
    server: Option<&str>,
    profile: Option<&str>,
    out: Out,
    id: Option<u64>,
) -> Result<ExitCode> {
    let c = connect(server, profile)?;
    let n = match id {
        Some(i) => {
            c.intercept_decide(i, &Decision::Forward { raw: None }).await?;
            1
        }
        None => c.intercept_forward_all().await?,
    };
    out.note(format!("forwarded {n}"));
    Ok(ExitCode::SUCCESS)
}

pub async fn intercept_drop(
    server: Option<&str>,
    profile: Option<&str>,
    out: Out,
    id: u64,
) -> Result<ExitCode> {
    connect(server, profile)?
        .intercept_decide(id, &Decision::Drop)
        .await?;
    out.note(format!("dropped {id}"));
    Ok(ExitCode::SUCCESS)
}

/// The CA certificate of the engine you are signed in to (PEM, to a file or stdout).
pub async fn ca_export(
    server: Option<&str>,
    profile: Option<&str>,
    out_file: Option<PathBuf>,
) -> Result<ExitCode> {
    let pem = connect(server, profile)?.ca_pem().await?;
    match out_file {
        Some(p) => std::fs::write(&p, pem).with_context(|| format!("cannot write {}", p.display()))?,
        None => std::io::stdout().write_all(pem.as_bytes())?,
    }
    Ok(ExitCode::SUCCESS)
}

/// Print engine events as they happen, as JSON lines, reconnecting when the connection drops. Without `--follow`
/// only the engine's `hello` is printed. `--count N` stops after N messages.
pub async fn events(
    server: Option<&str>,
    profile: Option<&str>,
    out: Out,
    follow: bool,
    count: Option<u64>,
) -> Result<ExitCode> {
    let c = connect(server, profile)?;
    let mut stream = c.events(None).await?;
    let mut seen = 0u64;
    let mut failures = 0u32;
    loop {
        match stream.next().await {
            Some(Ok(s)) => {
                failures = 0;
                let hello = matches!(s.event, Event::Hello { .. });
                let mut v = serde_json::to_value(&s.event)?;
                if let (Some(seq), Some(o)) = (s.seq, v.as_object_mut()) {
                    o.insert("seq".into(), seq.into());
                }
                match &s.event {
                    Event::Flow { flow } if !out.machine() => {
                        println!("flow  {}", flow_cells(&flow_json(flow)).join("  "));
                    }
                    _ => println!("{v}"),
                }
                std::io::stdout().flush().ok();
                seen += 1;
                if (!follow && hello) || count.is_some_and(|n| seen >= n) {
                    break;
                }
            }
            Some(Err(e)) => {
                failures += 1;
                if failures > 5 {
                    return Err(e.into());
                }
                out.note(format!("connection lost ({e}); reconnecting"));
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let _ = stream.reconnect().await;
            }
            None => {
                failures += 1;
                if failures > 5 {
                    bail!("the engine closed the event stream");
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let _ = stream.reconnect().await;
            }
        }
    }
    stream.close().await;
    Ok(ExitCode::SUCCESS)
}
