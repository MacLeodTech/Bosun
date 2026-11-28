//! Reports from issues. Pure: issues in, text out, no I/O and no clock, so the output is deterministic.
//!
//! Issues carry target content (URLs, evidence excerpts), so every format escapes it for its own syntax, and the
//! HTML report is a single document with no script, no links and no external loads, with a `Content-Security-Policy`
//! that forbids everything but its own stylesheet (see [`html_csp`]). Secrets (credentials in URLs, `Authorization`
//! and cookie headers, bearer tokens, JWTs, `password=`-style pairs) are redacted unless [`Options::redact`] is off.

use std::fmt::Write as _;
use std::sync::LazyLock;

use base64::Engine as _;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("unknown report format {0:?} (use html, json, sarif, junit or markdown)")]
    UnknownFormat(String),
    #[error("unknown tracker {0:?} (use github, jira or linear)")]
    UnknownTracker(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    New,
    Confirmed,
    FalsePositive,
}

/// A highlighted piece of a request or response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// `request` or `response`.
    pub part: String,
    pub excerpt: String,
}

/// One issue, as the report formats see it (the shape of an entry of `GET /issues`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    pub id: i64,
    /// Stable identifier of the kind of issue, such as `missing-csp`. It becomes the SARIF rule id.
    pub issue_type: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: Status,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub cwe: Vec<u32>,
    #[serde(default)]
    pub owasp: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Html,
    Json,
    Sarif,
    Junit,
    Markdown,
}

impl Format {
    pub fn parse(s: &str) -> Result<Self, ReportError> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "html" => Self::Html,
            "json" => Self::Json,
            "sarif" => Self::Sarif,
            "junit" | "xml" => Self::Junit,
            "markdown" | "md" => Self::Markdown,
            _ => return Err(ReportError::UnknownFormat(s.to_string())),
        })
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Self::Html => "text/html; charset=utf-8",
            Self::Json => "application/json",
            Self::Sarif => "application/sarif+json",
            Self::Junit => "application/xml",
            Self::Markdown => "text/markdown; charset=utf-8",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Json => "json",
            Self::Sarif => "sarif",
            Self::Junit => "xml",
            Self::Markdown => "md",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Redact secrets (the default). Turning this off must be a deliberate, audited choice of the caller.
    pub redact: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { redact: true }
    }
}

pub const REDACTED: &str = "[redacted]";

const SECRET_NAMES: &str = "password|passwd|pwd|secret|token|api[_-]?key|apikey|auth|authorization|session|sessionid|sid|csrf|xsrf|signature|credential";

static HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token)\s*:)[^\r\n]*",
    )
    .expect("static regex")
});
static PAIR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)\b([a-z0-9_.-]*(?:{SECRET_NAMES})[a-z0-9_.-]*)(["']?\s*[=:]\s*["']?)([^&\s"';,<>]+)"#
    ))
    .expect("static regex")
});
static BEARER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]{8,}").expect("static regex"));
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*").expect("static regex")
});
static USERINFO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@").expect("static regex"));

/// Redact secrets in a piece of text (a URL, a header block, a body excerpt).
pub fn redact(text: &str) -> String {
    let s = HEADER_RE.replace_all(text, format!("$1 {REDACTED}").as_str());
    let s = USERINFO_RE.replace_all(&s, format!("$1{REDACTED}@").as_str());
    let s = JWT_RE.replace_all(&s, REDACTED);
    let s = BEARER_RE.replace_all(&s, format!("$1 {REDACTED}").as_str());
    PAIR_RE
        .replace_all(&s, |c: &regex::Captures| format!("{}{}{REDACTED}", &c[1], &c[2]))
        .into_owned()
}

fn prepared(issues: &[Issue], opts: Options) -> Vec<Issue> {
    let mut v: Vec<Issue> = issues.to_vec();
    if opts.redact {
        for i in &mut v {
            i.url = redact(&i.url);
            i.description = redact(&i.description);
            for e in &mut i.evidence {
                e.excerpt = redact(&e.excerpt);
            }
        }
    }
    // Worst first, then a stable order.
    v.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.issue_type.cmp(&b.issue_type))
            .then(a.id.cmp(&b.id))
    });
    v
}

/// Render `issues` in `format`.
pub fn render(issues: &[Issue], format: Format, opts: Options) -> String {
    let v = prepared(issues, opts);
    match format {
        Format::Json => json_report(&v, opts),
        Format::Sarif => sarif_report(&v),
        Format::Junit => junit_report(&v),
        Format::Markdown => markdown_report(&v),
        Format::Html => html_report(&v),
    }
}

fn sev_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
fn conf_str(c: Confidence) -> &'static str {
    match c {
        Confidence::Tentative => "tentative",
        Confidence::Firm => "firm",
        Confidence::Certain => "certain",
    }
}
fn status_str(s: Status) -> &'static str {
    match s {
        Status::New => "new",
        Status::Confirmed => "confirmed",
        Status::FalsePositive => "false_positive",
    }
}

fn counts(v: &[Issue]) -> Vec<(Severity, usize)> {
    [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .map(|s| (s, v.iter().filter(|i| i.severity == s).count()))
    .collect()
}

// ---- JSON ----

fn json_report(v: &[Issue], opts: Options) -> String {
    let by: serde_json::Map<String, Value> = counts(v)
        .into_iter()
        .map(|(s, n)| (sev_str(s).to_string(), json!(n)))
        .collect();
    let doc = json!({
        "tool": "bosun",
        "redacted": opts.redact,
        "total": v.len(),
        "by_severity": by,
        "issues": v,
    });
    let mut s = serde_json::to_string_pretty(&doc).unwrap_or_default();
    s.push('\n');
    s
}

// ---- SARIF 2.1.0 ----

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn sarif_report(v: &[Issue]) -> String {
    let mut rule_ids: Vec<&str> = v.iter().map(|i| i.issue_type.as_str()).collect();
    rule_ids.sort_unstable();
    rule_ids.dedup();
    let rules: Vec<Value> = rule_ids
        .iter()
        .filter_map(|id| {
            let first = v.iter().find(|i| i.issue_type == *id)?;
            let mut tags: Vec<String> = first
                .cwe
                .iter()
                .map(|c| format!("external/cwe/cwe-{c}"))
                .collect();
            tags.extend(first.owasp.iter().map(|o| format!("owasp/{o}")));
            let mut r = json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": first.title },
                "defaultConfiguration": { "level": sarif_level(first.severity) },
                "properties": { "tags": tags },
            });
            if !first.remediation.is_empty() {
                r["help"] = json!({ "text": first.remediation });
            }
            Some(r)
        })
        .collect();
    let results: Vec<Value> = v
        .iter()
        .map(|i| {
            let idx = rule_ids.iter().position(|r| *r == i.issue_type).unwrap_or(0);
            let mut text = i.title.clone();
            if !i.description.is_empty() {
                text.push_str(": ");
                text.push_str(&i.description);
            }
            let evidence: Vec<Value> = i
                .evidence
                .iter()
                .map(|e| json!({"part": e.part, "excerpt": e.excerpt}))
                .collect();
            let mut r = json!({
                "ruleId": i.issue_type,
                "ruleIndex": idx,
                "level": sarif_level(i.severity),
                "message": { "text": text },
                "locations": [{ "physicalLocation": { "artifactLocation": { "uri": i.url } } }],
                "properties": {
                    "id": i.id,
                    "severity": sev_str(i.severity),
                    "confidence": conf_str(i.confidence),
                    "status": status_str(i.status),
                    "method": i.method,
                    "evidence": evidence,
                },
            });
            if i.status == Status::FalsePositive {
                r["suppressions"] = json!([{
                    "kind": "external",
                    "status": "accepted",
                    "justification": "marked a false positive in Bosun"
                }]);
            }
            r
        })
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "Bosun",
                "informationUri": "https://github.com/MacLeodTech/bosun",
                "rules": rules,
            } },
            "results": results,
        }],
    });
    let mut s = serde_json::to_string_pretty(&doc).unwrap_or_default();
    s.push('\n');
    s
}

// ---- JUnit ----

fn xml_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            // Characters XML 1.0 cannot carry at all.
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => o.push('\u{FFFD}'),
            '\u{FFFE}' | '\u{FFFF}' => o.push('\u{FFFD}'),
            c => o.push(c),
        }
    }
    o
}

fn junit_report(v: &[Issue]) -> String {
    let failures = v.iter().filter(|i| i.status != Status::FalsePositive).count();
    let skipped = v.len() - failures;
    let mut o = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        o,
        "<testsuites name=\"bosun\" tests=\"{}\" failures=\"{failures}\" skipped=\"{skipped}\">",
        v.len()
    );
    let _ = writeln!(
        o,
        "  <testsuite name=\"bosun issues\" tests=\"{}\" failures=\"{failures}\" skipped=\"{skipped}\">",
        v.len()
    );
    for i in v {
        let _ = writeln!(
            o,
            "    <testcase classname=\"{}\" name=\"{}\">",
            xml_escape(&i.issue_type),
            xml_escape(&format!("{} {}", i.method, i.url))
        );
        if i.status == Status::FalsePositive {
            o.push_str("      <skipped message=\"false positive\"/>\n");
        } else {
            let mut body = format!(
                "severity: {}\nconfidence: {}\nstatus: {}\n",
                sev_str(i.severity),
                conf_str(i.confidence),
                status_str(i.status)
            );
            if !i.description.is_empty() {
                let _ = writeln!(body, "{}", i.description);
            }
            if !i.remediation.is_empty() {
                let _ = writeln!(body, "remediation: {}", i.remediation);
            }
            for e in &i.evidence {
                let _ = writeln!(body, "evidence ({}): {}", e.part, e.excerpt);
            }
            let _ = writeln!(
                o,
                "      <failure message=\"{}\" type=\"{}\">{}</failure>",
                xml_escape(&i.title),
                sev_str(i.severity),
                xml_escape(&body)
            );
        }
        o.push_str("    </testcase>\n");
    }
    o.push_str("  </testsuite>\n</testsuites>\n");
    o
}

// ---- Markdown ----

/// Escape text for a Markdown line: neutralises emphasis, links, headings, tables and raw HTML.
fn md_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '!' | '|' | '~' => {
                o.push('\\');
                o.push(c);
            }
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '&' => o.push_str("&amp;"),
            '\r' | '\n' => o.push(' '),
            c => o.push(c),
        }
    }
    o
}

/// A fenced code block whose fence is longer than any run of backticks in `s`.
fn md_fence(s: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in s.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let fence = "`".repeat((longest + 1).max(3));
    format!("{fence}\n{}\n{fence}\n", s.replace('\r', ""))
}

fn markdown_report(v: &[Issue]) -> String {
    let mut o = String::from("# Bosun issues report\n\n");
    let _ = writeln!(o, "{} issue(s).\n", v.len());
    o.push_str("| Severity | Count |\n| --- | --- |\n");
    for (s, n) in counts(v) {
        let _ = writeln!(o, "| {} | {n} |", sev_str(s));
    }
    for i in v {
        let _ = write!(o, "\n## {}\n\n", md_escape(&i.title));
        let _ = writeln!(o, "- Severity: {}", sev_str(i.severity));
        let _ = writeln!(o, "- Confidence: {}", conf_str(i.confidence));
        let _ = writeln!(o, "- Status: {}", status_str(i.status));
        let _ = writeln!(o, "- Type: {}", md_escape(&i.issue_type));
        let _ = writeln!(o, "- Request: {} {}", md_escape(&i.method), md_escape(&i.url));
        if !i.cwe.is_empty() {
            let c: Vec<String> = i.cwe.iter().map(|c| format!("CWE-{c}")).collect();
            let _ = writeln!(o, "- CWE: {}", c.join(", "));
        }
        if !i.owasp.is_empty() {
            let _ = writeln!(o, "- OWASP: {}", md_escape(&i.owasp.join(", ")));
        }
        if !i.description.is_empty() {
            let _ = write!(o, "\n{}\n", md_escape(&i.description));
        }
        if !i.remediation.is_empty() {
            let _ = write!(o, "\n**Remediation:** {}\n", md_escape(&i.remediation));
        }
        for e in &i.evidence {
            let _ = write!(
                o,
                "\nEvidence ({}):\n\n{}",
                md_escape(&e.part),
                md_fence(&e.excerpt)
            );
        }
    }
    o
}

// ---- Issue tracker export ----

/// An issue tracker whose "new issue" request body Bosun can prepare. Bosun sends nothing to it: the user pastes
/// the title and body, or posts the payload themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tracker {
    Github,
    Jira,
    Linear,
}

impl Tracker {
    pub fn parse(s: &str) -> Result<Self, ReportError> {
        match s.to_ascii_lowercase().as_str() {
            "github" => Ok(Self::Github),
            "jira" => Ok(Self::Jira),
            "linear" => Ok(Self::Linear),
            _ => Err(ReportError::UnknownTracker(s.to_string())),
        }
    }
}

/// One issue prepared for a tracker.
#[derive(Debug, Clone, Serialize)]
pub struct TrackerExport {
    pub title: String,
    /// The description as Markdown (what GitHub and Linear take; readable anywhere).
    pub body: String,
    pub labels: Vec<String>,
    /// The JSON body for the tracker's create-issue call (GitHub REST; Jira REST v3 with an Atlassian document, which
    /// still needs the project key and issue type; Linear: the input fields, which still need the team id).
    pub payload: serde_json::Value,
}

/// Prepare one issue for `tracker`. Secrets are redacted unless `opts.redact` is off.
pub fn tracker_export(issue: &Issue, tracker: Tracker, opts: Options) -> TrackerExport {
    let v = prepared(std::slice::from_ref(issue), opts);
    let i = &v[0];
    let title = format!("[{}] {}", sev_str(i.severity), i.title);
    let mut body = String::new();
    let _ = writeln!(body, "- Severity: {}", sev_str(i.severity));
    let _ = writeln!(body, "- Confidence: {}", conf_str(i.confidence));
    let _ = writeln!(body, "- Request: {} {}", md_escape(&i.method), md_escape(&i.url));
    if !i.cwe.is_empty() {
        let c: Vec<String> = i.cwe.iter().map(|c| format!("CWE-{c}")).collect();
        let _ = writeln!(body, "- CWE: {}", c.join(", "));
    }
    if !i.owasp.is_empty() {
        let _ = writeln!(body, "- OWASP: {}", md_escape(&i.owasp.join(", ")));
    }
    if !i.description.is_empty() {
        let _ = write!(body, "\n{}\n", md_escape(&i.description));
    }
    if !i.remediation.is_empty() {
        let _ = write!(body, "\n**Remediation:** {}\n", md_escape(&i.remediation));
    }
    for e in &i.evidence {
        let _ = write!(
            body,
            "\nEvidence ({}):\n\n{}",
            md_escape(&e.part),
            md_fence(&e.excerpt)
        );
    }
    let labels = vec![
        "security".to_string(),
        format!("severity:{}", sev_str(i.severity)),
    ];
    let payload = match tracker {
        Tracker::Github => serde_json::json!({ "title": title, "body": body, "labels": labels }),
        Tracker::Linear => serde_json::json!({ "title": title, "description": body }),
        Tracker::Jira => {
            let mut content = vec![adf_para(&format!(
                "Severity {}, confidence {}. {} {}",
                sev_str(i.severity),
                conf_str(i.confidence),
                i.method,
                i.url
            ))];
            if !i.description.is_empty() {
                content.push(adf_para(&i.description));
            }
            if !i.remediation.is_empty() {
                content.push(adf_para(&format!("Remediation: {}", i.remediation)));
            }
            for e in &i.evidence {
                let t = if e.excerpt.is_empty() {
                    " "
                } else {
                    e.excerpt.as_str()
                };
                content.push(
                    serde_json::json!({ "type": "codeBlock", "content": [{ "type": "text", "text": t }] }),
                );
            }
            serde_json::json!({ "fields": {
                "summary": title,
                "labels": ["security", format!("severity-{}", sev_str(i.severity))],
                "description": { "type": "doc", "version": 1, "content": content },
            }})
        }
    };
    TrackerExport {
        title,
        body,
        labels,
        payload,
    }
}

fn adf_para(text: &str) -> serde_json::Value {
    let t = if text.is_empty() { " " } else { text };
    serde_json::json!({ "type": "paragraph", "content": [{ "type": "text", "text": t }] })
}

// ---- HTML ----

const CSS: &str = "body{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1b1b1b}\
h1{font-size:1.6rem}h2{font-size:1.15rem;margin:0}.issue{border:1px solid #bbb;border-radius:6px;padding:.8rem 1rem;margin:1rem 0}\
.sev{display:inline-block;padding:0 .5rem;border-radius:4px;color:#fff;font-size:.8rem;text-transform:uppercase}\
.critical{background:#7a0019}.high{background:#b3261e}.medium{background:#8a5300}.low{background:#245a8d}.info{background:#555}\
pre{background:#f3f3f3;padding:.6rem;overflow:auto;white-space:pre-wrap;word-break:break-all}dl{margin:.5rem 0}dt{font-weight:600}\
table{border-collapse:collapse}td,th{border:1px solid #bbb;padding:.2rem .6rem;text-align:left}";

/// The policy the HTML report must be served under (an HTTP header; the document repeats it in a `<meta>` too).
/// Nothing loads or runs except the document's own stylesheet, identified by its hash.
pub fn html_csp() -> String {
    format!("{}; frame-ancestors 'none'", meta_csp())
}

/// The same without `frame-ancestors`, which a `<meta>` policy cannot carry (browsers warn and ignore it).
fn meta_csp() -> String {
    let h = Sha256::digest(CSS.as_bytes());
    format!(
        "default-src 'none'; style-src 'sha256-{}'; base-uri 'none'; form-action 'none'",
        base64::engine::general_purpose::STANDARD.encode(h)
    )
}

fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn html_report(v: &[Issue]) -> String {
    let mut o = String::from("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    let _ = writeln!(
        o,
        "<meta http-equiv=\"Content-Security-Policy\" content=\"{}\">",
        html_escape(&meta_csp())
    );
    o.push_str("<meta name=\"referrer\" content=\"no-referrer\">\n<title>Bosun issues report</title>\n");
    let _ = writeln!(o, "<style>{CSS}</style>\n</head>\n<body>");
    let _ = writeln!(o, "<h1>Bosun issues report</h1>\n<p>{} issue(s).</p>", v.len());
    o.push_str("<table>\n<tr><th>Severity</th><th>Count</th></tr>\n");
    for (s, n) in counts(v) {
        let _ = writeln!(o, "<tr><td>{}</td><td>{n}</td></tr>", sev_str(s));
    }
    o.push_str("</table>\n");
    for i in v {
        let _ = writeln!(
            o,
            "<section class=\"issue\">\n<h2><span class=\"sev {}\">{}</span> {}</h2>",
            sev_str(i.severity),
            sev_str(i.severity),
            html_escape(&i.title)
        );
        o.push_str("<dl>\n");
        let _ = writeln!(
            o,
            "<dt>Request</dt><dd>{} {}</dd>",
            html_escape(&i.method),
            html_escape(&i.url)
        );
        let _ = writeln!(o, "<dt>Type</dt><dd>{}</dd>", html_escape(&i.issue_type));
        let _ = writeln!(o, "<dt>Confidence</dt><dd>{}</dd>", conf_str(i.confidence));
        let _ = writeln!(o, "<dt>Status</dt><dd>{}</dd>", status_str(i.status));
        if !i.cwe.is_empty() {
            let c: Vec<String> = i.cwe.iter().map(|c| format!("CWE-{c}")).collect();
            let _ = writeln!(o, "<dt>CWE</dt><dd>{}</dd>", c.join(", "));
        }
        if !i.owasp.is_empty() {
            let _ = writeln!(o, "<dt>OWASP</dt><dd>{}</dd>", html_escape(&i.owasp.join(", ")));
        }
        o.push_str("</dl>\n");
        if !i.description.is_empty() {
            let _ = writeln!(o, "<p>{}</p>", html_escape(&i.description));
        }
        if !i.remediation.is_empty() {
            let _ = writeln!(
                o,
                "<p><strong>Remediation:</strong> {}</p>",
                html_escape(&i.remediation)
            );
        }
        for e in &i.evidence {
            let _ = writeln!(
                o,
                "<p>Evidence ({}):</p>\n<pre>{}</pre>",
                html_escape(&e.part),
                html_escape(&e.excerpt)
            );
        }
        o.push_str("</section>\n");
    }
    o.push_str("</body>\n</html>\n");
    o
}
