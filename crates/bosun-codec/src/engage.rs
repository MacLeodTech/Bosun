//! Engagement helpers: what a tester wants to pull out of recorded traffic. Pure functions on text and bytes, so they
//! can be fuzzed: every scanner is linear in its input and stops at a fixed number of results.
//!
//! * [`find_in_html`] and [`find_urls`] list comments, scripts and references in a response body.
//! * [`csrf_poc`] writes a cross-site request forgery proof of concept for a recorded request. It is HTML for a
//!   *file the tester downloads*; the API serves it as an attachment, never to be rendered in Bosun's own origin.
//! * [`parameters`] lists the parameters of a request (query, form body, JSON body) for the target analysis.

use serde::Serialize;
use utoipa::ToSchema;

/// The most results of any kind from one scan.
pub const MAX_FINDINGS: usize = 500;
/// Longest value kept in a result, in characters; a longer one is cut and ends with "…".
pub const MAX_VALUE: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// `<!-- ... -->`
    Comment,
    /// The text of a `<script>` with no `src`.
    InlineScript,
    /// `<script src=...>`
    ScriptSrc,
    /// `href` of `<a>`, `<link>` and `<area>`.
    Link,
    /// `action` of `<form>`.
    FormAction,
    /// `src` of images, frames, media and other embeds.
    Resource,
    /// An absolute `http(s)://` URL found in text.
    Url,
    /// A quoted path such as `"/api/v1/users"` found in text (script and JSON bodies).
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Finding {
    pub kind: FindingKind,
    pub value: String,
    /// Byte offset into the text that was scanned.
    pub offset: usize,
}

fn clip(s: &str) -> String {
    let t = s.trim();
    if t.chars().count() <= MAX_VALUE {
        t.to_string()
    } else {
        let mut out: String = t.chars().take(MAX_VALUE).collect();
        out.push('…');
        out
    }
}

/// First position at or after `from` where `needle` (lower case ASCII) occurs in `hay`, ignoring ASCII case.
fn find_ci(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let last = hay.len() - needle.len();
    (from..=last).find(|&i| {
        hay[i..i + needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c)
}

/// One tag's name and attributes, starting just after `<`. Returns the lower-cased name, the attributes and the
/// position after the closing `>` (or the end of the text). Attribute values may be quoted or bare.
fn parse_tag(b: &[u8], mut i: usize) -> (String, Vec<(String, String)>, usize) {
    let start = i;
    while i < b.len() && !is_space(b[i]) && b[i] != b'>' && b[i] != b'/' {
        i += 1;
    }
    let name = String::from_utf8_lossy(&b[start..i]).to_ascii_lowercase();
    let mut attrs = Vec::new();
    while i < b.len() && b[i] != b'>' {
        while i < b.len() && (is_space(b[i]) || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() || b[i] == b'>' {
            break;
        }
        let ns = i;
        while i < b.len() && !is_space(b[i]) && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        let key = String::from_utf8_lossy(&b[ns..i]).to_ascii_lowercase();
        while i < b.len() && is_space(b[i]) {
            i += 1;
        }
        let mut value = String::new();
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && is_space(b[i]) {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                i += 1;
                let vs = i;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                value = String::from_utf8_lossy(&b[vs..i]).into_owned();
                i = (i + 1).min(b.len());
            } else {
                let vs = i;
                while i < b.len() && !is_space(b[i]) && b[i] != b'>' {
                    i += 1;
                }
                value = String::from_utf8_lossy(&b[vs..i]).into_owned();
            }
        }
        if !key.is_empty() {
            attrs.push((key, value));
        }
        // A byte that is neither a name nor a delimiter (a stray quote) would stall the loop: step over it.
        if i < b.len() && i == ns && b[i] != b'>' {
            i += 1;
        }
    }
    (name, attrs, (i + 1).min(b.len()))
}

/// Comments, scripts and references in an HTML document.
pub fn find_in_html(html: &str) -> Vec<Finding> {
    let b = html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() && out.len() < MAX_FINDINGS {
        let Some(rel) = b[i..].iter().position(|&c| c == b'<') else {
            break;
        };
        let at = i + rel;
        if b[at..].starts_with(b"<!--") {
            let body = at + 4;
            let end = b[body..]
                .windows(3)
                .position(|w| w == b"-->")
                .map_or(b.len(), |p| body + p);
            out.push(Finding {
                kind: FindingKind::Comment,
                value: clip(&String::from_utf8_lossy(&b[body..end])),
                offset: at,
            });
            i = (end + 3).min(b.len());
            continue;
        }
        let next = b.get(at + 1).copied().unwrap_or(0);
        if !(next.is_ascii_alphabetic()) {
            i = at + 1;
            continue;
        }
        let (name, attrs, after) = parse_tag(b, at + 1);
        let attr = |k: &str| attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        i = after;
        match name.as_str() {
            "script" => {
                if let Some(src) = attr("src") {
                    out.push(Finding {
                        kind: FindingKind::ScriptSrc,
                        value: clip(src),
                        offset: at,
                    });
                } else {
                    let end = find_ci(b, b"</script", after).unwrap_or(b.len());
                    let text = String::from_utf8_lossy(&b[after..end]);
                    if !text.trim().is_empty() {
                        out.push(Finding {
                            kind: FindingKind::InlineScript,
                            value: clip(&text),
                            offset: at,
                        });
                    }
                    i = end;
                }
            }
            "a" | "link" | "area" => {
                if let Some(h) = attr("href").filter(|h| !h.trim().is_empty()) {
                    out.push(Finding {
                        kind: FindingKind::Link,
                        value: clip(h),
                        offset: at,
                    });
                }
            }
            "form" => {
                // A form with no action submits to the page itself: report that, since it is still an endpoint.
                out.push(Finding {
                    kind: FindingKind::FormAction,
                    value: clip(attr("action").unwrap_or("")),
                    offset: at,
                });
            }
            "img" | "iframe" | "frame" | "embed" | "source" | "audio" | "video" | "track" | "input"
            | "object" => {
                if let Some(s) = attr("src")
                    .or_else(|| attr("data"))
                    .filter(|s| !s.trim().is_empty())
                {
                    out.push(Finding {
                        kind: FindingKind::Resource,
                        value: clip(s),
                        offset: at,
                    });
                }
            }
            _ => {}
        }
    }
    out
}

/// Absolute URLs and quoted paths in any text (script, JSON, plain text).
pub fn find_urls(text: &str) -> Vec<Finding> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() && out.len() < MAX_FINDINGS {
        let c = b[i];
        let is_url = (c == b'h' || c == b'H') && (b[i..].len() >= 8) && {
            let head = &b[i..i + 8];
            head[..7].eq_ignore_ascii_case(b"http://") || head.eq_ignore_ascii_case(b"https://")
        };
        if is_url {
            let end = b[i..]
                .iter()
                .position(|&x| {
                    is_space(x)
                        || matches!(
                            x,
                            b'"' | b'\'' | b'<' | b'>' | b'`' | b'\\' | b')' | b'(' | b'{' | b'}'
                        )
                })
                .map_or(b.len(), |p| i + p);
            out.push(Finding {
                kind: FindingKind::Url,
                value: clip(&String::from_utf8_lossy(&b[i..end])),
                offset: i,
            });
            i = end.max(i + 1);
            continue;
        }
        // A quoted path: "/something" with a letter after the slash, as written in scripts and JSON.
        if (c == b'"' || c == b'\'')
            && b.get(i + 1) == Some(&b'/')
            && b.get(i + 2).is_some_and(|x| x.is_ascii_alphabetic())
        {
            let end = b[i + 1..]
                .iter()
                .position(|&x| x == c || is_space(x) || matches!(x, b'<' | b'>' | b'\\'))
                .map_or(b.len(), |p| i + 1 + p);
            if b.get(end) == Some(&c) {
                out.push(Finding {
                    kind: FindingKind::Path,
                    value: clip(&String::from_utf8_lossy(&b[i + 1..end])),
                    offset: i + 1,
                });
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

// ---- parameters

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ParamWhere {
    Query,
    Form,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Param {
    pub name: String,
    #[serde(rename = "where")]
    pub location: ParamWhere,
    pub value: String,
}

/// Percent-decode with `+` as a space (form encoding). Invalid escapes stay as they are.
pub fn form_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if b
                .get(i + 1)
                .zip(b.get(i + 2))
                .is_some_and(|(h, l)| h.is_ascii_hexdigit() && l.is_ascii_hexdigit()) =>
            {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(b'?'));
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `a=1&b=2` as decoded pairs. A piece with no `=` is a name with an empty value.
pub fn form_pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .take(MAX_FINDINGS)
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (form_decode(k), form_decode(v)),
            None => (form_decode(p), String::new()),
        })
        .collect()
}

fn json_params(v: &serde_json::Value, prefix: &str, depth: usize, out: &mut Vec<Param>) {
    if out.len() >= MAX_FINDINGS {
        return;
    }
    match v {
        serde_json::Value::Object(m) if depth < 4 => {
            for (k, v) in m {
                let name = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                json_params(v, &name, depth + 1, out);
            }
        }
        serde_json::Value::Array(a) if depth < 4 => {
            for v in a.iter().take(3) {
                json_params(v, &format!("{prefix}[]"), depth + 1, out);
            }
        }
        other if !prefix.is_empty() => {
            let value = match other {
                serde_json::Value::String(s) => s.clone(),
                o => o.to_string(),
            };
            out.push(Param {
                name: prefix.to_string(),
                location: ParamWhere::Json,
                value: clip(&value),
            });
        }
        _ => {}
    }
}

/// The parameters of a request: those in the query string of `path`, and those in a form or JSON body.
pub fn parameters(path: &str, content_type: Option<&str>, body: &[u8]) -> Vec<Param> {
    let mut out = Vec::new();
    if let Some((_, q)) = path.split_once('?') {
        let q = q.split('#').next().unwrap_or("");
        for (name, value) in form_pairs(q) {
            out.push(Param {
                name: clip(&name),
                location: ParamWhere::Query,
                value: clip(&value),
            });
        }
    }
    let ct = content_type.unwrap_or("").to_ascii_lowercase();
    if ct.starts_with("application/x-www-form-urlencoded") {
        for (name, value) in form_pairs(&String::from_utf8_lossy(body)) {
            out.push(Param {
                name: clip(&name),
                location: ParamWhere::Form,
                value: clip(&value),
            });
        }
    } else if ct.contains("json")
        && let Ok(v) = serde_json::from_slice::<serde_json::Value>(body)
    {
        json_params(&v, "", 0, &mut out);
    }
    out.truncate(MAX_FINDINGS);
    out
}

// ---- Target analysis across the history

/// The most distinct endpoints, and the most distinct parameters, one analysis keeps. Past that, new ones are
/// counted nowhere and `truncated` is set.
pub const MAX_ANALYSIS_KEYS: usize = 5_000;
/// Distinct example values kept per parameter.
pub const MAX_SAMPLES: usize = 8;
/// Parameter names listed on one endpoint, and endpoints counted for one parameter.
const MAX_PER_KEY: usize = 100;

/// One recorded request, as the analysis sees it.
#[derive(Debug, Clone, Copy)]
pub struct Observation<'a> {
    pub method: &'a str,
    /// The request target: path and query.
    pub path: &'a str,
    pub status: Option<u16>,
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct StatusCount {
    pub status: u16,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct EndpointStat {
    pub method: String,
    /// The path without its query, with ids replaced: `/users/{n}`, `/files/{uuid}`, `/blob/{hex}`.
    pub path: String,
    pub count: u32,
    /// How often each response status came back (requests with no response are not listed).
    pub statuses: Vec<StatusCount>,
    /// The names of the parameters seen on this endpoint (at most 100).
    pub params: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ParamStat {
    pub name: String,
    #[serde(rename = "where")]
    pub location: ParamWhere,
    /// Requests that carried it.
    pub count: u32,
    /// Distinct endpoints it appeared on (counted up to 100).
    pub endpoints: u32,
    /// The first distinct values seen.
    pub values: Vec<String>,
    /// More distinct values than `values` holds: likely an identifier, a token or free text, not a flag.
    pub more_values: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct TargetAnalysis {
    /// Requests analysed.
    pub requests: u32,
    /// Most requested first.
    pub endpoints: Vec<EndpointStat>,
    pub params: Vec<ParamStat>,
    /// A limit was hit: there were more endpoints or parameters than are listed.
    pub truncated: bool,
}

/// A path segment that is an identifier becomes a placeholder, so `/users/1` and `/users/2` are one endpoint.
fn normalize_segment(seg: &str) -> &str {
    let b = seg.as_bytes();
    if b.is_empty() {
        return seg;
    }
    if b.iter().all(u8::is_ascii_digit) {
        return "{n}";
    }
    let is_uuid = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
    if is_uuid {
        return "{uuid}";
    }
    if b.len() >= 16 && b.iter().all(u8::is_ascii_hexdigit) {
        return "{hex}";
    }
    seg
}

/// The path of a request target with its query and fragment removed and its identifiers replaced.
pub fn normalize_path(target: &str) -> String {
    let path = target.split(['?', '#']).next().unwrap_or("");
    let path = if let Some(rest) = path
        .strip_prefix("http://")
        .or_else(|| path.strip_prefix("https://"))
    {
        rest.find('/').map_or("/", |i| &rest[i..])
    } else {
        path
    };
    let mut out = String::with_capacity(path.len());
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(normalize_segment(seg));
    }
    if out.is_empty() {
        out.push('/');
    }
    let mut t: String = out.chars().take(MAX_VALUE).collect();
    if t.len() < out.len() {
        t.push('…');
    }
    t
}

#[derive(Default)]
struct EndpointAcc {
    count: u32,
    statuses: std::collections::BTreeMap<u16, u32>,
    params: std::collections::BTreeSet<String>,
}

#[derive(Default)]
struct ParamAcc {
    count: u32,
    endpoints: std::collections::BTreeSet<usize>,
    values: std::collections::BTreeSet<String>,
    more: bool,
}

/// Accumulates requests into a [`TargetAnalysis`]. Memory is bounded by [`MAX_ANALYSIS_KEYS`] and the per-key caps,
/// not by how many requests are added.
#[derive(Default)]
pub struct Analyzer {
    requests: u32,
    endpoint_ix: std::collections::HashMap<(String, String), usize>,
    endpoints: Vec<((String, String), EndpointAcc)>,
    params: std::collections::HashMap<(String, ParamWhere), ParamAcc>,
    truncated: bool,
}

impl Analyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, o: &Observation<'_>) {
        self.requests = self.requests.saturating_add(1);
        let key = (o.method.to_ascii_uppercase(), normalize_path(o.path));
        let ix = match self.endpoint_ix.get(&key) {
            Some(&i) => Some(i),
            None if self.endpoints.len() < MAX_ANALYSIS_KEYS => {
                self.endpoints.push((key.clone(), EndpointAcc::default()));
                self.endpoint_ix.insert(key, self.endpoints.len() - 1);
                Some(self.endpoints.len() - 1)
            }
            None => {
                self.truncated = true;
                None
            }
        };
        if let Some(i) = ix {
            let e = &mut self.endpoints[i].1;
            e.count = e.count.saturating_add(1);
            if let Some(s) = o.status {
                let c = e.statuses.entry(s).or_insert(0);
                *c = c.saturating_add(1);
            }
        }
        for p in parameters(o.path, o.content_type, o.body) {
            let pk = (p.name.clone(), p.location);
            if !self.params.contains_key(&pk) && self.params.len() >= MAX_ANALYSIS_KEYS {
                self.truncated = true;
                continue;
            }
            if let Some(i) = ix {
                let e = &mut self.endpoints[i].1;
                if e.params.len() < MAX_PER_KEY || e.params.contains(&p.name) {
                    e.params.insert(p.name.clone());
                }
            }
            let acc = self.params.entry(pk).or_default();
            acc.count = acc.count.saturating_add(1);
            if let Some(i) = ix
                && (acc.endpoints.len() < MAX_PER_KEY || acc.endpoints.contains(&i))
            {
                acc.endpoints.insert(i);
            }
            if acc.values.len() < MAX_SAMPLES {
                acc.values.insert(p.value);
            } else if !acc.values.contains(&p.value) {
                acc.more = true;
            }
        }
    }

    pub fn finish(self) -> TargetAnalysis {
        let mut endpoints: Vec<EndpointStat> = self
            .endpoints
            .into_iter()
            .map(|((method, path), a)| EndpointStat {
                method,
                path,
                count: a.count,
                statuses: a
                    .statuses
                    .into_iter()
                    .map(|(status, count)| StatusCount { status, count })
                    .collect(),
                params: a.params.into_iter().collect(),
            })
            .collect();
        endpoints.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.method.cmp(&b.method))
        });
        let mut params: Vec<ParamStat> = self
            .params
            .into_iter()
            .map(|((name, location), a)| ParamStat {
                name,
                location,
                count: a.count,
                endpoints: u32::try_from(a.endpoints.len()).unwrap_or(u32::MAX),
                values: a.values.into_iter().collect(),
                more_values: a.more,
            })
            .collect();
        params.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.location.cmp(&b.location))
        });
        TargetAnalysis {
            requests: self.requests,
            endpoints,
            params,
            truncated: self.truncated,
        }
    }
}

// ---- CSRF proof of concept

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PocError {
    #[error("only http and https requests can be turned into a form")]
    Scheme,
    #[error("a form can only send GET or POST, and this request is {0}")]
    Method(String),
    #[error("{0}")]
    Unsupported(String),
}

pub struct PocInput<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
    /// Submit the form as soon as the page loads.
    pub auto_submit: bool,
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            // A control character has no business in an attribute, and a line break could end an HTML comment.
            c if c.is_control() && c != '\n' && c != '\t' => {}
            c => o.push(c),
        }
    }
    o
}

/// The text of a multipart part's `name="..."`, if it has one and it is not a file.
fn multipart_fields(ct: &str, body: &[u8]) -> Result<Vec<(String, String)>, PocError> {
    let boundary = ct
        .split(';')
        .filter_map(|p| p.trim().strip_prefix("boundary="))
        .next()
        .map(|b| b.trim_matches('"'))
        .filter(|b| !b.is_empty() && b.len() <= 200)
        .ok_or_else(|| PocError::Unsupported("the multipart body has no boundary".into()))?;
    let text = String::from_utf8_lossy(body);
    let delim = format!("--{boundary}");
    let mut fields = Vec::new();
    for part in text.split(&delim).skip(1) {
        if part.starts_with("--") {
            break;
        }
        let part = part
            .strip_prefix("\r\n")
            .or_else(|| part.strip_prefix('\n'))
            .unwrap_or(part);
        let Some((head, value)) = part.split_once("\r\n\r\n").or_else(|| part.split_once("\n\n")) else {
            continue;
        };
        let disp = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-disposition"))
            .unwrap_or("");
        if disp.to_ascii_lowercase().contains("filename=") {
            return Err(PocError::Unsupported(
                "the request uploads a file, which a form on another site cannot reproduce faithfully".into(),
            ));
        }
        let name = disp
            .split(';')
            .filter_map(|p| p.trim().strip_prefix("name="))
            .next()
            .map(|n| n.trim_matches('"').to_string());
        if let Some(name) = name {
            let value = value
                .strip_suffix("\r\n")
                .or_else(|| value.strip_suffix('\n'))
                .unwrap_or(value);
            fields.push((name, value.to_string()));
        }
        if fields.len() >= MAX_FINDINGS {
            break;
        }
    }
    Ok(fields)
}

/// An HTML page with a form that sends the recorded request from the victim's browser. Every value is escaped.
pub fn csrf_poc(r: &PocInput<'_>) -> Result<String, PocError> {
    let lower = r.url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return Err(PocError::Scheme);
    }
    let method = r.method.to_ascii_uppercase();
    if method != "GET" && method != "POST" {
        return Err(PocError::Method(method));
    }
    let ct = r.content_type.unwrap_or("").trim().to_ascii_lowercase();
    let (action, mut fields, enctype): (String, Vec<(String, String)>, &str) = if method == "GET" {
        // A GET form replaces the query string with its fields, so move the query into fields.
        let (base, query) = r.url.split_once('?').unwrap_or((r.url, ""));
        (
            base.to_string(),
            form_pairs(query.split('#').next().unwrap_or("")),
            "application/x-www-form-urlencoded",
        )
    } else if ct.is_empty() || ct.starts_with("application/x-www-form-urlencoded") {
        (
            r.url.to_string(),
            form_pairs(&String::from_utf8_lossy(r.body)),
            "application/x-www-form-urlencoded",
        )
    } else if ct.starts_with("multipart/form-data") {
        (
            r.url.to_string(),
            multipart_fields(r.content_type.unwrap_or(""), r.body)?,
            "multipart/form-data",
        )
    } else if ct.starts_with("application/json") || ct.starts_with("text/plain") {
        // A form can send any text with enctype text/plain: the name and value are joined with "=". Put the body in
        // the name, up to its last "}", and end it with a throw-away member so the "=" lands inside a string.
        let text = String::from_utf8_lossy(r.body);
        let t = text.trim();
        let Some(inner) = t.strip_prefix('{').and_then(|t| t.strip_suffix('}')) else {
            return Err(PocError::Unsupported(
                "only a JSON object can be sent from a form (as text/plain); this body is not one".into(),
            ));
        };
        let sep = if inner.trim().is_empty() { "" } else { "," };
        (
            r.url.to_string(),
            vec![(format!("{{{inner}{sep}\"padding\":\""), "\"}".to_string())],
            "text/plain",
        )
    } else {
        return Err(PocError::Unsupported(format!(
            "a form cannot send a body of type {ct}; the request has to be replayed another way"
        )));
    };
    fields.truncate(MAX_FINDINGS);
    let mut html = String::new();
    html.push_str("<!doctype html>\n<meta charset=\"utf-8\">\n<title>CSRF proof of concept</title>\n");
    html.push_str("<!-- Made by Bosun for testing a system you are authorised to test. Open this file in a test browser that is\n     signed in to the target; it sends the request below from that browser. -->\n");
    html.push_str(&format!(
        "<h1>CSRF proof of concept</h1>\n<p>{} {}</p>\n",
        esc(&method),
        esc(&action)
    ));
    html.push_str(&format!(
        "<form id=\"poc\" action=\"{}\" method=\"{}\" enctype=\"{}\">\n",
        esc(&action),
        method.to_ascii_lowercase(),
        enctype
    ));
    for (n, v) in &fields {
        html.push_str(&format!(
            "  <input type=\"hidden\" name=\"{}\" value=\"{}\">\n",
            esc(n),
            esc(v)
        ));
    }
    html.push_str("  <button type=\"submit\">Send the request</button>\n</form>\n");
    if r.auto_submit {
        // Called through the prototype: a field named "submit" would hide form.submit.
        html.push_str(
            "<script>HTMLFormElement.prototype.submit.call(document.getElementById(\"poc\"));</script>\n",
        );
    }
    Ok(html)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_groups_endpoints_and_counts_parameters() {
        let mut a = Analyzer::new();
        let get = |path: &'static str, status| Observation {
            method: "get",
            path,
            status: Some(status),
            content_type: None,
            body: b"",
        };
        a.add(&get("/users/1?x=1&debug=1", 200));
        a.add(&get("/users/2?x=2", 200));
        a.add(&get("/users/3?x=3", 404));
        a.add(&get("/files/123e4567-e89b-12d3-a456-426614174000", 200));
        a.add(&Observation {
            method: "POST",
            path: "/login",
            status: Some(302),
            content_type: Some("application/x-www-form-urlencoded"),
            body: b"u=a&p=b&x=9",
        });
        a.add(&get("http://t.test/users/4#frag", 200));
        let r = a.finish();
        assert_eq!(r.requests, 6);
        assert!(!r.truncated);
        assert_eq!(
            (
                r.endpoints[0].method.as_str(),
                r.endpoints[0].path.as_str(),
                r.endpoints[0].count
            ),
            ("GET", "/users/{n}", 4)
        );
        assert_eq!(
            r.endpoints[0].statuses,
            vec![
                StatusCount {
                    status: 200,
                    count: 3
                },
                StatusCount {
                    status: 404,
                    count: 1
                }
            ]
        );
        assert_eq!(r.endpoints[0].params, vec!["debug", "x"]);
        assert!(r.endpoints.iter().any(|e| e.path == "/files/{uuid}"));
        let x_query = r
            .params
            .iter()
            .find(|p| p.name == "x" && p.location == ParamWhere::Query)
            .unwrap();
        assert_eq!(
            (x_query.count, x_query.endpoints, x_query.values.len()),
            (3, 1, 3)
        );
        let x_form = r
            .params
            .iter()
            .find(|p| p.name == "x" && p.location == ParamWhere::Form)
            .unwrap();
        assert_eq!(x_form.count, 1);
        assert_eq!(r.params[0].name, "x");
    }

    #[test]
    fn analysis_is_bounded() {
        let mut a = Analyzer::new();
        for i in 0..(MAX_ANALYSIS_KEYS + 50) {
            let path = format!("/p{i}?q{i}=v");
            a.add(&Observation {
                method: "GET",
                path: &path,
                status: None,
                content_type: None,
                body: b"",
            });
        }
        for i in 0..100 {
            let path = format!("/same?k=value{i}");
            a.add(&Observation {
                method: "GET",
                path: &path,
                status: None,
                content_type: None,
                body: b"",
            });
        }
        let r = a.finish();
        assert!(r.truncated);
        assert_eq!(r.endpoints.len(), MAX_ANALYSIS_KEYS);
        assert!(r.params.len() <= MAX_ANALYSIS_KEYS);
        assert!(r.params.iter().all(|p| p.values.len() <= MAX_SAMPLES));
        assert_eq!(normalize_path("/a/b/"), "/a/b/");
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/x/0123456789abcdef/y"), "/x/{hex}/y");
        assert_eq!(normalize_path("/v1/abc"), "/v1/abc");
    }

    #[test]
    fn many_values_are_flagged() {
        let mut a = Analyzer::new();
        for i in 0..(MAX_SAMPLES + 3) {
            let path = format!("/s?id={i}");
            a.add(&Observation {
                method: "GET",
                path: &path,
                status: None,
                content_type: None,
                body: b"",
            });
        }
        let r = a.finish();
        assert!(r.params[0].more_values);
        assert_eq!(r.params[0].values.len(), MAX_SAMPLES);
    }

    const PAGE: &str = r#"<!doctype html><html><head><title>x</title>
<!-- TODO: remove the debug admin at /admin-old -->
<link rel="stylesheet" href="/static/app.css">
<script src="https://cdn.example.net/lib.js"></script>
<script>var api = "/api/v1/users"; fetch('/api/v1/orders?id=1');</script>
</head><body>
<a href="/account">Account</a> <a href=/bare>bare</a> <a>no href</a>
<form action="/login" method="post"><input name=user><input type="image" src="/img/go.png"></form>
<form method="get"></form>
<img src='/logo.png'><iframe src="//ads.example.org/f"></iframe>
<p>see https://docs.example.com/guide?x=1&y=2 for more</p>
<!-- unterminated comment at the end"#;

    fn kinds(f: &[Finding], k: FindingKind) -> Vec<&str> {
        f.iter()
            .filter(|x| x.kind == k)
            .map(|x| x.value.as_str())
            .collect()
    }

    #[test]
    fn a_page_gives_its_comments_scripts_and_references() {
        let f = find_in_html(PAGE);
        assert_eq!(
            kinds(&f, FindingKind::Comment),
            [
                "TODO: remove the debug admin at /admin-old",
                "unterminated comment at the end"
            ]
        );
        assert_eq!(
            kinds(&f, FindingKind::ScriptSrc),
            ["https://cdn.example.net/lib.js"]
        );
        assert_eq!(kinds(&f, FindingKind::InlineScript).len(), 1);
        assert!(kinds(&f, FindingKind::InlineScript)[0].contains("/api/v1/users"));
        assert_eq!(
            kinds(&f, FindingKind::Link),
            ["/static/app.css", "/account", "/bare"]
        );
        assert_eq!(kinds(&f, FindingKind::FormAction), ["/login", ""]);
        assert_eq!(
            kinds(&f, FindingKind::Resource),
            ["/img/go.png", "/logo.png", "//ads.example.org/f"]
        );
        // The offsets point at what was found.
        let c = f.iter().find(|x| x.kind == FindingKind::Comment).unwrap();
        assert!(PAGE[c.offset..].starts_with("<!--"));
    }

    #[test]
    fn urls_and_quoted_paths_are_found_in_any_text() {
        let f = find_urls(PAGE);
        assert!(kinds(&f, FindingKind::Url).contains(&"https://docs.example.com/guide?x=1&y=2"));
        let paths = kinds(&f, FindingKind::Path);
        assert!(paths.contains(&"/api/v1/users"), "{paths:?}");
        assert!(paths.contains(&"/api/v1/orders?id=1"), "{paths:?}");
        // "/" alone, "//" and an unterminated string are not paths.
        assert!(find_urls(r#"x = "/"; y = "//cdn"; z = "/unterminated"#).is_empty());
    }

    #[test]
    fn results_are_capped_and_long_values_are_cut() {
        let many = "<!--a-->".repeat(MAX_FINDINGS * 2);
        assert_eq!(find_in_html(&many).len(), MAX_FINDINGS);
        let long = format!("<!--{}-->", "x".repeat(MAX_VALUE * 3));
        let f = find_in_html(&long);
        assert_eq!(f[0].value.chars().count(), MAX_VALUE + 1);
        assert!(f[0].value.ends_with('…'));
    }

    #[test]
    fn hostile_markup_does_not_stall_or_panic() {
        for s in [
            "<",
            "<a",
            "<a href",
            "<a href=",
            "<a href=\"",
            "<a \"\"\" '''>",
            "<script",
            "<script>",
            "<!--",
            "<!-",
            "</",
            "<<<<<",
            "<a =b>",
            "<a b= >",
            "\u{0}<a href=x>",
        ] {
            let _ = find_in_html(s);
            let _ = find_urls(s);
        }
        let big = "<a ".repeat(100_000);
        assert!(find_in_html(&big).len() <= MAX_FINDINGS);
    }

    #[test]
    fn parameters_come_from_the_query_a_form_body_and_json() {
        let p = parameters(
            "/a?x=1&y=two%20words&z",
            Some("application/x-www-form-urlencoded"),
            b"user=bob&pw=p%26w+d",
        );
        let got: Vec<_> = p
            .iter()
            .map(|p| (p.name.as_str(), p.location, p.value.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("x", ParamWhere::Query, "1"),
                ("y", ParamWhere::Query, "two words"),
                ("z", ParamWhere::Query, ""),
                ("user", ParamWhere::Form, "bob"),
                ("pw", ParamWhere::Form, "p&w d"),
            ]
        );
        let j = parameters(
            "/b",
            Some("application/json; charset=utf-8"),
            br#"{"a":{"b":[1,2],"c":"x"},"d":null}"#,
        );
        let names: Vec<_> = j.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["a.b[]", "a.b[]", "a.c", "d"]);
        assert!(parameters("/c", Some("application/json"), b"{not json").is_empty());
    }

    #[test]
    fn a_form_post_becomes_a_form_with_every_value_escaped() {
        let html = csrf_poc(&PocInput {
            method: "post",
            url: "https://bank.test/transfer",
            content_type: Some("application/x-www-form-urlencoded"),
            body: b"to=mallory&amount=100&note=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            auto_submit: false,
        })
        .unwrap();
        assert!(html.contains("<form id=\"poc\" action=\"https://bank.test/transfer\" method=\"post\" enctype=\"application/x-www-form-urlencoded\">"));
        assert!(html.contains("<input type=\"hidden\" name=\"to\" value=\"mallory\">"));
        assert!(
            html.contains("value=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""),
            "{html}"
        );
        assert!(!html.contains("<script>alert(1)"));
        assert!(!html.contains("<script>"), "no script unless asked");
        let auto = csrf_poc(&PocInput {
            auto_submit: true,
            method: "POST",
            url: "http://x.test/",
            content_type: None,
            body: b"a=1",
        })
        .unwrap();
        assert!(auto.contains("HTMLFormElement.prototype.submit.call"));
    }

    #[test]
    fn a_hostile_url_or_field_cannot_break_out_of_the_page() {
        let html = csrf_poc(&PocInput {
            method: "POST",
            url: "http://x.test/\"><script>alert(1)</script>",
            content_type: None,
            body: b"a\"onmouseover=\"alert(1)=--><b>",
            auto_submit: false,
        })
        .unwrap();
        assert!(!html.contains("<script>alert"), "{html}");
        assert!(!html.contains("\"onmouseover=\""), "{html}");
        // The comment banner never contains target text, so it cannot be closed early.
        assert_eq!(html.matches("-->").count(), 1);
    }

    #[test]
    fn json_and_multipart_and_get_and_refusals() {
        let json = csrf_poc(&PocInput {
            method: "POST",
            url: "https://a.test/api",
            content_type: Some("application/json"),
            body: br#"{"to":"m","n":1}"#,
            auto_submit: false,
        })
        .unwrap();
        assert!(json.contains("enctype=\"text/plain\""));
        assert!(json.contains("name=\"{&quot;to&quot;:&quot;m&quot;,&quot;n&quot;:1,&quot;padding&quot;:&quot;\" value=\"&quot;}\""), "{json}");
        let body = b"--XX\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--XX\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\ntwo\r\n--XX--\r\n";
        let mp = csrf_poc(&PocInput {
            method: "POST",
            url: "https://a.test/u",
            content_type: Some("multipart/form-data; boundary=XX"),
            body,
            auto_submit: false,
        })
        .unwrap();
        assert!(mp.contains("enctype=\"multipart/form-data\"") && mp.contains("name=\"b\" value=\"two\""));
        let get = csrf_poc(&PocInput {
            method: "GET",
            url: "https://a.test/do?x=1&y=2",
            content_type: None,
            body: b"",
            auto_submit: false,
        })
        .unwrap();
        assert!(
            get.contains("action=\"https://a.test/do\" method=\"get\"")
                && get.contains("name=\"y\" value=\"2\"")
        );
        let upload =
            b"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nx\r\n--XX--\r\n";
        assert!(matches!(
            csrf_poc(&PocInput {
                method: "POST",
                url: "https://a.test/u",
                content_type: Some("multipart/form-data; boundary=XX"),
                body: upload,
                auto_submit: false
            }),
            Err(PocError::Unsupported(_))
        ));
        assert_eq!(
            csrf_poc(&PocInput {
                method: "PUT",
                url: "https://a.test/",
                content_type: None,
                body: b"",
                auto_submit: false
            }),
            Err(PocError::Method("PUT".into()))
        );
        assert_eq!(
            csrf_poc(&PocInput {
                method: "POST",
                url: "javascript:alert(1)",
                content_type: None,
                body: b"",
                auto_submit: false
            }),
            Err(PocError::Scheme)
        );
        assert!(matches!(
            csrf_poc(&PocInput {
                method: "POST",
                url: "https://a.test/",
                content_type: Some("application/octet-stream"),
                body: b"x",
                auto_submit: false
            }),
            Err(PocError::Unsupported(_))
        ));
        assert!(matches!(
            csrf_poc(&PocInput {
                method: "POST",
                url: "https://a.test/",
                content_type: Some("application/json"),
                body: b"[1]",
                auto_submit: false
            }),
            Err(PocError::Unsupported(_))
        ));
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn scanners_are_total_and_bounded(s in ".{0,2000}") {
                for f in find_in_html(&s).into_iter().chain(find_urls(&s)) {
                    prop_assert!(f.offset <= s.len());
                    prop_assert!(f.value.chars().count() <= MAX_VALUE + 1);
                }
                let _ = parameters(&s, Some("application/x-www-form-urlencoded"), s.as_bytes());
                let _ = parameters(&s, Some("application/json"), s.as_bytes());
            }

            #[test]
            fn a_poc_never_holds_unescaped_markup_from_the_request(body in "[a-z=&<>\"' %0-9]{0,200}") {
                if let Ok(html) = csrf_poc(&PocInput { method: "POST", url: "https://a.test/p", content_type: None, body: body.as_bytes(), auto_submit: false }) {
                    // Past the banner, the only tags are the ones this function writes.
                    let tags = html.matches('<').count();
                    let ours = html.matches("<!doctype").count() + html.matches("<meta").count() + html.matches("<title>").count()
                        + html.matches("</title>").count() + html.matches("<!--").count() + html.matches("<h1>").count()
                        + html.matches("</h1>").count() + html.matches("<p>").count() + html.matches("</p>").count()
                        + html.matches("<form ").count() + html.matches("</form>").count() + html.matches("<input ").count()
                        + html.matches("<button ").count() + html.matches("</button>").count();
                    prop_assert_eq!(tags, ours, "{}", html);
                }
            }
        }
    }
}
