//! The check language, version 1.
//!
//! ```yaml
//! version: 1
//! id: stack-trace-disclosure
//! info:
//!   name: Stack trace in a response
//!   severity: low            # info | low | medium | high
//!   confidence: firm         # tentative | firm | certain (default firm)
//!   remediation: Turn off debug output.
//!   cwe: [209]
//!   owasp: ["A05:2021 Security Misconfiguration"]
//! source:                    # only for imported or ported checks: where it came from and under what licence
//!   origin: nuclei-templates
//!   id: some-template
//!   license: MIT
//! passive:                   # a check on recorded flows ...
//!   matchers-condition: or   # and | or (default or)
//!   matchers:
//!     - type: regex          # word | regex | status
//!       part: body           # body | header | all | request (default body)
//!       regex: ['Traceback \(most recent call last\)']
//!       condition: or        # for several words or regexes (default or)
//!       negative: false      # the matcher holds when nothing matched
//!       case-insensitive: false
//!   extractors:
//!     - type: regex          # regex | kval
//!       regex: ['File "([^"]+)"']
//!       group: 1
//! requests:                  # ... or an active check: requests to send (the scan engine sends them, WP-54)
//!   - method: GET
//!     path: ["{{BaseURL}}/.git/config"]
//!     headers: { X-Probe: "{{interactsh-url}}" }   # an OAST hook: the scan engine supplies a callback address
//!     matchers: [{ type: word, words: ["[core]"] }]
//!     matchers-condition: and
//! ```
//!
//! A check has exactly one of `passive` and `requests`. Unknown fields are errors, so a typo is not a silently
//! disabled check. Everything is bounded (size, number of matchers, patterns, regex size), regexes are the `regex`
//! crate's (linear time), and a check cannot run code. `part: interactsh_protocol` and `interactsh_request` match
//! on an out-of-band interaction and are only valid in `requests`.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

use bosun_store::{Confidence, Evidence, EvidencePart, Severity};
use regex::bytes::{Regex, RegexBuilder};
use serde::Deserialize;

use crate::head::Head;

/// The only version this build reads.
pub const VERSION: u32 = 1;
/// Largest check document read.
pub const MAX_SOURCE: usize = 256 * 1024;
const MAX_MATCHERS: usize = 32;
const MAX_EXTRACTORS: usize = 16;
const MAX_PATTERNS: usize = 64;
const MAX_STR: usize = 2048;
const MAX_REQUESTS: usize = 8;
const MAX_PATHS: usize = 16;
const MAX_HEADERS: usize = 32;
const REGEX_SIZE: usize = 1 << 20;
/// How much of a body is matched.
const BODY_LIMIT: usize = 1 << 20;
const MAX_EXTRACTED: usize = 8;

/// The variables a request template may use.
pub const VARIABLES: &[&str] = &[
    "BaseURL",
    "RootURL",
    "Hostname",
    "Host",
    "Port",
    "Scheme",
    "interactsh-url",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckError(pub String);

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CheckError {}

fn err<T>(m: impl Into<String>) -> Result<T, CheckError> {
    Err(CheckError(m.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sev {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Conf {
    Tentative,
    Firm,
    Certain,
}

impl Sev {
    pub fn to_store(self) -> Severity {
        match self {
            Self::Info => Severity::Info,
            Self::Low => Severity::Low,
            Self::Medium => Severity::Medium,
            Self::High => Severity::High,
        }
    }
}

impl Conf {
    pub fn to_store(self) -> Confidence {
        match self {
            Self::Tentative => Confidence::Tentative,
            Self::Firm => Confidence::Firm,
            Self::Certain => Confidence::Certain,
        }
    }
}

fn firm() -> Conf {
    Conf::Firm
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub name: String,
    pub severity: Sev,
    #[serde(default = "firm")]
    pub confidence: Conf,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub cwe: Vec<u32>,
    #[serde(default)]
    pub owasp: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub reference: Vec<String>,
}

/// Where an imported or ported check came from. Kept so notices and licences travel with the check.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub origin: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub notice: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cond {
    And,
    #[default]
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Part {
    #[default]
    Body,
    Header,
    #[serde(alias = "response")]
    All,
    Request,
    #[serde(rename = "interactsh_protocol")]
    InteractshProtocol,
    #[serde(rename = "interactsh_request")]
    InteractshRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatcherKind {
    Word,
    Regex,
    Status,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub kind: MatcherKind,
    #[serde(default)]
    pub part: Part,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub condition: Cond,
    #[serde(default)]
    pub negative: bool,
    #[serde(default, rename = "case-insensitive")]
    pub case_insensitive: bool,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtractorKind {
    Regex,
    Kval,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extractor {
    #[serde(rename = "type")]
    pub kind: ExtractorKind,
    #[serde(default)]
    pub part: Part,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub group: usize,
    #[serde(default)]
    pub kval: Vec<String>,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Passive {
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Cond,
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

fn get() -> String {
    "GET".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default = "get")]
    pub method: String,
    pub path: Vec<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Cond,
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub version: u32,
    pub id: String,
    pub info: Info,
    #[serde(default)]
    pub source: Option<Source>,
    #[serde(default)]
    pub passive: Option<Passive>,
    #[serde(default)]
    pub requests: Vec<Request>,
}

/// An out-of-band interaction the scan engine saw for a request it sent: `protocol` is `dns`, `http` or `smtp`,
/// `request` what the callback server received.
#[derive(Debug, Clone, Default)]
pub struct Interaction {
    pub protocol: String,
    pub request: Vec<u8>,
}

/// What a check found: the highlighted ranges and the values its extractors took out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hit {
    pub evidence: Vec<Evidence>,
    pub extracted: Vec<(String, String)>,
}

/// The message a check is matched against.
pub struct Message<'a> {
    pub request: &'a [u8],
    pub response: &'a [u8],
    pub status: u16,
    pub interaction: Option<&'a Interaction>,
}

enum Test {
    Words { words: Vec<Vec<u8>>, nocase: bool },
    Regex(Vec<Regex>),
    Status(Vec<u16>),
}

struct CMatcher {
    part: Part,
    test: Test,
    cond: Cond,
    negative: bool,
}

enum CExtractor {
    Regex {
        part: Part,
        re: Vec<Regex>,
        group: usize,
        name: String,
    },
    Kval {
        names: Vec<String>,
        name: String,
    },
}

struct Set {
    cond: Cond,
    matchers: Vec<CMatcher>,
    extractors: Vec<CExtractor>,
}

/// A validated check with its regexes built.
pub struct Compiled {
    pub check: Check,
    passive: Option<Set>,
    requests: Vec<Set>,
}

impl fmt::Debug for Compiled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Compiled")
            .field("id", &self.check.id)
            .finish_non_exhaustive()
    }
}

/// Read a check from YAML text and validate it.
pub fn parse(text: &str) -> Result<Compiled, CheckError> {
    if text.len() > MAX_SOURCE {
        return err(format!("the check is larger than {} KiB", MAX_SOURCE / 1024));
    }
    let check: Check =
        serde_saphyr::from_str(text).map_err(|e| CheckError(format!("not a valid check: {e}")))?;
    Compiled::new(check)
}

impl Compiled {
    /// Validate `check` and build its regexes.
    pub fn new(check: Check) -> Result<Self, CheckError> {
        if check.version != VERSION {
            return err(format!(
                "unsupported check version {} (this build reads version {VERSION})",
                check.version
            ));
        }
        valid_id(&check.id)?;
        let i = &check.info;
        if i.name.trim().is_empty() || i.name.len() > 200 {
            return err("info.name must be 1 to 200 characters");
        }
        for s in [&i.description, &i.remediation] {
            if s.len() > 8192 {
                return err("info text is longer than 8192 characters");
            }
        }
        if i.cwe.len() > 16 || i.owasp.len() > 16 || i.tags.len() > 32 || i.reference.len() > 16 {
            return err("too many cwe, owasp, tags or reference entries");
        }
        match (&check.passive, check.requests.is_empty()) {
            (Some(_), false) => return err("a check has either `passive` or `requests`, not both"),
            (None, true) => return err("a check needs `passive` or `requests`"),
            _ => {}
        }
        if check.requests.len() > MAX_REQUESTS {
            return err(format!("at most {MAX_REQUESTS} requests"));
        }
        let passive = match &check.passive {
            Some(p) => Some(build_set(
                p.matchers_condition,
                &p.matchers,
                &p.extractors,
                false,
            )?),
            None => None,
        };
        let mut requests = Vec::new();
        for r in &check.requests {
            valid_request(r)?;
            requests.push(build_set(r.matchers_condition, &r.matchers, &r.extractors, true)?);
        }
        Ok(Self {
            check,
            passive,
            requests,
        })
    }

    pub fn is_passive(&self) -> bool {
        self.passive.is_some()
    }

    /// Whether any request carries an OAST hook (`{{interactsh-url}}`), so the engine must start a callback
    /// listener for it.
    pub fn uses_oast(&self) -> bool {
        self.check.requests.iter().any(|r| {
            r.path
                .iter()
                .chain(r.headers.values())
                .any(|s| s.contains("{{interactsh-url}}"))
                || r.body.contains("{{interactsh-url}}")
                || r.matchers.iter().any(|m| is_oast(m.part))
        })
    }

    /// Match the passive part against a recorded message. `None` for an active check or no match.
    pub fn eval_passive(&self, msg: &Message<'_>) -> Option<Hit> {
        run(self.passive.as_ref()?, msg)
    }

    /// Match request number `index` against what came back (the scan engine's side of an active check).
    pub fn eval_request(&self, index: usize, msg: &Message<'_>) -> Option<Hit> {
        run(self.requests.get(index)?, msg)
    }
}

fn is_oast(p: Part) -> bool {
    matches!(p, Part::InteractshProtocol | Part::InteractshRequest)
}

fn valid_id(id: &str) -> Result<(), CheckError> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok {
        Ok(())
    } else {
        err("id must be 1 to 64 characters of a-z, 0-9 and '-', not starting with '-'")
    }
}

fn valid_request(r: &Request) -> Result<(), CheckError> {
    if r.method.is_empty() || r.method.len() > 16 || !r.method.bytes().all(|b| b.is_ascii_uppercase()) {
        return err("request method must be upper-case letters");
    }
    if r.path.is_empty() || r.path.len() > MAX_PATHS {
        return err(format!("a request needs 1 to {MAX_PATHS} paths"));
    }
    if r.headers.len() > MAX_HEADERS {
        return err(format!("at most {MAX_HEADERS} headers per request"));
    }
    for p in &r.path {
        if !(p.starts_with("{{BaseURL}}") || p.starts_with("{{RootURL}}") || p.starts_with('/')) {
            return err(
                "a path must start with {{BaseURL}}, {{RootURL}} or '/' (a check cannot choose another host)",
            );
        }
        template_ok(p)?;
    }
    for (k, v) in &r.headers {
        if k.is_empty()
            || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || v.bytes().any(|b| b == b'\r' || b == b'\n')
        {
            return err("header names are letters, digits and '-'; values have no line breaks");
        }
        template_ok(v)?;
    }
    template_ok(&r.body)
}

/// Every `{{name}}` must be a known variable and closed.
fn template_ok(s: &str) -> Result<(), CheckError> {
    if s.len() > 8192 {
        return err("a request template is longer than 8192 characters");
    }
    let mut rest = s;
    while let Some(i) = rest.find("{{") {
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else {
            return err("a `{{` in a template is never closed");
        };
        let name = after[..j].trim();
        if !VARIABLES.contains(&name) {
            return err(format!(
                "unknown template variable `{}`",
                name.chars().take(40).collect::<String>()
            ));
        }
        rest = &after[j + 2..];
    }
    Ok(())
}

/// Replace the variables in a template. `vars` pairs a name with its value; an unknown name stays as it is.
pub fn expand(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else {
            out.push_str(&rest[i..]);
            return out;
        };
        let name = after[..j].trim();
        match vars.iter().find(|(k, _)| *k == name) {
            Some((_, v)) => out.push_str(v),
            None => {
                out.push_str("{{");
                out.push_str(&after[..j]);
                out.push_str("}}");
            }
        }
        rest = &after[j + 2..];
    }
    out.push_str(rest);
    out
}

fn regex(p: &str, nocase: bool) -> Result<Regex, CheckError> {
    if p.is_empty() || p.len() > MAX_STR {
        return err(format!("a pattern must be 1 to {MAX_STR} characters"));
    }
    RegexBuilder::new(p)
        .case_insensitive(nocase)
        .size_limit(REGEX_SIZE)
        .dfa_size_limit(REGEX_SIZE)
        .nest_limit(64)
        .build()
        .map_err(|e| {
            CheckError(format!(
                "bad regex: {}",
                e.to_string().lines().last().unwrap_or("error")
            ))
        })
}

fn build_set(cond: Cond, ms: &[Matcher], es: &[Extractor], active: bool) -> Result<Set, CheckError> {
    if ms.is_empty() || ms.len() > MAX_MATCHERS {
        return err(format!("a check needs 1 to {MAX_MATCHERS} matchers"));
    }
    if es.len() > MAX_EXTRACTORS {
        return err(format!("at most {MAX_EXTRACTORS} extractors"));
    }
    let mut matchers = Vec::new();
    for m in ms {
        if is_oast(m.part) && !active {
            return err("interactsh parts are only valid in `requests`");
        }
        let test = match m.kind {
            MatcherKind::Word => {
                if m.words.is_empty()
                    || m.words.len() > MAX_PATTERNS
                    || !m.regex.is_empty()
                    || !m.status.is_empty()
                {
                    return err(format!(
                        "a word matcher needs 1 to {MAX_PATTERNS} words and nothing else"
                    ));
                }
                if m.words.iter().any(|w| w.is_empty() || w.len() > MAX_STR) {
                    return err(format!("a word must be 1 to {MAX_STR} characters"));
                }
                let words = m
                    .words
                    .iter()
                    .map(|w| {
                        if m.case_insensitive {
                            w.to_ascii_lowercase()
                        } else {
                            w.clone()
                        }
                        .into_bytes()
                    })
                    .collect();
                Test::Words {
                    words,
                    nocase: m.case_insensitive,
                }
            }
            MatcherKind::Regex => {
                if m.regex.is_empty()
                    || m.regex.len() > MAX_PATTERNS
                    || !m.words.is_empty()
                    || !m.status.is_empty()
                {
                    return err(format!(
                        "a regex matcher needs 1 to {MAX_PATTERNS} regexes and nothing else"
                    ));
                }
                Test::Regex(
                    m.regex
                        .iter()
                        .map(|r| regex(r, m.case_insensitive))
                        .collect::<Result<_, _>>()?,
                )
            }
            MatcherKind::Status => {
                if m.status.is_empty()
                    || m.status.len() > MAX_PATTERNS
                    || !m.words.is_empty()
                    || !m.regex.is_empty()
                    || m.status.iter().any(|s| !(100..=599).contains(s))
                {
                    return err("a status matcher needs statuses from 100 to 599 and nothing else");
                }
                Test::Status(m.status.clone())
            }
        };
        matchers.push(CMatcher {
            part: m.part,
            test,
            cond: m.condition,
            negative: m.negative,
        });
    }
    let mut extractors = Vec::new();
    for e in es {
        extractors.push(match e.kind {
            ExtractorKind::Regex => {
                if e.regex.is_empty() || e.regex.len() > MAX_PATTERNS || !e.kval.is_empty() {
                    return err("a regex extractor needs regexes and no kval");
                }
                let re = e
                    .regex
                    .iter()
                    .map(|r| regex(r, false))
                    .collect::<Result<Vec<_>, _>>()?;
                if re.iter().any(|r| e.group >= r.captures_len()) {
                    return err("an extractor's group is beyond the groups of its regex");
                }
                CExtractor::Regex {
                    part: e.part,
                    re,
                    group: e.group,
                    name: e.name.clone(),
                }
            }
            ExtractorKind::Kval => {
                if e.kval.is_empty() || e.kval.len() > MAX_PATTERNS || !e.regex.is_empty() {
                    return err("a kval extractor needs header names and no regex");
                }
                CExtractor::Kval {
                    names: e.kval.iter().map(|k| k.replace('_', "-")).collect(),
                    name: e.name.clone(),
                }
            }
        });
    }
    Ok(Set {
        cond,
        matchers,
        extractors,
    })
}

/// A part of the message: the bytes, where they start in the stored message and which message that is.
struct View<'a> {
    bytes: &'a [u8],
    base: usize,
    part: EvidencePart,
}

struct Ctx<'a> {
    msg: &'a Message<'a>,
    rh: Head<'a>,
    body: Option<Range<usize>>,
}

impl<'a> Ctx<'a> {
    fn view(&self, p: Part) -> Option<View<'a>> {
        let r = self.msg.response;
        Some(match p {
            Part::Body => {
                let b = self.body.clone()?;
                View {
                    bytes: &r[b.clone()],
                    base: b.start,
                    part: EvidencePart::Response,
                }
            }
            Part::Header => View {
                bytes: &r[..self.rh.body.min(r.len())],
                base: 0,
                part: EvidencePart::Response,
            },
            Part::All => {
                let end = self.body.as_ref().map_or(self.rh.body.min(r.len()), |b| b.end);
                View {
                    bytes: &r[..end],
                    base: 0,
                    part: EvidencePart::Response,
                }
            }
            Part::Request => View {
                bytes: self.msg.request,
                base: 0,
                part: EvidencePart::Request,
            },
            Part::InteractshProtocol => View {
                bytes: self.msg.interaction?.protocol.as_bytes(),
                base: 0,
                part: EvidencePart::Response,
            },
            Part::InteractshRequest => View {
                bytes: &self.msg.interaction?.request,
                base: 0,
                part: EvidencePart::Response,
            },
        })
    }
}

/// The body as stored, unless it is compressed (it cannot be read as it is) or past the limit.
fn body_range(rh: &Head<'_>, resp: &[u8]) -> Option<Range<usize>> {
    if let Some(e) = rh.get("content-encoding")
        && !e.value.is_empty()
        && !e.value.eq_ignore_ascii_case("identity")
    {
        return None;
    }
    let b = resp.get(rh.body..)?;
    Some(rh.body..rh.body + b.len().min(BODY_LIMIT))
}

fn find(hay: &[u8], needle: &[u8], nocase: bool) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| {
        if nocase {
            w.eq_ignore_ascii_case(needle)
        } else {
            w == needle
        }
    })
}

/// Whether the matcher's patterns hold, and the ranges that made them hold.
fn test_one(m: &CMatcher, ctx: &Ctx<'_>) -> (bool, Vec<Evidence>) {
    if let Test::Status(v) = &m.test {
        return (v.contains(&ctx.msg.status), Vec::new());
    }
    // A part that cannot be read (a compressed body, no interaction) never matches, negative or not: not knowing
    // is not the same as not finding.
    let Some(view) = ctx.view(m.part) else {
        return (false, Vec::new());
    };
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut hits = 0usize;
    let total;
    match &m.test {
        Test::Words { words, nocase } => {
            total = words.len();
            for w in words {
                if let Some(i) = find(view.bytes, w, *nocase) {
                    hits += 1;
                    ranges.push((i, i + w.len()));
                }
            }
        }
        Test::Regex(res) => {
            total = res.len();
            for re in res {
                if let Some(x) = re.find(view.bytes) {
                    hits += 1;
                    ranges.push((x.start(), x.end()));
                }
            }
        }
        Test::Status(_) => unreachable!(),
    }
    let raw = match m.cond {
        Cond::Or => hits > 0,
        Cond::And => hits == total,
    };
    let held = raw != m.negative;
    let ev = if held && !m.negative {
        ranges
            .into_iter()
            .map(|(s, e)| Evidence {
                part: view.part,
                start: (view.base + s) as u64,
                end: (view.base + e) as u64,
            })
            .collect()
    } else {
        Vec::new()
    };
    (held, ev)
}

fn run(set: &Set, msg: &Message<'_>) -> Option<Hit> {
    let rh = Head::parse(msg.response);
    let body = body_range(&rh, msg.response);
    let ctx = Ctx { msg, rh, body };
    let mut evidence = Vec::new();
    let mut any = false;
    let mut all = true;
    for m in &set.matchers {
        let (held, ev) = test_one(m, &ctx);
        any |= held;
        all &= held;
        if held {
            evidence.extend(ev);
        }
    }
    let ok = match set.cond {
        Cond::Or => any,
        Cond::And => all,
    };
    if !ok {
        return None;
    }
    evidence.truncate(16);
    let mut extracted = Vec::new();
    'outer: for e in &set.extractors {
        let (name, vals): (&str, Vec<String>) = match e {
            CExtractor::Regex {
                part,
                re,
                group,
                name,
            } => {
                let mut v = Vec::new();
                if let Some(view) = ctx.view(*part) {
                    for r in re {
                        for c in r.captures_iter(view.bytes).take(MAX_EXTRACTED) {
                            if let Some(g) = c.get(*group) {
                                v.push(String::from_utf8_lossy(g.as_bytes()).into_owned());
                            }
                        }
                    }
                }
                (name, v)
            }
            CExtractor::Kval { names, name } => {
                let v = names
                    .iter()
                    .flat_map(|n| ctx.rh.all(n).map(|h| h.value.to_string()))
                    .collect();
                (name, v)
            }
        };
        for v in vals {
            if extracted.len() >= MAX_EXTRACTED {
                break 'outer;
            }
            extracted.push((name.to_string(), v.chars().take(120).collect()));
        }
    }
    Some(Hit { evidence, extracted })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "version: 1\nid: t\ninfo: {name: T, severity: low}\n";

    fn check(rest: &str) -> Result<Compiled, CheckError> {
        parse(&format!("{BASE}{rest}"))
    }

    fn msg<'a>(resp: &'a [u8], status: u16) -> Message<'a> {
        Message {
            request: b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n",
            response: resp,
            status,
            interaction: None,
        }
    }

    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.1\r\nContent-Type: text/html\r\n\r\n<h1>Hello World</h1> v=1.2.3";

    #[test]
    fn words_regexes_and_status() {
        let c = check("passive:\n  matchers:\n    - {type: word, words: [hello], case-insensitive: true}\n")
            .unwrap();
        let h = c.eval_passive(&msg(RESP, 200)).unwrap();
        let e = h.evidence[0];
        assert_eq!(&RESP[e.start as usize..e.end as usize], b"Hello");
        // Case matters by default.
        let c = check("passive:\n  matchers:\n    - {type: word, words: [hello]}\n").unwrap();
        assert!(c.eval_passive(&msg(RESP, 200)).is_none());
        let c =
            check("passive:\n  matchers:\n    - {type: regex, part: header, regex: ['Apache/[0-9.]+']}\n")
                .unwrap();
        let e = c.eval_passive(&msg(RESP, 200)).unwrap().evidence[0];
        assert_eq!(&RESP[e.start as usize..e.end as usize], b"Apache/2.4.1");
        let c = check("passive:\n  matchers:\n    - {type: status, status: [404, 500]}\n").unwrap();
        assert!(c.eval_passive(&msg(RESP, 200)).is_none());
        assert!(c.eval_passive(&msg(RESP, 500)).is_some());
    }

    #[test]
    fn conditions_and_negatives() {
        let and = "passive:\n  matchers-condition: and\n  matchers:\n    - {type: status, status: [200]}\n    - {type: word, part: header, words: ['x-frame-options'], negative: true, case-insensitive: true}\n";
        let c = check(and).unwrap();
        assert!(c.eval_passive(&msg(RESP, 200)).is_some());
        let with = b"HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n";
        assert!(c.eval_passive(&msg(with, 200)).is_none());
        let c = check("passive:\n  matchers:\n    - {type: word, words: [Hello, nope], condition: and}\n")
            .unwrap();
        assert!(c.eval_passive(&msg(RESP, 200)).is_none());
    }

    #[test]
    fn a_compressed_body_is_never_matched() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nHello";
        for neg in ["false", "true"] {
            let c = check(&format!(
                "passive:\n  matchers:\n    - {{type: word, words: [Hello], negative: {neg}}}\n"
            ))
            .unwrap();
            assert!(c.eval_passive(&msg(r, 200)).is_none(), "negative: {neg}");
        }
    }

    #[test]
    fn extractors() {
        let c = check(
            "passive:\n  matchers: [{type: status, status: [200]}]\n  extractors:\n    - {type: regex, name: v, regex: ['v=([0-9.]+)'], group: 1}\n    - {type: kval, name: srv, kval: [server]}\n",
        )
        .unwrap();
        let h = c.eval_passive(&msg(RESP, 200)).unwrap();
        assert_eq!(
            h.extracted,
            [
                ("v".into(), "1.2.3".into()),
                ("srv".into(), "Apache/2.4.1".into())
            ]
        );
    }

    #[test]
    fn requests_oast_and_templates() {
        let c = check(
            "requests:\n  - method: GET\n    path: ['{{BaseURL}}/a?u={{interactsh-url}}']\n    matchers:\n      - {type: word, part: interactsh_protocol, words: [dns]}\n",
        )
        .unwrap();
        assert!(!c.is_passive() && c.uses_oast());
        let i = Interaction {
            protocol: "dns".into(),
            request: vec![],
        };
        let m = Message {
            request: b"",
            response: b"HTTP/1.1 200 OK\r\n\r\n",
            status: 200,
            interaction: Some(&i),
        };
        assert!(c.eval_request(0, &m).is_some());
        assert!(c.eval_request(0, &msg(RESP, 200)).is_none());
        assert_eq!(
            expand("{{BaseURL}}/x{{ nope }}", &[("BaseURL", "http://h")]),
            "http://h/x{{ nope }}"
        );
    }

    #[test]
    fn rejects_what_it_should() {
        let m = "matchers: [{type: status, status: [200]}]";
        let cases = [
            (
                "version: 2\nid: t\ninfo: {name: T, severity: low}\npassive:\n  matchers: [{type: status, status: [200]}]\n",
                "version",
            ),
            (
                "version: 1\nid: Bad_Id\ninfo: {name: T, severity: low}\npassive:\n  matchers: [{type: status, status: [200]}]\n",
                "id must",
            ),
            (
                "version: 1\nid: t\ninfo: {name: T, severity: low, typo: 1}\npassive:\n  matchers: [{type: status, status: [200]}]\n",
                "typo",
            ),
            ("version: 1\nid: t\ninfo: {name: T, severity: low}\n", "needs"),
            (
                &format!("{BASE}passive: {{{m}}}\nrequests: [{{path: ['/'], {m}}}]\n"),
                "not both",
            ),
            (
                &format!("{BASE}passive: {{matchers: [{{type: regex, regex: ['(']}}]}}\n"),
                "bad regex",
            ),
            (
                &format!("{BASE}passive: {{matchers: [{{type: regex, regex: ['(a{{1000}}){{1000}}']}}]}}\n"),
                "regex",
            ),
            (
                &format!(
                    "{BASE}passive: {{matchers: [{{type: word, part: interactsh_protocol, words: [a]}}]}}\n"
                ),
                "interactsh",
            ),
            (
                &format!("{BASE}requests: [{{path: ['http://evil.test/'], {m}}}]\n"),
                "cannot choose",
            ),
            (
                &format!("{BASE}requests: [{{path: ['/{{{{Nope}}}}'], {m}}}]\n"),
                "unknown template",
            ),
            (
                &format!("{BASE}requests: [{{path: ['/'], headers: {{'X': \"a\\nb\"}}, {m}}}]\n"),
                "line breaks",
            ),
            (
                &format!("{BASE}passive: {{matchers: [{{type: status, status: [99]}}]}}\n"),
                "status",
            ),
        ];
        for (text, want) in cases {
            let e = parse(text).unwrap_err().to_string();
            assert!(e.contains(want), "{text:?} -> {e}");
        }
    }

    #[test]
    fn yaml_bombs_are_refused_not_expanded() {
        let mut s = String::from("a0: &a0 [x]\n");
        for i in 1..40 {
            s.push_str(&format!("a{i}: &a{i} [*a{}, *a{}]\n", i - 1, i - 1));
        }
        assert!(parse(&s).is_err());
        assert!(parse(&"a".repeat(MAX_SOURCE + 1)).is_err());
    }
}
