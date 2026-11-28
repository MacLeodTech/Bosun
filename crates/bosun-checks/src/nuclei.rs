//! Import a compatible subset of Nuclei templates (ProjectDiscovery, MIT licence).
//!
//! Supported: `http` (or the older `requests`) blocks with `method`, `path`, `headers`, `body`, `word`, `regex`
//! and `status` matchers (`part` body, header, all or response; `condition`, `negative`, `case-insensitive`,
//! `matchers-condition`) and `regex` and `kval` extractors. Everything else is refused with the name of the
//! feature, never dropped silently, because a template that loses a matcher reports false findings: `raw`
//! requests, `payloads` and fuzzing, `dsl` matchers and extractors, `flow`, `variables`, other protocols,
//! `binary`/`xpath`/`json` matchers, and `interactsh` parts other than the two the language has.
//!
//! The converted check keeps a `source` block (origin, id, author, licence and Nuclei's copyright notice), and the
//! repository's `NOTICE` lists the project. Severity `critical` becomes `high`, and `unknown` becomes `info`.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::lang::{
    Check, CheckError, Compiled, Cond, Conf, Extractor, ExtractorKind, Info, MAX_SOURCE, Matcher,
    MatcherKind, Part, Request, Sev, Source, VERSION,
};

/// What the converted check's `source.notice` says.
pub const NOTICE: &str =
    "Converted from a Nuclei template. Nuclei templates: Copyright (c) ProjectDiscovery, Inc., MIT License.";

#[derive(Deserialize)]
struct Template {
    id: String,
    info: NInfo,
    #[serde(default)]
    http: Vec<NRequest>,
    #[serde(default)]
    requests: Vec<NRequest>,
    // Present only to be refused by name.
    flow: Option<serde_json::Value>,
    variables: Option<serde_json::Value>,
    dns: Option<serde_json::Value>,
    file: Option<serde_json::Value>,
    tcp: Option<serde_json::Value>,
    network: Option<serde_json::Value>,
    headless: Option<serde_json::Value>,
    ssl: Option<serde_json::Value>,
    code: Option<serde_json::Value>,
    javascript: Option<serde_json::Value>,
    whois: Option<serde_json::Value>,
    workflows: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct NInfo {
    name: String,
    #[serde(default)]
    author: StrOrList,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    remediation: String,
    #[serde(default)]
    tags: StrOrList,
    #[serde(default)]
    reference: StrOrList,
    #[serde(default)]
    classification: Option<Classification>,
}

#[derive(Deserialize, Default)]
struct Classification {
    #[serde(default, rename = "cwe-id")]
    cwe_id: StrOrList,
}

/// Nuclei lets many fields be a string or a list, and comma-separates some.
#[derive(Deserialize, Default)]
#[serde(untagged)]
enum StrOrList {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl StrOrList {
    fn items(&self) -> Vec<String> {
        match self {
            Self::None => vec![],
            Self::One(s) => s
                .split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect(),
            Self::Many(v) => v
                .iter()
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect(),
        }
    }
}

#[derive(Deserialize)]
struct NRequest {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    path: Vec<String>,
    #[serde(default)]
    headers: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    body: String,
    #[serde(default, rename = "matchers-condition")]
    matchers_condition: String,
    #[serde(default)]
    matchers: Vec<NMatcher>,
    #[serde(default)]
    extractors: Vec<NExtractor>,
    raw: Option<serde_json::Value>,
    payloads: Option<serde_json::Value>,
    fuzzing: Option<serde_json::Value>,
    attack: Option<serde_json::Value>,
    race: Option<serde_json::Value>,
    #[serde(rename = "unsafe")]
    unsafe_: Option<serde_json::Value>,
    #[serde(rename = "req-condition")]
    req_condition: Option<serde_json::Value>,
    pipeline: Option<serde_json::Value>,
    #[serde(rename = "skip-variables-check")]
    _skip: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct NMatcher {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    part: String,
    #[serde(default)]
    words: Vec<String>,
    #[serde(default)]
    regex: Vec<String>,
    #[serde(default)]
    status: Vec<u16>,
    #[serde(default)]
    condition: String,
    #[serde(default)]
    negative: bool,
    #[serde(default, rename = "case-insensitive")]
    case_insensitive: bool,
    #[serde(default)]
    name: String,
    #[serde(default)]
    encoding: String,
    #[serde(default, rename = "match-all")]
    match_all: bool,
    #[serde(default)]
    internal: bool,
}

#[derive(Deserialize)]
struct NExtractor {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    part: String,
    #[serde(default)]
    regex: Vec<String>,
    #[serde(default)]
    group: usize,
    #[serde(default)]
    kval: Vec<String>,
    #[serde(default)]
    name: String,
}

fn cond(s: &str) -> Result<Cond, CheckError> {
    match s {
        "" | "or" => Ok(Cond::Or),
        "and" => Ok(Cond::And),
        other => Err(CheckError(format!(
            "unsupported condition `{}`",
            other.chars().take(20).collect::<String>()
        ))),
    }
}

fn part(s: &str) -> Result<Part, CheckError> {
    match s {
        "" | "body" => Ok(Part::Body),
        "header" => Ok(Part::Header),
        "all" | "response" => Ok(Part::All),
        "request" => Ok(Part::Request),
        "interactsh_protocol" => Ok(Part::InteractshProtocol),
        "interactsh_request" => Ok(Part::InteractshRequest),
        other => Err(CheckError(format!(
            "unsupported part `{}`",
            other.chars().take(30).collect::<String>()
        ))),
    }
}

/// Nuclei's `{{BaseURL}}` and friends are ours too; `{{interactsh-url}}` is the OAST hook. Anything else
/// (`{{randstr}}`, `{{md5(...)}}`, user variables) would send a literal and is refused by validation.
fn convert_request(r: NRequest) -> Result<Request, CheckError> {
    for (name, present) in [
        ("raw requests", r.raw.is_some()),
        ("payloads", r.payloads.is_some()),
        ("fuzzing", r.fuzzing.is_some()),
        ("attack", r.attack.is_some()),
        ("race", r.race.is_some()),
        ("unsafe", r.unsafe_.is_some()),
        ("req-condition", r.req_condition.is_some()),
        ("pipeline", r.pipeline.is_some()),
    ] {
        if present {
            return Err(CheckError(format!("unsupported Nuclei feature: {name}")));
        }
    }
    let mut matchers = Vec::new();
    for m in r.matchers {
        if m.match_all || m.internal || !m.encoding.is_empty() {
            return Err(CheckError(
                "unsupported Nuclei feature: match-all, internal or encoded matchers".into(),
            ));
        }
        let kind = match m.kind.as_str() {
            "word" => MatcherKind::Word,
            "regex" => MatcherKind::Regex,
            "status" => MatcherKind::Status,
            other => {
                return Err(CheckError(format!(
                    "unsupported Nuclei matcher type `{}`",
                    other.chars().take(20).collect::<String>()
                )));
            }
        };
        matchers.push(Matcher {
            kind,
            part: part(&m.part)?,
            words: m.words,
            regex: m.regex,
            status: m.status,
            condition: cond(&m.condition)?,
            negative: m.negative,
            case_insensitive: m.case_insensitive,
            name: m.name,
        });
    }
    let mut extractors = Vec::new();
    for e in r.extractors {
        let kind = match e.kind.as_str() {
            "regex" => ExtractorKind::Regex,
            "kval" => ExtractorKind::Kval,
            other => {
                return Err(CheckError(format!(
                    "unsupported Nuclei extractor type `{}`",
                    other.chars().take(20).collect::<String>()
                )));
            }
        };
        extractors.push(Extractor {
            kind,
            part: part(&e.part)?,
            regex: e.regex,
            group: e.group,
            kval: e.kval,
            name: e.name,
        });
    }
    let mut headers = BTreeMap::new();
    for (k, v) in r.headers {
        let serde_json::Value::String(s) = v else {
            return Err(CheckError("a header value that is not text".into()));
        };
        headers.insert(k, s);
    }
    Ok(Request {
        method: r.method.unwrap_or_else(|| "GET".into()).to_ascii_uppercase(),
        path: r.path,
        headers,
        body: r.body,
        matchers_condition: cond(&r.matchers_condition)?,
        matchers,
        extractors,
    })
}

/// Convert a Nuclei template (YAML text) into a validated check.
pub fn import(text: &str) -> Result<Compiled, CheckError> {
    if text.len() > MAX_SOURCE {
        return Err(CheckError("the template is too large".into()));
    }
    let t: Template =
        serde_saphyr::from_str(text).map_err(|e| CheckError(format!("not a Nuclei template: {e}")))?;
    for (name, present) in [
        ("flow", t.flow.is_some()),
        ("variables", t.variables.is_some()),
        ("dns", t.dns.is_some()),
        ("file", t.file.is_some()),
        ("tcp", t.tcp.is_some()),
        ("network", t.network.is_some()),
        ("headless", t.headless.is_some()),
        ("ssl", t.ssl.is_some()),
        ("code", t.code.is_some()),
        ("javascript", t.javascript.is_some()),
        ("whois", t.whois.is_some()),
        ("workflows", t.workflows.is_some()),
    ] {
        if present {
            return Err(CheckError(format!("unsupported Nuclei feature: {name}")));
        }
    }
    let reqs: Vec<NRequest> = t.http.into_iter().chain(t.requests).collect();
    if reqs.is_empty() {
        return Err(CheckError("the template has no http requests".into()));
    }
    let requests = reqs
        .into_iter()
        .map(convert_request)
        .collect::<Result<Vec<_>, _>>()?;
    let sev = match t.info.severity.to_ascii_lowercase().as_str() {
        "" | "info" | "unknown" => Sev::Info,
        "low" => Sev::Low,
        "medium" => Sev::Medium,
        "high" | "critical" => Sev::High,
        other => {
            return Err(CheckError(format!(
                "unknown severity `{}`",
                other.chars().take(20).collect::<String>()
            )));
        }
    };
    let cwe = t
        .info
        .classification
        .map(|c| {
            c.cwe_id
                .items()
                .iter()
                .filter_map(|s| {
                    s.trim_start_matches("CWE-")
                        .trim_start_matches("cwe-")
                        .parse()
                        .ok()
                })
                .collect()
        })
        .unwrap_or_default();
    let author = t.info.author.items().join(", ");
    let id: String =
        t.id.to_ascii_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
    let id = format!("nuclei-{}", id.trim_matches('-'));
    let check = Check {
        version: VERSION,
        id: id
            .chars()
            .take(64)
            .collect::<String>()
            .trim_end_matches('-')
            .to_string(),
        info: Info {
            name: t.info.name,
            severity: sev,
            confidence: Conf::Tentative,
            description: t.info.description,
            remediation: t.info.remediation,
            cwe,
            owasp: vec![],
            tags: t.info.tags.items().into_iter().take(32).collect(),
            reference: t.info.reference.items().into_iter().take(16).collect(),
        },
        source: Some(Source {
            origin: "nuclei-templates".into(),
            id: t.id.chars().take(128).collect(),
            author: author.chars().take(200).collect(),
            license: "MIT".into(),
            notice: NOTICE.into(),
        }),
        passive: None,
        requests,
    };
    Compiled::new(check)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::Message;

    const GIT: &str = "id: git-config\ninfo:\n  name: Git Config Exposure\n  author: [pdteam, other]\n  severity: medium\n  tags: exposure,git\n  classification:\n    cwe-id: CWE-200\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/.git/config'\n    matchers-condition: and\n    matchers:\n      - type: word\n        words: ['[core]']\n        part: body\n      - type: status\n        status: [200]\n";

    #[test]
    fn imports_a_simple_template() {
        let c = import(GIT).unwrap();
        assert_eq!(c.check.id, "nuclei-git-config");
        assert_eq!(c.check.info.cwe, [200]);
        assert_eq!(c.check.info.tags, ["exposure", "git"]);
        let s = c.check.source.as_ref().unwrap();
        assert_eq!((s.license.as_str(), s.author.as_str()), ("MIT", "pdteam, other"));
        assert!(s.notice.contains("ProjectDiscovery"));
        let ok = b"HTTP/1.1 200 OK\r\n\r\n[core]\n";
        let m = |r: &'static [u8], s| Message {
            request: b"",
            response: r,
            status: s,
            interaction: None,
        };
        assert!(c.eval_request(0, &m(ok, 200)).is_some());
        assert!(c.eval_request(0, &m(ok, 404)).is_none());
        assert!(
            c.eval_request(0, &m(b"HTTP/1.1 200 OK\r\n\r\nnothing", 200))
                .is_none()
        );
    }

    #[test]
    fn refuses_what_it_cannot_do() {
        let base = "id: x\ninfo: {name: X, severity: low}\n";
        let m = "matchers: [{type: status, status: [200]}]";
        let cases = [
            (
                format!("{base}http:\n  - raw: ['GET / HTTP/1.1']\n    {m}\n"),
                "raw requests",
            ),
            (
                format!("{base}http:\n  - path: ['{{{{BaseURL}}}}/']\n    payloads: {{a: [b]}}\n    {m}\n"),
                "payloads",
            ),
            (
                format!(
                    "{base}http:\n  - path: ['{{{{BaseURL}}}}/']\n    matchers: [{{type: dsl, dsl: ['true']}}]\n"
                ),
                "dsl",
            ),
            (
                format!("{base}http:\n  - path: ['{{{{BaseURL}}}}/{{{{randstr}}}}']\n    {m}\n"),
                "unknown template variable",
            ),
            (format!("{base}dns:\n  - name: x\n"), "dns"),
            (
                format!(
                    "{base}http:\n  - path: ['{{{{BaseURL}}}}/']\n    matchers: [{{type: word, words: [a], part: body, encoding: hex}}]\n"
                ),
                "encoded",
            ),
            ("id: x\ninfo: {name: X, severity: low}\n".to_string(), "no http"),
        ];
        for (t, want) in cases {
            let e = import(&t).unwrap_err().to_string();
            assert!(e.contains(want), "{want}: {e}");
        }
    }
}
