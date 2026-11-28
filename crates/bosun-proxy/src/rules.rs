//! Match and replace rules applied to proxied traffic.
//!
//! Rules work on the raw HTTP/1.1-style text of a message. Header rules apply line by line to the header
//! block: an empty match with a replacement adds a header, a match with an empty replacement removes the
//! matching header lines. First-line rules apply to the request or status line; body rules apply to the body
//! bytes.

use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleTarget {
    RequestFirstLine,
    RequestHeader,
    RequestBody,
    ResponseFirstLine,
    ResponseHeader,
    ResponseBody,
}

impl RuleTarget {
    pub fn is_request(self) -> bool {
        matches!(
            self,
            Self::RequestFirstLine | Self::RequestHeader | Self::RequestBody
        )
    }

    pub fn is_body(self) -> bool {
        matches!(self, Self::RequestBody | Self::ResponseBody)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[schema(as = MatchRule)]
pub struct RuleSpec {
    #[serde(default = "yes")]
    pub enabled: bool,
    pub target: RuleTarget,
    /// Literal text, or a regex when `regex` is true. Empty (header rules only) means "add".
    #[serde(rename = "match", default)]
    pub pattern: String,
    #[serde(default)]
    pub replace: String,
    #[serde(default)]
    pub regex: bool,
    #[serde(default)]
    pub comment: String,
    /// Body rules only: fire only when the body is a GraphQL request with an operation of this name
    /// (`operationName`, or the name in the query). Empty means every body.
    #[serde(default)]
    pub operation: String,
}

fn yes() -> bool {
    true
}

#[derive(Debug)]
struct Rule {
    target: RuleTarget,
    re: Option<Regex>,
    replace: Vec<u8>,
    operation: Option<String>,
}

/// A compiled rule set. Regexes use the `regex` crate, which runs in linear time, so a rule cannot be made to
/// hang on hostile traffic.
#[derive(Debug, Default)]
pub struct RuleSet {
    specs: Vec<RuleSpec>,
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn compile(specs: Vec<RuleSpec>) -> Result<Self, String> {
        let mut rules = Vec::new();
        for (i, s) in specs.iter().enumerate() {
            if !s.enabled {
                continue;
            }
            let re = if s.pattern.is_empty() {
                if !matches!(s.target, RuleTarget::RequestHeader | RuleTarget::ResponseHeader) {
                    return Err(format!(
                        "rule {}: an empty match is only allowed for header rules",
                        i + 1
                    ));
                }
                None
            } else {
                let p = if s.regex {
                    s.pattern.clone()
                } else {
                    regex::escape(&s.pattern)
                };
                Some(
                    regex::bytes::RegexBuilder::new(&p)
                        .size_limit(1 << 20)
                        .build()
                        .map_err(|e| format!("rule {}: {e}", i + 1))?,
                )
            };
            if !s.operation.is_empty() && !s.target.is_body() {
                return Err(format!(
                    "rule {}: an operation name is only allowed for body rules",
                    i + 1
                ));
            }
            rules.push(Rule {
                target: s.target,
                re,
                replace: s.replace.as_bytes().to_vec(),
                operation: (!s.operation.is_empty()).then(|| s.operation.clone()),
            });
        }
        Ok(Self { specs, rules })
    }

    pub fn specs(&self) -> &[RuleSpec] {
        &self.specs
    }

    pub fn has(&self, f: impl Fn(RuleTarget) -> bool) -> bool {
        self.rules.iter().any(|r| f(r.target))
    }

    /// Apply request rules to a raw request. Returns `None` when nothing changed.
    pub fn apply_request(&self, raw: &[u8]) -> Option<Vec<u8>> {
        self.apply(
            raw,
            [
                RuleTarget::RequestFirstLine,
                RuleTarget::RequestHeader,
                RuleTarget::RequestBody,
            ],
        )
    }

    /// Apply response rules (`with_body` false skips body rules, for streamed responses).
    pub fn apply_response(&self, raw: &[u8], with_body: bool) -> Option<Vec<u8>> {
        let body = if with_body {
            RuleTarget::ResponseBody
        } else {
            RuleTarget::ResponseHeader
        };
        self.apply(
            raw,
            [RuleTarget::ResponseFirstLine, RuleTarget::ResponseHeader, body],
        )
    }

    fn apply(&self, raw: &[u8], [first, header, body]: [RuleTarget; 3]) -> Option<Vec<u8>> {
        let rules: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|r| [first, header, body].contains(&r.target))
            .collect();
        if rules.is_empty() {
            return None;
        }
        let (head, body_bytes) = split_head(raw);
        let mut lines: Vec<Vec<u8>> = head
            .split(|&b| b == b'\n')
            .map(|l| l.strip_suffix(b"\r").unwrap_or(l).to_vec())
            .collect();
        while lines.last().is_some_and(|l| l.is_empty()) {
            lines.pop();
        }
        if lines.is_empty() {
            return None;
        }
        let mut body_out = body_bytes.to_vec();
        let mut changed = false;
        for r in rules {
            match (r.target == first, r.target == header, &r.re) {
                (true, _, Some(re)) => {
                    let new = re.replace_all(&lines[0], &r.replace[..]).into_owned();
                    changed |= new != lines[0];
                    lines[0] = new;
                }
                (_, true, None) => {
                    lines.push(r.replace.clone());
                    changed = true;
                }
                (_, true, Some(re)) => {
                    let mut out = vec![lines[0].clone()];
                    for l in &lines[1..] {
                        if re.is_match(l) {
                            changed = true;
                            if r.replace.is_empty() {
                                continue;
                            }
                            out.push(re.replace_all(l, &r.replace[..]).into_owned());
                        } else {
                            out.push(l.clone());
                        }
                    }
                    lines = out;
                }
                (_, _, Some(re))
                    if r.target == body
                        && r.operation
                            .as_deref()
                            .is_none_or(|op| bosun_codec::graphql::has_operation(&body_out, op)) =>
                {
                    let new = re.replace_all(&body_out, &r.replace[..]).into_owned();
                    changed |= new != body_out;
                    body_out = new;
                }
                _ => {}
            }
        }
        if !changed {
            return None;
        }
        let mut out = Vec::with_capacity(raw.len() + 64);
        for l in &lines {
            out.extend_from_slice(l);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&body_out);
        Some(out)
    }
}

fn split_head(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        (&raw[..i], &raw[i + 4..])
    } else if let Some(i) = raw.windows(2).position(|w| w == b"\n\n") {
        (&raw[..i], &raw[i + 2..])
    } else {
        (raw, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(target: RuleTarget, m: &str, r: &str, regex: bool) -> RuleSpec {
        RuleSpec {
            enabled: true,
            target,
            pattern: m.into(),
            replace: r.into(),
            regex,
            comment: String::new(),
            operation: String::new(),
        }
    }

    #[test]
    fn header_add_replace_remove_and_body() {
        let rs = RuleSet::compile(vec![
            spec(RuleTarget::RequestHeader, "", "X-Test: 1", false),
            spec(
                RuleTarget::RequestHeader,
                r"^User-Agent:.*$",
                "User-Agent: bosun",
                true,
            ),
            spec(RuleTarget::RequestHeader, r"(?i)^cookie:", "", true),
            spec(RuleTarget::RequestBody, "a.b", "X", false),
            spec(RuleTarget::ResponseBody, "never", "applied", false),
        ])
        .unwrap();
        let raw = b"POST / HTTP/1.1\r\nHost: h\r\nUser-Agent: curl\r\nCookie: s=1\r\n\r\na.b axb";
        let out = rs.apply_request(raw).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "POST / HTTP/1.1\r\nHost: h\r\nUser-Agent: bosun\r\nX-Test: 1\r\n\r\nX axb",
            "literal match escapes regex metacharacters"
        );
    }

    #[test]
    fn unchanged_returns_none_and_body_rules_skip_when_streaming() {
        let rs = RuleSet::compile(vec![spec(RuleTarget::ResponseBody, "x", "y", false)]).unwrap();
        assert!(rs.apply_response(b"HTTP/1.1 200 OK\r\n\r\nx", false).is_none());
        assert!(rs.apply_response(b"HTTP/1.1 200 OK\r\n\r\nx", true).is_some());
        assert!(rs.apply_request(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn body_rule_fires_only_on_its_graphql_operation() {
        let mut s = spec(RuleTarget::RequestBody, "secret", "XXXXXX", false);
        s.operation = "GetUser".into();
        let rs = RuleSet::compile(vec![s.clone()]).unwrap();
        let hit = br#"{"query":"query GetUser { secret }"}"#;
        let miss = br#"{"query":"query Other { secret }"}"#;
        let raw = |b: &[u8]| [&b"POST /g HTTP/1.1\r\n\r\n"[..], b].concat();
        let out = rs.apply_request(&raw(hit)).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("{ XXXXXX }"));
        assert!(rs.apply_request(&raw(miss)).is_none());
        assert!(rs.apply_request(&raw(b"secret, not json")).is_none());
        s.target = RuleTarget::RequestHeader;
        assert!(
            RuleSet::compile(vec![s]).is_err(),
            "header rules cannot name an operation"
        );
    }

    #[test]
    fn first_line_and_validation() {
        let rs =
            RuleSet::compile(vec![spec(RuleTarget::ResponseFirstLine, " 403 ", " 200 ", false)]).unwrap();
        let out = rs
            .apply_response(b"HTTP/1.1 403 Forbidden\r\n\r\n", false)
            .unwrap();
        assert!(out.starts_with(b"HTTP/1.1 200 Forbidden"));
        assert!(RuleSet::compile(vec![spec(RuleTarget::RequestBody, "", "x", false)]).is_err());
        assert!(RuleSet::compile(vec![spec(RuleTarget::RequestBody, "(", "x", true)]).is_err());
    }
}
