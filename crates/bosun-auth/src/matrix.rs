//! The authorisation matrix.
//!
//! Each [`Probe`] is a request recorded while signed in as its `owner`. The matrix sends it again as every
//! [`Identity`] (and as nobody) and sets each answer against the owner's. An identity that gets the same answer
//! and is neither the owner nor listed in `allowed` has reached something it should not: that is a [`Finding`].

use std::collections::HashSet;

use bosun_http::{Engine, SendError, SendOptions};
use bosun_model::{FlowSource, Target};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The name used for "no credentials at all".
pub const ANONYMOUS: &str = "anonymous";
/// The most probes in one run.
pub const MAX_PROBES: usize = 2_000;
/// The most identities in one run.
pub const MAX_IDENTITIES: usize = 20;

/// An account: a name and the headers that make a request be that account (`Cookie`, `Authorization`, an API key).
/// The headers replace whatever the recorded request carried for them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct Identity {
    pub name: String,
    pub headers: Vec<(String, String)>,
}

/// A request recorded as `owner` (one of the identity names), to be replayed as the others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub label: String,
    pub owner: String,
    /// Other identities that are meant to reach it too (an admin, say). Their access is not a finding.
    pub allowed: Vec<String>,
    pub target: Target,
    pub request: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(default)]
pub struct Options {
    /// How alike two bodies must be (0 to 100) for the answers to count as the same.
    pub similarity_percent: u8,
    pub verify_tls: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            similarity_percent: 90,
            verify_tls: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The owner's own answer: the baseline.
    Owner,
    /// Answered like the owner.
    Same,
    /// Answered like the owner, and meant to be (listed in `allowed`).
    Allowed,
    /// Refused: 401, 403, 404, or a redirect.
    Denied,
    /// Answered, but with something else (typically the account's own data).
    Different,
    /// No answer.
    Error,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct Cell {
    pub identity: String,
    pub verdict: Verdict,
    pub status: Option<u16>,
    pub body_len: usize,
    /// 0 to 100 against the owner's body.
    pub similarity: u8,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct Row {
    pub label: String,
    pub owner: String,
    pub cells: Vec<Cell>,
    /// Why there are no comparisons (the owner's own request did not succeed).
    pub skipped: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Another account read or did what only the owner should (IDOR, horizontal or vertical).
    BrokenAccessControl,
    /// It needs no login at all.
    MissingAuthentication,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
pub struct Finding {
    pub kind: FindingKind,
    pub label: String,
    pub owner: String,
    pub identity: String,
    pub status: Option<u16>,
    pub similarity: u8,
}

impl Row {
    pub fn findings(&self) -> Vec<Finding> {
        self.cells
            .iter()
            .filter(|c| c.verdict == Verdict::Same)
            .map(|c| Finding {
                kind: if c.identity == ANONYMOUS {
                    FindingKind::MissingAuthentication
                } else {
                    FindingKind::BrokenAccessControl
                },
                label: self.label.clone(),
                owner: self.owner.clone(),
                identity: c.identity.clone(),
                status: c.status,
                similarity: c.similarity,
            })
            .collect()
    }
}

/// `request` with its `Cookie` and `Authorization` headers (and any other header named in `headers`) replaced by
/// `headers`.
pub fn with_identity(request: &[u8], headers: &[(String, String)]) -> Vec<u8> {
    let head_end = request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(request.len(), |p| p + 2);
    let (head, rest) = request.split_at(head_end);
    let replaced: HashSet<String> = headers.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
    let mut out = Vec::with_capacity(request.len() + 64);
    for (i, line) in head.split_inclusive(|&b| b == b'\n').enumerate() {
        if i > 0 {
            let name = line
                .split(|&b| b == b':')
                .next()
                .map(|n| String::from_utf8_lossy(n).trim().to_ascii_lowercase())
                .unwrap_or_default();
            if matches!(name.as_str(), "cookie" | "authorization") || replaced.contains(&name) {
                continue;
            }
        }
        out.extend_from_slice(line);
    }
    // Insert after the request line.
    let line_end = out.iter().position(|&b| b == b'\n').map_or(out.len(), |p| p + 1);
    let mut inject = Vec::new();
    for (k, v) in headers {
        if k.bytes().any(|b| b == b'\r' || b == b'\n' || b == b':')
            || v.bytes().any(|b| b == b'\r' || b == b'\n')
        {
            continue;
        }
        inject.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.splice(line_end..line_end, inject);
    out.extend_from_slice(rest);
    out
}

fn body_of(raw: &[u8]) -> &[u8] {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(&[][..], |p| &raw[p + 4..])
}

/// How alike two bodies are, 0 to 100: the share of the longer one's byte-trigrams the other has.
pub fn similarity(a: &[u8], b: &[u8]) -> u8 {
    if a == b {
        return 100;
    }
    if a.len() < 3 || b.len() < 3 {
        return 0;
    }
    fn grams(x: &[u8]) -> HashSet<&[u8]> {
        x.windows(3).collect()
    }
    let (ga, gb) = (grams(a), grams(b));
    let common = ga.intersection(&gb).count();
    ((common * 100) / ga.len().max(gb.len())) as u8
}

fn denied(status: u16) -> bool {
    matches!(status, 401 | 403 | 404 | 405) || (300..400).contains(&status)
}

async fn send(
    engine: &Engine,
    p: &Probe,
    headers: &[(String, String)],
    o: &SendOptions,
) -> Result<bosun_http::Exchange, String> {
    let req = with_identity(&p.request, headers);
    match engine.send(&p.target, &req, o).await {
        Ok(ex) => Ok(ex),
        Err(SendError::Refused(e)) => Err(format!("refused by the scope gate: {e}")),
        Err(e) => Err(e.to_string()),
    }
}

/// Run the matrix. Fails only when the arguments are unusable; a request that cannot be sent is a cell with an
/// error.
pub async fn run(
    engine: &Engine,
    identities: &[Identity],
    probes: &[Probe],
    options: &Options,
) -> Result<Vec<Row>, String> {
    if identities.len() > MAX_IDENTITIES || probes.len() > MAX_PROBES {
        return Err("too many identities or probes".into());
    }
    if options.similarity_percent > 100 {
        return Err("similarity_percent is 0 to 100".into());
    }
    let mut names = HashSet::new();
    for i in identities {
        if i.name.is_empty() || i.name == ANONYMOUS || !names.insert(i.name.as_str()) {
            return Err(format!(
                "identity names must be unique and not empty or \"{ANONYMOUS}\" (got \"{}\")",
                i.name
            ));
        }
    }
    let so = SendOptions {
        source: FlowSource::Scanner,
        update_content_length: true,
        verify_tls: options.verify_tls,
        ..SendOptions::default()
    };
    let mut rows = Vec::new();
    for p in probes {
        let Some(owner) = identities.iter().find(|i| i.name == p.owner) else {
            rows.push(Row {
                label: p.label.clone(),
                owner: p.owner.clone(),
                cells: vec![],
                skipped: Some(format!("no identity named \"{}\"", p.owner)),
            });
            continue;
        };
        let base = match send(engine, p, &owner.headers, &so).await {
            Ok(ex) if ex.status.is_some_and(|s| (200..300).contains(&s)) => ex,
            Ok(ex) => {
                rows.push(Row {
                    label: p.label.clone(),
                    owner: p.owner.clone(),
                    cells: vec![],
                    skipped: Some(format!("the owner's own request got {:?}", ex.status)),
                });
                continue;
            }
            Err(e) => {
                rows.push(Row {
                    label: p.label.clone(),
                    owner: p.owner.clone(),
                    cells: vec![],
                    skipped: Some(e),
                });
                continue;
            }
        };
        let base_body = body_of(&base.response).to_vec();
        let mut cells = vec![Cell {
            identity: p.owner.clone(),
            verdict: Verdict::Owner,
            status: base.status,
            body_len: base_body.len(),
            similarity: 100,
            error: None,
        }];
        let anon = Identity {
            name: ANONYMOUS.into(),
            headers: vec![],
        };
        for who in identities.iter().filter(|i| i.name != p.owner).chain([&anon]) {
            let cell = match send(engine, p, &who.headers, &so).await {
                Err(e) => Cell {
                    identity: who.name.clone(),
                    verdict: Verdict::Error,
                    status: None,
                    body_len: 0,
                    similarity: 0,
                    error: Some(e),
                },
                Ok(ex) => {
                    let body = body_of(&ex.response);
                    let sim = similarity(&base_body, body);
                    let status = ex.status;
                    let verdict = match status {
                        None => Verdict::Error,
                        Some(s) if denied(s) => Verdict::Denied,
                        Some(s) if Some(s) == base.status && sim >= options.similarity_percent => {
                            Verdict::Same
                        }
                        Some(_) => Verdict::Different,
                    };
                    Cell {
                        identity: who.name.clone(),
                        verdict,
                        status,
                        body_len: body.len(),
                        similarity: sim,
                        error: ex.error.clone(),
                    }
                }
            };
            // Access that was meant to be allowed is not a finding.
            let cell = if p.allowed.contains(&cell.identity) && cell.verdict == Verdict::Same {
                Cell {
                    verdict: Verdict::Allowed,
                    ..cell
                }
            } else {
                cell
            };
            cells.push(cell);
        }
        rows.push(Row {
            label: p.label.clone(),
            owner: p.owner.clone(),
            cells,
            skipped: None,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_headers_replace_cookie_and_authorization_and_cannot_inject() {
        let req = b"GET /a HTTP/1.1\r\nHost: x\r\nCookie: sid=old\r\nauthorization: Bearer old\r\nAccept: */*\r\n\r\nbody";
        let out = with_identity(
            req,
            &[
                ("Cookie".into(), "sid=new".into()),
                ("X-Evil".into(), "a\r\nInjected: 1".into()),
            ],
        );
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("GET /a HTTP/1.1\r\nCookie: sid=new\r\n"), "{s}");
        assert!(s.contains("Host: x\r\n") && s.contains("Accept: */*\r\n") && s.ends_with("\r\n\r\nbody"));
        assert!(!s.contains("old") && !s.contains("Injected"), "{s}");
    }

    #[test]
    fn no_identity_headers_means_no_credentials() {
        let s = String::from_utf8(with_identity(b"GET / HTTP/1.1\r\nCookie: a=b\r\n\r\n", &[])).unwrap();
        assert_eq!(s, "GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn similarity_is_100_for_equal_and_low_for_unrelated() {
        assert_eq!(similarity(b"Order 1 for alice", b"Order 1 for alice"), 100);
        assert!(
            similarity(
                b"Order 1 for alice: 2 x anchor chain",
                b"Order 3 for bob: 40 m of rope"
            ) < 60
        );
        assert_eq!(similarity(b"", b"abc"), 0);
    }
}
