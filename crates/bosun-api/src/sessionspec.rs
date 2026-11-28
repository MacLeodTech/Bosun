//! Session handling for scans and crawls (WP-56): a login request, what to keep from its answer, and when the
//! session has ended.
//!
//! The login request may name vault entries as `{{vault:ID}}` (the secret as it is), `{{vault:ID|url}}`
//! (percent-encoded) or `{{vault:ID|json}}` (escaped for a JSON string). The secrets are opened here on the
//! server; they go into the login request only, which goes through the Repeater's engine like every other
//! request. A secret with a line break or a NUL byte is refused, so it cannot add a header.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::Response;
use bosun_auth::{Capture, Expiry, LoginMacro, Session};
use bosun_model::Target;
use regex::Regex;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::AppState;
use crate::security::reject;

/// The login request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginSpec {
    /// Absolute `http` or `https` URL of the login endpoint.
    pub url: String,
    /// Default `POST`.
    #[serde(default)]
    pub method: Option<String>,
    /// Each `Name: value`.
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
}

/// What to keep from the login answer.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureSpec {
    /// Every cookie the answer sets.
    Cookies,
    /// The first capture group of `pattern` on the body, sent as `header: {prefix}{value}`.
    Body {
        pattern: String,
        header: String,
        #[serde(default)]
        prefix: String,
    },
    /// A response header, sent as `header: {prefix}{value}`.
    Header {
        from: String,
        header: String,
        #[serde(default)]
        prefix: String,
    },
}

/// When an answer means the session has ended (default: status 401, or a redirect to a `login` page).
#[derive(Debug, Deserialize, ToSchema)]
pub struct ExpirySpec {
    #[serde(default)]
    pub statuses: Vec<u16>,
    #[serde(default)]
    pub redirect_contains: Option<String>,
    #[serde(default)]
    pub body_contains: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SessionSpec {
    pub login: LoginSpec,
    pub capture: CaptureSpec,
    #[serde(default)]
    pub expiry: Option<ExpirySpec>,
}

fn bad(msg: &str) -> Response {
    reject(StatusCode::BAD_REQUEST, msg)
}

const OPEN: &str = "{{vault:";

/// The vault ids a text names.
fn ids_in(text: &str, out: &mut BTreeSet<i64>) -> Result<(), Response> {
    let mut rest = text;
    while let Some(p) = rest.find(OPEN) {
        let after = &rest[p + OPEN.len()..];
        let end = after
            .find("}}")
            .ok_or_else(|| bad("a {{vault:ID}} placeholder is not closed"))?;
        let id = after[..end].split('|').next().unwrap_or_default();
        out.insert(
            id.parse()
                .map_err(|_| bad("a vault placeholder is {{vault:ID}}"))?,
        );
        rest = &after[end + 2..];
    }
    Ok(())
}

fn encode(s: &str, how: &str) -> Result<String, Response> {
    Ok(match how {
        "" => s.to_string(),
        "url" => s
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect(),
        "json" => {
            let q = serde_json::to_string(s).unwrap_or_default();
            q[1..q.len().saturating_sub(1)].to_string()
        }
        _ => return Err(bad("a vault placeholder ends in |url or |json, or nothing")),
    })
}

fn fill(text: &str, secrets: &[(i64, String)]) -> Result<String, Response> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(p) = rest.find(OPEN) {
        out.push_str(&rest[..p]);
        let after = &rest[p + OPEN.len()..];
        let end = after
            .find("}}")
            .ok_or_else(|| bad("a {{vault:ID}} placeholder is not closed"))?;
        let (id, how) = after[..end].split_once('|').unwrap_or((&after[..end], ""));
        let id: i64 = id
            .parse()
            .map_err(|_| bad("a vault placeholder is {{vault:ID}}"))?;
        let secret = secrets
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, s)| s.as_str())
            .unwrap_or_default();
        out.push_str(&encode(secret, how)?);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn plain(s: &str) -> bool {
    !s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// Build the session, opening the vault entries the login names. Nothing is sent yet: the first request of the
/// scan or crawl signs in.
pub async fn build(st: &AppState, spec: &SessionSpec) -> Result<Arc<Session>, Response> {
    let l = &spec.login;
    let method = l.method.as_deref().unwrap_or("POST").to_ascii_uppercase();
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(bad("the login method is not valid"));
    }
    let url = bosun_crawl::parse_url(&l.url)
        .ok_or_else(|| bad("the login URL is not an absolute http or https URL"))?;
    let mut ids = BTreeSet::new();
    for t in l.headers.iter().chain(l.body.iter()).chain(l.content_type.iter()) {
        ids_in(t, &mut ids)?;
    }
    if ids.len() > 8 {
        return Err(bad("the login names at most 8 vault entries"));
    }
    let p = st.project();
    let key = st.inner.data_key.clone();
    let secrets = tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        for id in ids {
            let s = crate::vault::open_secret(&p, &key, id)?
                .ok_or_else(|| bosun_store::StoreError::Conflict(format!("no vault entry {id}")))?;
            out.push((id, String::from_utf8_lossy(&s).into_owned()));
        }
        Ok::<_, bosun_store::StoreError>(out)
    })
    .await
    .map_err(|_| reject(StatusCode::INTERNAL_SERVER_ERROR, "could not open the vault"))?
    .map_err(|e| bad(&e.to_string()))?;
    if secrets.iter().any(|(_, s)| !plain(s)) {
        return Err(bad("a vault entry used in the login has a line break or NUL"));
    }

    let body = l.body.as_deref().map(|b| fill(b, &secrets)).transpose()?;
    let mut raw = format!("{method} {} HTTP/1.1\r\nHost: {}\r\n", url.path, url.authority());
    for h in &l.headers {
        let h = fill(h, &secrets)?;
        let (k, v) = h
            .split_once(':')
            .ok_or_else(|| bad("a header is `Name: value`"))?;
        if k.trim().is_empty() || !plain(&h) {
            return Err(bad("a login header is not valid"));
        }
        raw.push_str(&format!("{}: {}\r\n", k.trim(), v.trim()));
    }
    if let Some(ct) = &l.content_type {
        if !plain(ct) {
            return Err(bad("the content type is not valid"));
        }
        raw.push_str(&format!("Content-Type: {ct}\r\n"));
    } else if body.is_some() {
        raw.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
    }
    if let Some(b) = &body {
        raw.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    raw.push_str("Connection: close\r\n\r\n");
    let mut request = raw.into_bytes();
    request.extend_from_slice(body.unwrap_or_default().as_bytes());

    let capture = match &spec.capture {
        CaptureSpec::Cookies => Capture::Cookies,
        CaptureSpec::Body {
            pattern,
            header,
            prefix,
        } => {
            if header.is_empty() || !plain(header) || !plain(prefix) {
                return Err(bad("the capture header is not valid"));
            }
            Capture::Body {
                pattern: Regex::new(pattern).map_err(|e| bad(&format!("the capture pattern: {e}")))?,
                header: header.clone(),
                prefix: prefix.clone(),
            }
        }
        CaptureSpec::Header { from, header, prefix } => {
            if from.is_empty() || header.is_empty() || !plain(from) || !plain(header) || !plain(prefix) {
                return Err(bad("the capture header is not valid"));
            }
            Capture::Header {
                from: from.to_ascii_lowercase(),
                header: header.clone(),
                prefix: prefix.clone(),
            }
        }
    };
    let expiry = match &spec.expiry {
        None => Expiry::default(),
        Some(e) => Expiry {
            statuses: e.statuses.clone(),
            redirect_contains: e.redirect_contains.clone(),
            body_contains: e.body_contains.clone(),
        },
    };
    let login = LoginMacro {
        target: Target::new(url.scheme, &url.host, url.port),
        request,
        capture,
    };
    Ok(Arc::new(Session::new(st.inner.repeater.clone(), login, expiry)))
}
