//! Engagement helpers on a recorded flow (WP-45): what its response contains (comments, scripts, references), the
//! parameters of its request, and a CSRF proof of concept. Read-only on stored data, so the viewer role is enough.
//! The proof of concept is HTML meant for a file the tester saves: it is only ever served as an attachment, with a
//! sandboxing CSP, so even opened by mistake in Bosun's origin it cannot run anything or reach the API.

use std::io::Read as _;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bosun_codec::engage::{self, Analyzer, Finding, Observation, Param, PocError, PocInput, TargetAnalysis};
use bosun_model::FlowId;
use bosun_store::{Role, Which, codec};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::reject;

type R = Result<Response, Response>;

/// How much of a body is scanned.
const SCAN_LIMIT: u64 = 2 << 20;

#[derive(Debug, Serialize, ToSchema)]
pub struct EngageReport {
    /// What the response holds: comments, scripts, links, forms, resources, URLs and quoted paths.
    pub findings: Vec<Finding>,
    /// The parameters of the request: query, form body and JSON body.
    pub params: Vec<Param>,
    /// The scanned body was longer than the scan limit (or the decoded body was cut).
    pub truncated: bool,
    /// The response has a Content-Encoding Bosun cannot undo, so only the request side is reported.
    pub undecoded: Option<String>,
}

/// One header's value in a request or response head (first match, case-insensitive).
fn header_value(head: &[u8], name: &str) -> Option<String> {
    String::from_utf8_lossy(head).lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

struct Loaded {
    head: Vec<u8>,
    body: Vec<u8>,
    truncated: bool,
}

fn load(
    p: &bosun_store::Project,
    id: FlowId,
    which: Which,
) -> Result<Option<Loaded>, bosun_store::StoreError> {
    p.with_message(id, which, |m| {
        let Some(m) = m else { return Ok(None) };
        let head = m.head()?;
        let head_len = head.len() as u64;
        let mut body = Vec::new();
        m.body(head_len, 0, None)?
            .take(SCAN_LIMIT)
            .read_to_end(&mut body)
            .map_err(bosun_store::StoreError::Compress)?;
        let truncated = m.size - head_len > SCAN_LIMIT;
        Ok(Some(Loaded {
            head,
            body,
            truncated,
        }))
    })
}

fn request_target(head: &[u8]) -> String {
    String::from_utf8_lossy(head)
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string()
}

pub async fn flow_engage(State(st): State<AppState>, caller: Caller, Path(id): Path<FlowId>) -> R {
    caller.require(Role::Viewer)?;
    let p = st.project();
    let report =
        tokio::task::spawn_blocking(move || -> Result<Option<EngageReport>, bosun_store::StoreError> {
            let Some(req) = load(&p, id, Which::Request)? else {
                return Ok(None);
            };
            let ct = header_value(&req.head, "content-type");
            let params = engage::parameters(&request_target(&req.head), ct.as_deref(), &req.body);
            let mut findings = Vec::new();
            let mut truncated = false;
            let mut undecoded = None;
            if let Some(resp) = load(&p, id, Which::Response)? {
                truncated = resp.truncated;
                let ce = header_value(&resp.head, "content-encoding");
                let body = match codec::decode(ce.as_deref(), &resp.body, SCAN_LIMIT as usize) {
                    codec::Decoded::Plain => Some(resp.body),
                    codec::Decoded::Ok { data, truncated: t } => {
                        truncated |= t;
                        Some(data)
                    }
                    codec::Decoded::Unsupported(c) => {
                        undecoded = Some(c);
                        None
                    }
                    codec::Decoded::Failed(e) => {
                        undecoded = Some(e);
                        None
                    }
                };
                if let Some(body) = body {
                    let text = String::from_utf8_lossy(&body);
                    let mime = header_value(&resp.head, "content-type")
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if mime.contains("html") || text.trim_start().starts_with('<') {
                        findings.extend(engage::find_in_html(&text));
                    }
                    findings.extend(engage::find_urls(&text));
                    findings.truncate(engage::MAX_FINDINGS * 2);
                }
            }
            Ok(Some(EngageReport {
                findings,
                params,
                truncated,
                undecoded,
            }))
        })
        .await
        .map_err(crate::handlers::internal)?
        .map_err(crate::handlers::internal)?;
    match report {
        Some(r) => Ok(Json(r).into_response()),
        None => Err(reject(StatusCode::NOT_FOUND, "no such flow")),
    }
}

#[derive(Debug, Deserialize)]
pub struct PocQuery {
    /// "1" to submit the form as soon as the page opens.
    pub auto: Option<String>,
}

pub async fn flow_csrf_poc(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<FlowId>,
    Query(q): Query<PocQuery>,
) -> R {
    caller.require(Role::Viewer)?;
    let auto_submit = q.auto.as_deref().is_some_and(|a| a == "1" || a == "true");
    let p = st.project();
    let built = tokio::task::spawn_blocking(
        move || -> Result<Option<Result<String, PocError>>, bosun_store::StoreError> {
            let Some(meta) = p.flow_meta(id)? else {
                return Ok(None);
            };
            let Some(req) = load(&p, id, Which::Request)? else {
                return Ok(None);
            };
            if req.truncated {
                return Ok(Some(Err(PocError::Unsupported(
                    "the request body is too large to copy into a form".into(),
                ))));
            }
            let s = &meta.summary;
            let default_port = matches!((s.scheme.as_str(), s.port), ("https", 443) | ("http", 80));
            let authority = if default_port {
                s.host.clone()
            } else {
                format!("{}:{}", s.host, s.port)
            };
            let url = format!("{}://{authority}{}", s.scheme.as_str(), request_target(&req.head));
            let ct = header_value(&req.head, "content-type");
            Ok(Some(engage::csrf_poc(&PocInput {
                method: &s.method,
                url: &url,
                content_type: ct.as_deref(),
                body: &req.body,
                auto_submit,
            })))
        },
    )
    .await
    .map_err(crate::handlers::internal)?
    .map_err(crate::handlers::internal)?;
    let html = match built {
        None => return Err(reject(StatusCode::NOT_FOUND, "no such flow")),
        Some(Err(e)) => return Err(reject(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string())),
        Some(Ok(h)) => h,
    };
    let mut r = html.into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"csrf-poc-{id}.html\""))
            .unwrap_or(HeaderValue::from_static("attachment")),
    );
    // Belt and braces: a copy opened in the wrong place can neither run script nor reach anything.
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox; default-src 'none'"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Ok(r)
}

/// The most requests of a host one analysis reads, and how many of them it may read a body for.
const ANALYSIS_DEFAULT: u32 = 5_000;
const ANALYSIS_MAX: u32 = 20_000;
/// Request bodies longer than this are not read for parameters.
const ANALYSIS_BODY: u64 = 64 << 10;

#[derive(Debug, Deserialize)]
pub struct AnalysisQuery {
    pub host: String,
    pub port: Option<u16>,
    /// How many of the newest requests to read (default 5,000, most 20,000).
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HostAnalysis {
    pub host: String,
    pub port: Option<u16>,
    /// The host has more recorded requests than were read; the newest were.
    pub capped: bool,
    #[serde(flatten)]
    pub analysis: TargetAnalysis,
}

/// The distinct endpoints and parameters of one host across the whole history, with counts.
pub async fn host_analysis(State(st): State<AppState>, caller: Caller, Query(q): Query<AnalysisQuery>) -> R {
    caller.require(Role::Viewer)?;
    let host = q.host.trim().to_ascii_lowercase();
    if host.is_empty() || host.len() > 255 {
        return Err(reject(StatusCode::BAD_REQUEST, "give a host"));
    }
    let limit = q.limit.unwrap_or(ANALYSIS_DEFAULT).clamp(1, ANALYSIS_MAX);
    let port = q.port;
    let p = st.project();
    let name = host.clone();
    let (analysis, capped) = tokio::task::spawn_blocking(
        move || -> Result<(TargetAnalysis, bool), bosun_store::StoreError> {
            // One extra row tells whether there was more than `limit`.
            let rows = p.host_requests(&name, port, limit + 1)?;
            let capped = rows.len() > limit as usize;
            let mut an = Analyzer::new();
            for r in rows.iter().take(limit as usize) {
                // Query parameters come with the request line; only a method that can carry a body needs the message.
                let wants_body = !matches!(r.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE");
                let (ct, body) = if wants_body {
                    p.with_message(r.id, Which::Request, |m| {
                        let Some(m) = m else { return Ok((None, Vec::new())) };
                        let head = m.head()?;
                        let ct = header_value(&head, "content-type");
                        let head_len = head.len() as u64;
                        let mut body = Vec::new();
                        if m.size.saturating_sub(head_len) <= ANALYSIS_BODY {
                            m.body(head_len, 0, None)?
                                .take(ANALYSIS_BODY)
                                .read_to_end(&mut body)
                                .map_err(bosun_store::StoreError::Compress)?;
                        }
                        Ok((ct, body))
                    })?
                } else {
                    (None, Vec::new())
                };
                an.add(&Observation {
                    method: &r.method,
                    path: &r.path,
                    status: r.status,
                    content_type: ct.as_deref(),
                    body: &body,
                });
            }
            Ok((an.finish(), capped))
        },
    )
    .await
    .map_err(crate::handlers::internal)?
    .map_err(crate::handlers::internal)?;
    Ok(Json(HostAnalysis {
        host,
        port,
        capped,
        analysis,
    })
    .into_response())
}
