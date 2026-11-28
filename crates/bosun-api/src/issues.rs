//! The passive scanner's issues: list, read, triage and rescan.
//!
//! The scanner itself ([`bosun_scan`]) runs beside the recorder and reads what the proxy stored; this module is only
//! the API around its results. Changing an issue's status and starting a rescan are audited.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bosun_store::{Confidence, Issue, IssueFilter, IssueStatus, Role, Severity};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::{empty, reject};

type R = Result<Response, Response>;

fn internal<E: std::fmt::Display>(e: E) -> Response {
    tracing::error!(error = %e, "an issues database task failed");
    reject(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error (see the server log)",
    )
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Response> {
    tokio::task::spawn_blocking(f).await.map_err(internal)
}

#[derive(Debug, Deserialize)]
pub struct IssueQuery {
    status: Option<String>,
    severity: Option<String>,
    confidence: Option<String>,
    rule: Option<String>,
    host: Option<String>,
    flow_id: Option<i64>,
    /// Text in the title, detail or path.
    q: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IssueList {
    /// Newest sighting first.
    pub issues: Vec<Issue>,
    /// Flows the scanner has not read yet.
    pub pending: i64,
    /// The rule ids the scanner has, for filters.
    pub rules: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct IssueChange {
    pub status: IssueStatus,
}

fn parse<T>(v: Option<&str>, what: &str, f: fn(&str) -> Option<T>) -> Result<Option<T>, Response> {
    match v.filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => f(s)
            .map(Some)
            .ok_or_else(|| reject(StatusCode::BAD_REQUEST, &format!("{what}: not a known value"))),
    }
}

pub async fn list(State(st): State<AppState>, caller: Caller, Query(q): Query<IssueQuery>) -> R {
    caller.require(Role::Viewer)?;
    let filter = IssueFilter {
        status: parse(q.status.as_deref(), "status", IssueStatus::parse)?,
        severity: parse(q.severity.as_deref(), "severity", Severity::parse)?,
        confidence: parse(q.confidence.as_deref(), "confidence", Confidence::parse)?,
        rule: q.rule.filter(|s| !s.is_empty()),
        host: q.host.filter(|s| !s.is_empty()),
        flow_id: q.flow_id,
        text: q.q.map(|s| s.chars().take(200).collect()),
        limit: q.limit,
    };
    let p = st.project();
    let (issues, pending) =
        blocking(move || Ok::<_, bosun_store::StoreError>((p.issues(&filter)?, p.scan_backlog()?)))
            .await?
            .map_err(internal)?;
    Ok(Json(IssueList {
        issues,
        pending,
        rules: bosun_scan::RULES.iter().map(|s| (*s).to_string()).collect(),
    })
    .into_response())
}

pub async fn get(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Viewer)?;
    let p = st.project();
    let issue = blocking(move || p.issue(id)).await?.map_err(internal)?;
    match issue {
        Some(i) => Ok(Json(i).into_response()),
        None => Err(reject(StatusCode::NOT_FOUND, "no such issue")),
    }
}

pub async fn change(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<i64>,
    Json(b): Json<IssueChange>,
) -> R {
    caller.require(Role::Tester)?;
    let p = st.project();
    let status = b.status;
    let found = blocking(move || p.issue_set_status(id, status))
        .await?
        .map_err(internal)?;
    if !found {
        return Err(reject(StatusCode::NOT_FOUND, "no such issue"));
    }
    caller
        .audit(&st, "issue.status", &format!("issue {id}: {}", status.as_str()))
        .await;
    Ok(empty(StatusCode::NO_CONTENT))
}

pub async fn rescan(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Tester)?;
    let p = st.project();
    blocking(move || p.scan_restart()).await?.map_err(internal)?;
    caller
        .audit(&st, "issues.rescan", "all flows queued for scanning")
        .await;
    Ok(empty(StatusCode::NO_CONTENT))
}

#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    /// html, json, sarif, junit or markdown (default html).
    format: Option<String>,
    /// `0` keeps secrets in the report (tester role, audited). Anything else redacts them.
    redact: Option<String>,
    status: Option<String>,
    severity: Option<String>,
    confidence: Option<String>,
    rule: Option<String>,
    host: Option<String>,
    q: Option<String>,
}

/// How much of a flow's message one piece of evidence quotes.
const EXCERPT_MAX: u64 = 400;

fn report_issue(i: &Issue, method: String, flow: Option<&bosun_model::FlowDetail>) -> bosun_report::Issue {
    use bosun_report as r;
    let default_port = matches!((i.scheme.as_str(), i.port), ("http", 80) | ("https", 443));
    let url = if default_port {
        format!("{}://{}{}", i.scheme, i.host, i.path)
    } else {
        format!("{}://{}:{}{}", i.scheme, i.host, i.port, i.path)
    };
    let evidence = i
        .evidence
        .iter()
        .filter_map(|e| {
            let f = flow?;
            let (part, bytes) = match e.part {
                bosun_store::EvidencePart::Request => ("request", Some(&f.request)),
                bosun_store::EvidencePart::Response => ("response", f.response.as_ref()),
            };
            let bytes = bytes?;
            let start = (e.start as usize).min(bytes.len());
            let end = (e.end.min(e.start.saturating_add(EXCERPT_MAX)) as usize).clamp(start, bytes.len());
            Some(r::Evidence {
                part: part.into(),
                excerpt: String::from_utf8_lossy(&bytes[start..end]).into_owned(),
            })
        })
        .collect();
    let detail = if i.count > 1 {
        format!("{} (seen in {} flows)", i.detail, i.count)
    } else {
        i.detail.clone()
    };
    r::Issue {
        id: i.id,
        issue_type: i.rule.clone(),
        title: i.title.clone(),
        severity: match i.severity {
            Severity::Info => r::Severity::Info,
            Severity::Low => r::Severity::Low,
            Severity::Medium => r::Severity::Medium,
            Severity::High => r::Severity::High,
        },
        confidence: match i.confidence {
            Confidence::Tentative => r::Confidence::Tentative,
            Confidence::Firm => r::Confidence::Firm,
            Confidence::Certain => r::Confidence::Certain,
        },
        status: match i.status {
            IssueStatus::New => r::Status::New,
            IssueStatus::Confirmed => r::Status::Confirmed,
            IssueStatus::FalsePositive => r::Status::FalsePositive,
        },
        method,
        url,
        description: detail,
        remediation: i.remediation.clone(),
        cwe: i.cwe.clone(),
        owasp: i.owasp.clone(),
        evidence,
    }
}

/// `GET /issues/report`: the issues (same filters as the list) as a report file. Always an attachment, with a CSP
/// that lets nothing run, so a copy opened in the wrong place is inert. Secrets are redacted unless `redact=0`,
/// which needs the tester role and is audited.
pub async fn report(State(st): State<AppState>, caller: Caller, Query(q): Query<ReportQuery>) -> R {
    caller.require(Role::Viewer)?;
    let format = bosun_report::Format::parse(q.format.as_deref().unwrap_or("html"))
        .map_err(|e| reject(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let redact = q.redact.as_deref() != Some("0");
    if !redact {
        caller.require(Role::Tester)?;
    }
    let filter = IssueFilter {
        status: parse(q.status.as_deref(), "status", IssueStatus::parse)?,
        severity: parse(q.severity.as_deref(), "severity", Severity::parse)?,
        confidence: parse(q.confidence.as_deref(), "confidence", Confidence::parse)?,
        rule: q.rule.filter(|s| !s.is_empty()),
        host: q.host.filter(|s| !s.is_empty()),
        flow_id: None,
        text: q.q.map(|s| s.chars().take(200).collect()),
        limit: Some(5000),
    };
    let p = st.project();
    let issues = blocking(move || {
        let list = p.issues(&filter)?;
        let mut out = Vec::with_capacity(list.len());
        for i in &list {
            let flow = match i.flow_id {
                Some(id) => p.get_flow(id)?,
                None => None,
            };
            let method = flow
                .as_ref()
                .map(|f| f.summary.method.clone())
                .unwrap_or_default();
            out.push(report_issue(i, method, flow.as_ref()));
        }
        Ok::<_, bosun_store::StoreError>(out)
    })
    .await?
    .map_err(internal)?;
    let n = issues.len();
    let body = bosun_report::render(&issues, format, bosun_report::Options { redact });
    if !redact {
        caller
            .audit(
                &st,
                "issues.report",
                &format!("{n} issues as {} with secrets kept", format.extension()),
            )
            .await;
    }
    let mut r = body.into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(format.content_type()),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"bosun-report.{}\"",
            format.extension()
        ))
        .unwrap_or(HeaderValue::from_static("attachment")),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&format!("sandbox; {}", bosun_report::html_csp()))
            .unwrap_or(HeaderValue::from_static("sandbox; default-src 'none'")),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Ok(r)
}

#[derive(Debug, Deserialize)]
pub struct TrackerQuery {
    /// github, jira or linear.
    tracker: Option<String>,
    /// `0` keeps secrets (audited). Anything else redacts them.
    redact: Option<String>,
}

/// What `GET /issues/{id}/tracker` returns: one issue prepared for an issue tracker.
#[derive(Debug, Serialize, ToSchema)]
pub struct TrackerReply {
    pub title: String,
    /// Markdown description.
    pub body: String,
    pub labels: Vec<String>,
    /// The JSON body for the tracker's create-issue call.
    #[schema(value_type = Object)]
    pub payload: serde_json::Value,
}

/// `GET /issues/{id}/tracker`: one issue prepared for GitHub, Jira or Linear, to copy or post by hand. Bosun makes no
/// request to the tracker. Tester role (the text leaves Bosun), secrets redacted unless `redact=0`, every export audited.
pub async fn tracker(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<i64>,
    Query(q): Query<TrackerQuery>,
) -> R {
    caller.require(Role::Tester)?;
    let tracker = bosun_report::Tracker::parse(q.tracker.as_deref().unwrap_or("github"))
        .map_err(|e| reject(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let redact = q.redact.as_deref() != Some("0");
    let p = st.project();
    let found = blocking(move || {
        let Some(i) = p.issue(id)? else { return Ok(None) };
        let flow = match i.flow_id {
            Some(f) => p.get_flow(f)?,
            None => None,
        };
        let method = flow
            .as_ref()
            .map(|f| f.summary.method.clone())
            .unwrap_or_default();
        Ok::<_, bosun_store::StoreError>(Some(report_issue(&i, method, flow.as_ref())))
    })
    .await?
    .map_err(internal)?;
    let Some(issue) = found else {
        return Err(reject(StatusCode::NOT_FOUND, "no such issue"));
    };
    let x = bosun_report::tracker_export(&issue, tracker, bosun_report::Options { redact });
    caller
        .audit(
            &st,
            "issues.tracker_export",
            &format!(
                "issue {id} prepared for {tracker:?}{}",
                if redact { "" } else { " with secrets kept" }
            ),
        )
        .await;
    Ok(Json(TrackerReply {
        title: x.title,
        body: x.body,
        labels: x.labels,
        payload: x.payload,
    })
    .into_response())
}
