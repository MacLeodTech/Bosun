//! The passive scanner's issues: list, read, triage and rescan.
//!
//! The scanner itself ([`bosun_scan`]) runs beside the recorder and reads what the proxy stored; this module is only
//! the API around its results. Changing an issue's status and starting a rescan are audited.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
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
