//! Custom passive checks: the project's own YAML checks, run by the passive scanner next to the built-in ones.
//!
//! The text is validated with the `bosun-checks` loader (its size caps and regex limits) before it is stored, and
//! the scanner compiles it again when it loads it. A check is data: it cannot run code or send a request. Every
//! change is audited. A new or changed check applies to new traffic at once and to recorded traffic after a
//! rescan (`POST /issues/rescan`).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bosun_checks::lang::parse;
use bosun_model::now_ms;
use bosun_store::{Role, StoreError, StoredCheck};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::{empty, reject};

type R = Result<Response, Response>;

fn internal<E: std::fmt::Display>(e: E) -> Response {
    tracing::error!(error = %e, "a checks database task failed");
    reject(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error (see the server log)",
    )
}

fn store_err(e: StoreError) -> Response {
    match e {
        StoreError::Conflict(m) => reject(StatusCode::CONFLICT, &m),
        e => internal(e),
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Response> {
    tokio::task::spawn_blocking(f).await.map_err(internal)
}

/// A stored check with the fields read out of its YAML.
#[derive(Debug, Serialize, ToSchema)]
pub struct CheckView {
    pub id: i64,
    /// The `id` in the YAML: the rule name on the issues it finds.
    pub check_id: String,
    pub name: String,
    /// info, low, medium or high; empty when the stored text no longer loads.
    pub severity: String,
    pub enabled: bool,
    pub yaml: String,
    pub created_ms: i64,
    pub updated_ms: i64,
}

fn view(c: StoredCheck) -> CheckView {
    let (name, severity) = match parse(&c.yaml) {
        Ok(p) => (
            p.check.info.name.clone(),
            p.check.info.severity.to_store().as_str().to_string(),
        ),
        Err(_) => (c.check_id.clone(), String::new()),
    };
    CheckView {
        id: c.id,
        check_id: c.check_id,
        name,
        severity,
        enabled: c.enabled,
        yaml: c.yaml,
        created_ms: c.created_ms,
        updated_ms: c.updated_ms,
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CheckList {
    pub checks: Vec<CheckView>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CheckBody {
    pub yaml: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CheckEnabled {
    pub enabled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CheckValidation {
    pub valid: bool,
    /// What is wrong, when it is not valid.
    pub error: Option<String>,
    pub check_id: Option<String>,
    pub name: Option<String>,
}

/// Load `yaml` with the check loader and apply the extra rules for stored checks. Returns the check id.
fn validate(yaml: &str) -> Result<(String, String), String> {
    let c = parse(yaml).map_err(|e| e.0)?;
    if !c.is_passive() {
        return Err(
            "a stored check needs a `passive` section (active checks arrive with the active scanner)".into(),
        );
    }
    if bosun_scan::RULES.iter().any(|i| *i == c.check.id) || bosun_checks::all_ids().contains(&c.check.id) {
        return Err(format!(
            "`{}` is the id of a built-in check; pick another id",
            c.check.id
        ));
    }
    Ok((c.check.id.clone(), c.check.info.name.clone()))
}

fn invalid(msg: &str) -> Response {
    reject(StatusCode::BAD_REQUEST, msg)
}

pub async fn list(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let p = st.project();
    let rows = blocking(move || p.checks()).await?.map_err(internal)?;
    Ok(Json(CheckList {
        checks: rows.into_iter().map(view).collect(),
    })
    .into_response())
}

pub async fn validate_only(State(_st): State<AppState>, caller: Caller, Json(b): Json<CheckBody>) -> R {
    caller.require(Role::Tester)?;
    Ok(Json(match validate(&b.yaml) {
        Ok((id, name)) => CheckValidation {
            valid: true,
            error: None,
            check_id: Some(id),
            name: Some(name),
        },
        Err(e) => CheckValidation {
            valid: false,
            error: Some(e),
            check_id: None,
            name: None,
        },
    })
    .into_response())
}

pub async fn add(State(st): State<AppState>, caller: Caller, Json(b): Json<CheckBody>) -> R {
    caller.require(Role::Tester)?;
    let (check_id, _) = validate(&b.yaml).map_err(|e| invalid(&e))?;
    let p = st.project();
    let (cid, yaml) = (check_id.clone(), b.yaml);
    let stored = blocking(move || {
        let id = p.check_add(&cid, &yaml, now_ms())?;
        p.check(id)
    })
    .await?
    .map_err(store_err)?;
    caller
        .audit(&st, "check.add", &format!("custom check `{check_id}`"))
        .await;
    match stored {
        Some(c) => Ok((StatusCode::CREATED, Json(view(c))).into_response()),
        None => Err(internal("the new check is missing")),
    }
}

pub async fn replace(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<i64>,
    Json(b): Json<CheckBody>,
) -> R {
    caller.require(Role::Tester)?;
    let (check_id, _) = validate(&b.yaml).map_err(|e| invalid(&e))?;
    let p = st.project();
    let (cid, yaml) = (check_id.clone(), b.yaml);
    let stored = blocking(move || {
        if !p.check_update(id, &cid, &yaml, now_ms())? {
            return Ok(None);
        }
        p.check(id)
    })
    .await?
    .map_err(store_err)?;
    let Some(c) = stored else {
        return Err(reject(StatusCode::NOT_FOUND, "no such check"));
    };
    caller
        .audit(&st, "check.update", &format!("custom check `{check_id}`"))
        .await;
    Ok(Json(view(c)).into_response())
}

pub async fn set_enabled(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<i64>,
    Json(b): Json<CheckEnabled>,
) -> R {
    caller.require(Role::Tester)?;
    let p = st.project();
    let enabled = b.enabled;
    let found = blocking(move || {
        Ok::<_, StoreError>(match p.check(id)? {
            Some(c) if p.check_set_enabled(id, enabled, now_ms())? => Some(c.check_id),
            _ => None,
        })
    })
    .await?
    .map_err(store_err)?;
    let Some(check_id) = found else {
        return Err(reject(StatusCode::NOT_FOUND, "no such check"));
    };
    caller
        .audit(
            &st,
            "check.enable",
            &format!(
                "custom check `{check_id}` {}",
                if enabled { "enabled" } else { "disabled" }
            ),
        )
        .await;
    Ok(empty(StatusCode::NO_CONTENT))
}

pub async fn delete(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Tester)?;
    let p = st.project();
    let found = blocking(move || {
        let c = p.check(id)?;
        if c.is_some() {
            p.check_delete(id)?;
        }
        Ok::<_, StoreError>(c.map(|c| c.check_id))
    })
    .await?
    .map_err(store_err)?;
    let Some(check_id) = found else {
        return Err(reject(StatusCode::NOT_FOUND, "no such check"));
    };
    caller
        .audit(&st, "check.delete", &format!("custom check `{check_id}`"))
        .await;
    Ok(empty(StatusCode::NO_CONTENT))
}
