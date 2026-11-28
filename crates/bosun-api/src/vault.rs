//! The credential vault: named secrets (auth configs, passwords, tokens, keys, OAST keys) kept sealed with the data
//! key. The API never returns a secret: lists and results carry id, name, kind, timestamps and a masked hint.
//! Other features refer to a secret by its id and open it server-side with [`open_secret`]. Writes are admin
//! actions and are audited by name (never by value).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bosun_ca::DataKey;
use bosun_model::now_ms;
use bosun_store::{Project, Role, StoreError, VaultEntry};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::{empty, reject};

type R = Result<Response, Response>;

/// The kinds an entry can have.
pub const KINDS: &[&str] = &[
    "password",
    "token",
    "api_key",
    "auth_config",
    "client_cert_password",
    "oast_key",
    "other",
];
const MAX_SECRET: usize = 64 * 1024;
const MAX_NAME: usize = 100;

fn purpose(id: i64) -> String {
    format!("vault:{id}")
}

fn internal<E: std::fmt::Display>(e: E) -> Response {
    tracing::error!(error = %e, "a vault task failed");
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

/// A masked hint: a long secret shows its last two characters, a short one nothing.
fn hint(secret: &str) -> String {
    let n = secret.chars().count();
    if n >= 12 {
        let tail: String = secret.chars().skip(n - 2).collect();
        format!("••••{tail}")
    } else {
        "••••".to_string()
    }
}

/// Open one secret for server-side use (a scan's credentials, an OAST client). Blocking. `None` if no such entry.
pub fn open_secret(project: &Project, key: &DataKey, id: i64) -> Result<Option<Vec<u8>>, StoreError> {
    let Some(sealed) = project.vault_sealed(id)? else {
        return Ok(None);
    };
    key.open(&purpose(id), &sealed)
        .map(Some)
        .map_err(|e| StoreError::Locked(e.to_string()))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VaultList {
    pub entries: Vec<VaultEntry>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VaultCreate {
    /// A unique name, 1 to 100 characters.
    pub name: String,
    /// One of `password`, `token`, `api_key`, `auth_config`, `client_cert_password`, `oast_key`, `other`.
    pub kind: String,
    /// The secret. Stored sealed; never returned.
    pub secret: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VaultUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    /// A new secret; leave out to keep the current one.
    #[serde(default)]
    pub secret: Option<String>,
}

fn check_name(n: &str) -> Result<(), Response> {
    let n = n.trim();
    if n.is_empty() || n.chars().count() > MAX_NAME || n.chars().any(char::is_control) {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "the name must be 1 to 100 characters without control characters",
        ));
    }
    Ok(())
}

fn check_kind(k: &str) -> Result<(), Response> {
    if KINDS.contains(&k) {
        Ok(())
    } else {
        Err(reject(
            StatusCode::BAD_REQUEST,
            &format!("the kind must be one of: {}", KINDS.join(", ")),
        ))
    }
}

fn check_secret(s: &str) -> Result<(), Response> {
    if s.is_empty() || s.len() > MAX_SECRET {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "the secret must be 1 byte to 64 KiB",
        ));
    }
    Ok(())
}

pub async fn list(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let p = st.project();
    let entries = blocking(move || p.vault_list()).await?.map_err(internal)?;
    Ok(Json(VaultList { entries }).into_response())
}

pub async fn create(State(st): State<AppState>, caller: Caller, Json(b): Json<VaultCreate>) -> R {
    caller.require(Role::Admin)?;
    check_name(&b.name)?;
    check_kind(&b.kind)?;
    check_secret(&b.secret)?;
    let (p, key) = (st.project(), st.inner.data_key.clone());
    let name = b.name.trim().to_string();
    let (n, k) = (name.clone(), b.kind.clone());
    let h = hint(&b.secret);
    let secret = b.secret;
    let entry = blocking(move || {
        p.vault_add(&n, &k, &h, now_ms(), |id| {
            key.seal(&purpose(id), secret.as_bytes())
                .map_err(|e| StoreError::Locked(e.to_string()))
        })
    })
    .await?
    .map_err(store_err)?;
    caller
        .audit(&st, "vault.create", &format!("vault entry `{name}` ({})", b.kind))
        .await;
    Ok((StatusCode::CREATED, Json(entry)).into_response())
}

pub async fn update(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<i64>,
    Json(b): Json<VaultUpdate>,
) -> R {
    caller.require(Role::Admin)?;
    let name = b.name.as_deref().map(str::trim).map(str::to_string);
    if let Some(n) = &name {
        check_name(n)?;
    }
    if let Some(k) = &b.kind {
        check_kind(k)?;
    }
    if let Some(s) = &b.secret {
        check_secret(s)?;
    }
    let sealed = match &b.secret {
        Some(s) => Some((
            st.inner
                .data_key
                .seal(&purpose(id), s.as_bytes())
                .map_err(internal)?,
            hint(s),
        )),
        None => None,
    };
    let rotated = sealed.is_some();
    let (p, kind) = (st.project(), b.kind.clone());
    let entry = blocking(move || {
        p.vault_update(
            id,
            name.as_deref(),
            kind.as_deref(),
            sealed.as_ref().map(|(s, h)| (s.as_slice(), h.as_str())),
            now_ms(),
        )
    })
    .await?
    .map_err(store_err)?
    .ok_or_else(|| reject(StatusCode::NOT_FOUND, "no such vault entry"))?;
    caller
        .audit(
            &st,
            "vault.update",
            &format!(
                "vault entry `{}`{}",
                entry.name,
                if rotated { " (secret replaced)" } else { "" }
            ),
        )
        .await;
    Ok(Json(entry).into_response())
}

pub async fn delete(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Admin)?;
    let p = st.project();
    let name = blocking(move || p.vault_delete(id))
        .await?
        .map_err(store_err)?
        .ok_or_else(|| reject(StatusCode::NOT_FOUND, "no such vault entry"))?;
    caller
        .audit(&st, "vault.delete", &format!("vault entry `{name}`"))
        .await;
    Ok(empty(StatusCode::NO_CONTENT))
}
