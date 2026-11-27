//! The authorisation matrix (WP-56): replay recorded requests as other accounts and as nobody, and report where
//! the answers are the same.
//!
//! Probes are recorded flows. Every send goes through the Repeater's engine, so the scope gate, the kill switch
//! and the per-host rate limit apply. An account's credentials are either headers given in the request or a vault
//! entry, opened here on the server and never returned. Running the matrix is audited.

use std::collections::HashSet;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bosun_auth::{Identity, Options, Probe, Row, run};
use bosun_model::{FlowId, Target};
use bosun_store::Role;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::reject;

type R = Result<Response, Response>;

/// The most probes in one API run (the engine allows more).
const MAX_API_PROBES: usize = 200;

/// Where a header value comes from: a vault entry, opened on the server.
#[derive(Debug, Deserialize, ToSchema)]
pub struct VaultHeader {
    pub vault_id: i64,
    /// The header to set, such as `Authorization` or `Cookie`.
    pub header: String,
    /// Text put before the secret, such as `Bearer `.
    #[serde(default)]
    pub prefix: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MatrixIdentity {
    pub name: String,
    /// Headers that make a request be this account.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Headers taken from the vault.
    #[serde(default)]
    pub vault: Vec<VaultHeader>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MatrixProbe {
    /// A recorded flow, replayed as each account.
    pub flow_id: FlowId,
    /// The account the flow was recorded as (an identity name).
    pub owner: String,
    /// Accounts that are meant to reach it too.
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MatrixBody {
    pub identities: Vec<MatrixIdentity>,
    pub probes: Vec<MatrixProbe>,
    #[serde(default)]
    pub options: Option<Options>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MatrixResult {
    pub rows: Vec<Row>,
    pub findings: Vec<bosun_auth::Finding>,
}

fn bad(msg: &str) -> Response {
    reject(StatusCode::BAD_REQUEST, msg)
}

fn header_ok(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

pub async fn matrix(State(st): State<AppState>, caller: Caller, Json(b): Json<MatrixBody>) -> R {
    caller.require(Role::Tester)?;
    if b.probes.is_empty() || b.probes.len() > MAX_API_PROBES {
        return Err(bad("send 1 to 200 probes"));
    }
    if b.identities.is_empty() || b.identities.len() > bosun_auth::MAX_IDENTITIES {
        return Err(bad("send 1 to 20 identities"));
    }
    let names: HashSet<&str> = b.identities.iter().map(|i| i.name.as_str()).collect();
    if names.len() != b.identities.len() {
        return Err(bad("identity names must be unique"));
    }
    for p in &b.probes {
        if !names.contains(p.owner.as_str()) {
            return Err(bad("a probe's owner must be one of the identities"));
        }
    }
    for i in &b.identities {
        if i.headers.iter().any(|(n, v)| !header_ok(n, v))
            || i.vault.iter().any(|v| !header_ok(&v.header, &v.prefix))
        {
            return Err(bad("a header name or value is not valid"));
        }
    }

    // Open the vault entries and load the recorded flows off the async threads.
    let p = st.project();
    let key = st.inner.data_key.clone();
    let wanted: Vec<FlowId> = b.probes.iter().map(|p| p.flow_id).collect();
    let vault: Vec<(usize, usize, i64)> = b
        .identities
        .iter()
        .enumerate()
        .flat_map(|(i, id)| id.vault.iter().enumerate().map(move |(j, v)| (i, j, v.vault_id)))
        .collect();
    let (secrets, flows) = tokio::task::spawn_blocking(move || {
        let mut secrets = Vec::new();
        for (i, j, id) in vault {
            let s = crate::vault::open_secret(&p, &key, id)?
                .ok_or_else(|| bosun_store::StoreError::Conflict(format!("no vault entry {id}")))?;
            secrets.push((i, j, String::from_utf8_lossy(&s).into_owned()));
        }
        let mut flows = Vec::new();
        for id in wanted {
            flows.push(p.get_flow(id)?);
        }
        Ok::<_, bosun_store::StoreError>((secrets, flows))
    })
    .await
    .map_err(|_| {
        reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error (see the server log)",
        )
    })?
    .map_err(|e| match e {
        bosun_store::StoreError::Conflict(m) => bad(&m),
        e => {
            tracing::error!(error = %e, "the authorisation matrix could not load its inputs");
            reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error (see the server log)",
            )
        }
    })?;

    let mut identities: Vec<Identity> = b
        .identities
        .iter()
        .map(|i| Identity {
            name: i.name.clone(),
            headers: i.headers.clone(),
        })
        .collect();
    for (i, j, secret) in secrets {
        let v = &b.identities[i].vault[j];
        if secret.bytes().any(|c| c == b'\r' || c == b'\n' || c == 0) {
            return Err(bad("a vault secret used as a header has a line break"));
        }
        identities[i]
            .headers
            .push((v.header.clone(), format!("{}{}", v.prefix, secret)));
    }

    let mut probes = Vec::new();
    for (spec, flow) in b.probes.iter().zip(flows) {
        let f = flow.ok_or_else(|| reject(StatusCode::NOT_FOUND, "no such flow"))?;
        probes.push(Probe {
            label: spec
                .label
                .clone()
                .unwrap_or_else(|| format!("{} {}", f.summary.method, f.summary.path)),
            owner: spec.owner.clone(),
            allowed: spec.allowed.clone(),
            target: Target::new(f.summary.scheme, f.summary.host.clone(), f.summary.port),
            request: f.request,
        });
    }

    caller
        .audit(
            &st,
            "authmatrix.run",
            &format!("{} probes as {} accounts", probes.len(), identities.len()),
        )
        .await;
    let rows = run(
        &st.inner.repeater,
        &identities,
        &probes,
        &b.options.unwrap_or_default(),
    )
    .await
    .map_err(|e| bad(&e))?;
    let findings = rows.iter().flat_map(Row::findings).collect();
    Ok(Json(MatrixResult { rows, findings }).into_response())
}
