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
use bosun_store::{Confidence, NewIssue, Role, Severity};
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
    /// Save each finding as an issue (rule `authz-matrix`) that points at the probe's recorded flow.
    #[serde(default)]
    pub save_issues: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MatrixResult {
    pub rows: Vec<Row>,
    pub findings: Vec<bosun_auth::Finding>,
    /// Issues saved (0 unless `save_issues` was set).
    pub issues_saved: usize,
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
    let mut origins = Vec::new();
    for (spec, flow) in b.probes.iter().zip(flows) {
        let f = flow.ok_or_else(|| reject(StatusCode::NOT_FOUND, "no such flow"))?;
        origins.push((
            spec.flow_id,
            f.summary.scheme.as_str().to_string(),
            f.summary.host.clone(),
            f.summary.port,
            f.summary.path.split('?').next().unwrap_or("/").to_string(),
        ));
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
    let findings: Vec<bosun_auth::Finding> = rows.iter().flat_map(Row::findings).collect();
    let mut issues_saved = 0;
    if b.save_issues {
        let mut issues = Vec::new();
        for (row, (flow_id, scheme, host, port, path)) in rows.iter().zip(origins) {
            for f in row.findings() {
                issues.push(issue_of(&f, flow_id, &scheme, &host, port, &path));
            }
        }
        issues_saved = issues.len();
        if !issues.is_empty() {
            let p = st.project();
            tokio::task::spawn_blocking(move || p.scan_commit(&[], &issues))
                .await
                .map_err(|_| {
                    reject(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal error (see the server log)",
                    )
                })?
                .map_err(|e| {
                    tracing::error!(error = %e, "could not save the matrix findings");
                    reject(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal error (see the server log)",
                    )
                })?;
        }
    }
    Ok(Json(MatrixResult {
        rows,
        findings,
        issues_saved,
    })
    .into_response())
}

fn issue_of(
    f: &bosun_auth::Finding,
    flow_id: FlowId,
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
) -> NewIssue {
    let anonymous = f.kind == bosun_auth::FindingKind::MissingAuthentication;
    let who = if anonymous {
        "nobody (no login)"
    } else {
        f.identity.as_str()
    };
    NewIssue {
        rule: "authz-matrix".into(),
        title: if anonymous {
            format!("Missing authentication: \"{}\" answers without a login", f.label)
        } else {
            format!(
                "Broken access control: {} can reach \"{}\" ({}'s)",
                f.identity, f.label, f.owner
            )
        },
        severity: Severity::High,
        confidence: Confidence::Firm,
        flow_id,
        scheme: scheme.into(),
        host: host.into(),
        port,
        path: path.into(),
        detail: format!(
            "The request recorded as {}, replayed as {who}, got status {:?} and a body {}% like the owner's.",
            f.owner, f.status, f.similarity
        ),
        evidence: Vec::new(),
        remediation:
            "Check on the server that the account asking is allowed to read this object or use this function."
                .into(),
        cwe: vec![if anonymous { 306 } else { 639 }],
        owasp: vec!["A01:2021".into()],
        fingerprint: format!("authz-matrix|{}|{host}|{path}|{}", f.identity, f.label),
        time_ms: bosun_model::now_ms(),
    }
}
