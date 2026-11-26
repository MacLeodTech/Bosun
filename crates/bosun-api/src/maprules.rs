//! Map Local, Map Remote and throttle rules. Saving them replaces the list, is audited, and is checked first:
//! a Map Local directory must exist, and a Map Remote target must pass the scope gate (`Gate::check`), so a rule
//! pointing out of scope is refused when it is saved as well as when a request meets it.
//!
//! Map Local serves files from this machine, so a list that holds a Map Local rule needs the admin role. The
//! other kinds need the tester role, like match-and-replace.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bosun_proxy::Proxy;
use bosun_proxy::mapping::{MapKind, MapRule, MapRules, parse_target};
use bosun_store::{Role, StoreError};

use crate::AppState;
use crate::auth::Caller;
use crate::security::reject;

type R = Result<Response, Response>;

fn internal<E: std::fmt::Display>(e: E) -> Response {
    tracing::error!(error = %e, "a map rule task failed");
    reject(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error (see the server log)",
    )
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Response> {
    tokio::task::spawn_blocking(f).await.map_err(internal)
}

/// Load the active project's saved rules into the proxy. Rules that cannot be used now are left out. Blocking.
pub(crate) fn reload(proxy: &Proxy) -> Result<(), StoreError> {
    let specs: Vec<MapRule> = proxy
        .project()
        .map_rule_specs()?
        .iter()
        .filter_map(|s| serde_json::from_str(s).ok())
        .collect();
    let skipped = proxy.load_map_rules(specs);
    if skipped > 0 {
        tracing::warn!(
            skipped,
            "some saved map rules cannot be used (a missing directory?) and were left out"
        );
    }
    Ok(())
}

pub async fn get(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(st.inner.proxy.map_rules()).into_response())
}

pub async fn put(State(st): State<AppState>, caller: Caller, Json(rules): Json<Vec<MapRule>>) -> R {
    caller.require(Role::Tester)?;
    if rules.iter().any(|r| r.kind == MapKind::MapLocal) {
        caller.require(Role::Admin)?;
    }
    let _settings = st.inner.projects.settings_guard().await;
    let bad = |m: &str| reject(StatusCode::BAD_REQUEST, m);
    if rules.len() > bosun_proxy::mapping::MAX_MAP_RULES {
        return Err(bad("too many rules"));
    }
    // Validate before anything changes: syntax, directories, then the gate for every Map Remote target.
    let (proxy, check) = (st.inner.proxy.clone(), rules.clone());
    blocking(move || -> Result<(), String> {
        MapRules::compile(check.clone())?;
        for (i, r) in check
            .iter()
            .enumerate()
            .filter(|(_, r)| r.enabled && r.kind == MapKind::MapRemote)
        {
            let t = parse_target(&r.target).map_err(|e| format!("rule {}: {e}", i + 1))?;
            proxy
                .check_remote_target(&t)
                .map_err(|e| format!("rule {}: the target is not allowed: {e}", i + 1))?;
        }
        Ok(())
    })
    .await?
    .map_err(|e| bad(&e))?;
    let jsons: Vec<String> = rules
        .iter()
        .filter_map(|r| serde_json::to_string(r).ok())
        .collect();
    let p = st.project();
    blocking(move || p.set_map_rule_specs(&jsons))
        .await?
        .map_err(|e| match e {
            StoreError::Conflict(m) => reject(StatusCode::CONFLICT, &m),
            e => internal(e),
        })?;
    st.inner.proxy.set_map_rules(rules.clone()).map_err(|e| bad(&e))?;
    let detail = format!(
        "{} rules ({} Map Local, {} Map Remote, {} throttle)",
        rules.len(),
        rules.iter().filter(|r| r.kind == MapKind::MapLocal).count(),
        rules.iter().filter(|r| r.kind == MapKind::MapRemote).count(),
        rules.iter().filter(|r| r.kind == MapKind::Throttle).count(),
    );
    caller.audit(&st, "maprules.update", &detail).await;
    Ok(Json(rules).into_response())
}
