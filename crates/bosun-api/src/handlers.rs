//! API handlers. Every handler takes a [`Caller`] (so it cannot be reached without authentication) and checks
//! the role it needs before doing anything.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bosun_model::{FlowId, RawResponse};
use bosun_proxy::{Decision, InterceptSettings, RuleSpec};
use bosun_scope::{Scope, ScopeSpec};
use bosun_store::codec::{self, Decoded};
use bosun_store::{FlowFilter, Role};
use serde::{Deserialize, Serialize};

use crate::auth::{Caller, check_password_policy, check_username, hash_password, random_token};
use crate::security::{empty, reject};
use crate::{AppState, SETTING_INTERCEPT, SETTING_RULES, SETTING_SCOPE};

type R = Result<Response, Response>;

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "API error");
    reject(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error (see the server log)",
    )
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Response> {
    tokio::task::spawn_blocking(f).await.map_err(internal)
}

pub async fn status(State(st): State<AppState>) -> Response {
    let setup_required = st
        .inner
        .setup_code
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some();
    Json(serde_json::json!({
        "name": "Bosun",
        "version": env!("CARGO_PKG_VERSION"),
        "setup_required": setup_required,
    }))
    .into_response()
}

// ---- History ----------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct FlowQuery {
    text: Option<String>,
    host: Option<String>,
    /// Comma-separated.
    methods: Option<String>,
    status_min: Option<u16>,
    status_max: Option<u16>,
    #[serde(default)]
    in_scope_only: bool,
    source: Option<String>,
    /// Comma-separated extensions to hide.
    hide_ext: Option<String>,
    before: Option<FlowId>,
    after: Option<FlowId>,
    limit: Option<u32>,
}

fn csv(s: Option<String>) -> Option<Vec<String>> {
    s.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    })
}

pub async fn list_flows(State(st): State<AppState>, caller: Caller, Query(q): Query<FlowQuery>) -> R {
    caller.require(Role::Viewer)?;
    let filter = FlowFilter {
        text: q.text,
        host: q.host,
        methods: csv(q.methods),
        status_min: q.status_min,
        status_max: q.status_max,
        in_scope_only: q.in_scope_only,
        source: q.source.as_deref().and_then(bosun_model::FlowSource::parse),
        hide_extensions: csv(q.hide_ext),
        before_id: q.before,
        after_id: q.after,
        limit: q.limit,
    };
    let p = st.inner.project.clone();
    let flows = blocking(move || p.list_flows(&filter)).await?.map_err(internal)?;
    Ok(Json(flows).into_response())
}

#[derive(Serialize)]
struct FlowView {
    #[serde(flatten)]
    detail: bosun_model::FlowDetail,
    /// The response body with Content-Encoding undone, when it was encoded.
    #[serde(with = "bosun_model::b64_opt")]
    response_body_decoded: Option<Vec<u8>>,
    decode_note: Option<String>,
}

pub async fn get_flow(State(st): State<AppState>, caller: Caller, Path(id): Path<FlowId>) -> R {
    caller.require(Role::Viewer)?;
    let p = st.inner.project.clone();
    let detail = blocking(move || p.get_flow(id)).await?.map_err(internal)?;
    let Some(detail) = detail else {
        return Err(reject(StatusCode::NOT_FOUND, "no such flow"));
    };
    let (mut decoded, mut note) = (None, None);
    if let Some(resp) = detail
        .response
        .as_deref()
        .and_then(|r| RawResponse::parse(r).ok())
    {
        let ce = resp
            .header("content-encoding")
            .map(|v| String::from_utf8_lossy(v).to_string());
        match codec::decode(ce.as_deref(), &resp.body, codec::DEFAULT_DECODE_LIMIT) {
            Decoded::Plain => {}
            Decoded::Ok { data, truncated } => {
                decoded = Some(data);
                if truncated {
                    note = Some("decoded body truncated at 32 MiB".into());
                }
            }
            Decoded::Unsupported(c) => note = Some(format!("unsupported content-encoding {c}")),
            Decoded::Failed(e) => note = Some(format!("could not decode: {e}")),
        }
    }
    Ok(Json(FlowView {
        detail,
        response_body_decoded: decoded,
        decode_note: note,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct Annotate {
    tags: Option<Vec<String>>,
    note: Option<String>,
}

pub async fn annotate_flow(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<FlowId>,
    Json(b): Json<Annotate>,
) -> R {
    caller.require(Role::Tester)?;
    if b.tags
        .as_ref()
        .is_some_and(|t| t.len() > 32 || t.iter().any(|x| x.len() > 64))
        || b.note.as_ref().is_some_and(|n| n.len() > 10_000)
    {
        return Err(reject(StatusCode::BAD_REQUEST, "too many or too long tags/note"));
    }
    let p = st.inner.project.clone();
    let found = blocking(move || p.set_annotations(id, b.tags.as_deref(), b.note.as_deref()))
        .await?
        .map_err(internal)?;
    Ok(if found {
        empty(StatusCode::NO_CONTENT)
    } else {
        reject(StatusCode::NOT_FOUND, "no such flow")
    })
}

#[derive(Deserialize)]
pub struct DeleteFlows {
    ids: Vec<FlowId>,
}

pub async fn delete_flows(State(st): State<AppState>, caller: Caller, Json(b): Json<DeleteFlows>) -> R {
    caller.require(Role::Tester)?;
    if b.ids.len() > 100_000 {
        return Err(reject(StatusCode::BAD_REQUEST, "too many ids"));
    }
    let n_ids = b.ids.len();
    let p = st.inner.project.clone();
    let n = blocking(move || p.delete_flows(&b.ids))
        .await?
        .map_err(internal)?;
    caller.audit(&st, "flows.delete", &format!("{n} of {n_ids} requested"));
    Ok(Json(serde_json::json!({ "deleted": n })).into_response())
}

#[derive(Deserialize)]
pub struct WsQuery {
    after: Option<i64>,
    limit: Option<u32>,
}

pub async fn ws_messages(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<FlowId>,
    Query(q): Query<WsQuery>,
) -> R {
    caller.require(Role::Viewer)?;
    let p = st.inner.project.clone();
    let msgs = blocking(move || p.ws_messages(id, q.after, q.limit.unwrap_or(500)))
        .await?
        .map_err(internal)?;
    Ok(Json(msgs).into_response())
}

#[derive(Deserialize)]
pub struct SiteQuery {
    host: Option<String>,
}

pub async fn site_map(State(st): State<AppState>, caller: Caller, Query(q): Query<SiteQuery>) -> R {
    caller.require(Role::Viewer)?;
    let p = st.inner.project.clone();
    let entries = blocking(move || p.site_map(q.host.as_deref()))
        .await?
        .map_err(internal)?;
    Ok(Json(entries).into_response())
}

// ---- Scope, rules, intercept ------------------------------------------------------------------------------

pub async fn get_scope(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(st.inner.gate.scope().spec().clone()).into_response())
}

pub async fn put_scope(State(st): State<AppState>, caller: Caller, Json(spec): Json<ScopeSpec>) -> R {
    caller.require(Role::Tester)?;
    if spec.include.len() + spec.exclude.len() > 1000 {
        return Err(reject(StatusCode::BAD_REQUEST, "too many scope rules"));
    }
    let scope = Scope::compile(spec.clone()).map_err(|e| reject(StatusCode::BAD_REQUEST, &e.to_string()))?;
    st.inner
        .project
        .set_setting(SETTING_SCOPE, &spec)
        .map_err(internal)?;
    st.inner.gate.set_scope(scope);
    caller.audit(
        &st,
        "scope.update",
        &serde_json::to_string(&spec).unwrap_or_default(),
    );
    Ok(Json(spec).into_response())
}

pub async fn get_rules(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(st.inner.proxy.rules()).into_response())
}

pub async fn put_rules(State(st): State<AppState>, caller: Caller, Json(rules): Json<Vec<RuleSpec>>) -> R {
    caller.require(Role::Tester)?;
    if rules.len() > 500 {
        return Err(reject(StatusCode::BAD_REQUEST, "too many rules"));
    }
    st.inner
        .proxy
        .set_rules(rules.clone())
        .map_err(|e| reject(StatusCode::BAD_REQUEST, &e))?;
    st.inner
        .project
        .set_setting(SETTING_RULES, &rules)
        .map_err(internal)?;
    caller.audit(&st, "rules.update", &format!("{} rules", rules.len()));
    Ok(Json(rules).into_response())
}

pub async fn get_intercept(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(st.inner.proxy.intercept().settings()).into_response())
}

pub async fn put_intercept(
    State(st): State<AppState>,
    caller: Caller,
    Json(s): Json<InterceptSettings>,
) -> R {
    caller.require(Role::Tester)?;
    st.inner.proxy.intercept().set(s);
    st.inner
        .project
        .set_setting(SETTING_INTERCEPT, &s)
        .map_err(internal)?;
    Ok(Json(s).into_response())
}

pub async fn intercept_queue(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(st.inner.proxy.intercept().list()).into_response())
}

pub async fn intercept_item(State(st): State<AppState>, caller: Caller, Path(id): Path<u64>) -> R {
    caller.require(Role::Viewer)?;
    match st.inner.proxy.intercept().get(id) {
        Some(i) => Ok(Json(i).into_response()),
        None => Err(reject(StatusCode::NOT_FOUND, "no such item (already forwarded?)")),
    }
}

pub async fn intercept_decide(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<u64>,
    Json(d): Json<Decision>,
) -> R {
    caller.require(Role::Tester)?;
    if st.inner.proxy.intercept().resolve(id, d) {
        Ok(empty(StatusCode::NO_CONTENT))
    } else {
        Err(reject(StatusCode::NOT_FOUND, "no such item (already forwarded?)"))
    }
}

pub async fn intercept_forward_all(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Tester)?;
    let n = st.inner.proxy.intercept().forward_all();
    Ok(Json(serde_json::json!({ "forwarded": n })).into_response())
}

// ---- Proxy, CA, browser -----------------------------------------------------------------------------------

pub async fn proxy_info(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let c = st.inner.proxy.config();
    Ok(Json(serde_json::json!({
        "listen": c.listen,
        "http2": c.http2,
        "invisible": c.invisible,
        "verify_upstream_tls": c.verify_upstream_tls,
        "upstream": c.upstream,
        "tls_passthrough": c.tls_passthrough,
        "auth_required": c.auth.is_some(),
        "record_out_of_scope": c.record_out_of_scope,
        "tools_stopped": st.inner.gate.is_stopped(),
    }))
    .into_response())
}

#[derive(Deserialize)]
pub struct StopBody {
    stopped: bool,
}

/// The kill switch for all tool traffic.
pub async fn set_stopped(State(st): State<AppState>, caller: Caller, Json(b): Json<StopBody>) -> R {
    caller.require(Role::Tester)?;
    st.inner.gate.set_stopped(b.stopped);
    caller.audit(&st, "tools.stop", &b.stopped.to_string());
    Ok(Json(serde_json::json!({ "stopped": b.stopped })).into_response())
}

pub async fn ca_info(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(serde_json::json!({
        "fingerprint_sha256": st.inner.ca.fingerprint(),
        "spki_sha256": st.inner.ca.spki_hash(),
        "pem": st.inner.ca.cert_pem(),
    }))
    .into_response())
}

pub async fn ca_pem(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let mut r = st.inner.ca.cert_pem().to_string().into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-pem-file"),
    );
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"bosun-ca.pem\""),
    );
    Ok(r)
}

pub async fn launch_browser(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Tester)?;
    let Some(b) = st.inner.browser.as_ref() else {
        return Err(reject(
            StatusCode::FORBIDDEN,
            "launching a browser is disabled on this server (it only runs where the API listens on loopback); \
             point your own browser at the proxy instead",
        ));
    };
    match b.launch(st.inner.proxy.config().listen, &st.inner.ca.spki_hash()) {
        Ok(info) => {
            caller.audit(&st, "browser.launch", &info);
            Ok(Json(serde_json::json!({ "launched": info })).into_response())
        }
        Err(e) => Err(reject(StatusCode::SERVICE_UNAVAILABLE, &e)),
    }
}

// ---- Accounts ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct NewToken {
    name: String,
}

pub async fn list_tokens(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(st.inner.app.list_api_tokens(caller.user.id).map_err(internal)?).into_response())
}

pub async fn create_token(State(st): State<AppState>, caller: Caller, Json(b): Json<NewToken>) -> R {
    caller.require(Role::Viewer)?;
    if b.name.is_empty() || b.name.len() > 64 {
        return Err(reject(StatusCode::BAD_REQUEST, "token names are 1-64 characters"));
    }
    let token = format!("bosun_{}", random_token());
    let t = st
        .inner
        .app
        .create_api_token(&b.name, &token, caller.user.id)
        .map_err(internal)?;
    caller.audit(&st, "token.create", &b.name);
    // The token is shown once; only its hash is stored.
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "token": token, "info": t })),
    )
        .into_response())
}

pub async fn delete_token(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Viewer)?;
    if st
        .inner
        .app
        .delete_api_token(id, caller.user.id)
        .map_err(internal)?
    {
        caller.audit(&st, "token.delete", &id.to_string());
        Ok(empty(StatusCode::NO_CONTENT))
    } else {
        Err(reject(StatusCode::NOT_FOUND, "no such token"))
    }
}

pub async fn list_users(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Admin)?;
    Ok(Json(st.inner.app.list_users().map_err(internal)?).into_response())
}

#[derive(Deserialize)]
pub struct NewUser {
    username: String,
    password: String,
    role: Role,
}

pub async fn create_user(State(st): State<AppState>, caller: Caller, Json(b): Json<NewUser>) -> R {
    caller.require(Role::Admin)?;
    check_username(&b.username)
        .and_then(|_| check_password_policy(&b.password))
        .map_err(|e| reject(StatusCode::BAD_REQUEST, &e))?;
    let pw = b.password;
    let hash = blocking(move || hash_password(&pw)).await?.map_err(internal)?;
    let u = st
        .inner
        .app
        .create_user(&b.username, &hash, b.role)
        .map_err(|e| match e {
            bosun_store::StoreError::Conflict(m) => reject(StatusCode::CONFLICT, &m),
            e => internal(e),
        })?;
    caller.audit(
        &st,
        "user.create",
        &format!("{} ({})", u.username, u.role.as_str()),
    );
    Ok((StatusCode::CREATED, Json(u)).into_response())
}

pub async fn delete_user(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Admin)?;
    if id == caller.user.id {
        return Err(reject(StatusCode::BAD_REQUEST, "you cannot delete yourself"));
    }
    match st.inner.app.delete_user(id) {
        Ok(true) => {
            caller.audit(&st, "user.delete", &id.to_string());
            Ok(empty(StatusCode::NO_CONTENT))
        }
        Ok(false) => Err(reject(StatusCode::NOT_FOUND, "no such user")),
        Err(bosun_store::StoreError::Conflict(m)) => Err(reject(StatusCode::CONFLICT, &m)),
        Err(e) => Err(internal(e)),
    }
}

#[derive(Deserialize)]
pub struct AuditQuery {
    before: Option<i64>,
    limit: Option<u32>,
}

pub async fn audit_log(State(st): State<AppState>, caller: Caller, Query(q): Query<AuditQuery>) -> R {
    caller.require(Role::Admin)?;
    Ok(Json(
        st.inner
            .app
            .audit_log(q.before, q.limit.unwrap_or(200))
            .map_err(internal)?,
    )
    .into_response())
}
