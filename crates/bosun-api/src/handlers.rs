//! API handlers. Every handler takes a [`Caller`] (so it cannot be reached without authentication) and checks
//! the role it needs before doing anything.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::io::Read as _;

use bosun_model::{FlowId, RawResponse};
use bosun_proxy::{Decision, InterceptSettings, RuleSpec};
use bosun_scope::{Scope, ScopeSpec};
use bosun_store::codec;
use bosun_store::{FlowFilter, Role, TokenScope};
use serde::{Deserialize, Serialize};

use crate::auth::{Caller, check_password_policy, check_username, hash_password, random_token};
use crate::security::{empty, reject};
use crate::{AppState, SETTING_INTERCEPT, SETTING_RULES, SETTING_SAVED_FILTERS, SETTING_SCOPE};

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

/// Store a project setting without blocking an async worker.
async fn save_setting<T: Serialize + Send + 'static>(
    st: &AppState,
    key: &'static str,
    value: T,
) -> Result<(), Response> {
    let p = st.project();
    blocking(move || p.set_setting(key, &value))
        .await?
        .map_err(internal)
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
    /// A history query (see `docs/query-language.md`), combined with the fields above by `and`.
    q: Option<String>,
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
    let query = match q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(text) => {
            let parsed = bosun_store::query::parse(text);
            if let Some(e) = parsed.errors.first() {
                return Err(reject(StatusCode::BAD_REQUEST, &format!("query: {}", e.message)));
            }
            parsed.expr
        }
        None => None,
    };
    let filter = FlowFilter {
        query,
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
    let p = st.project();
    let flows = blocking(move || p.list_flows(&filter))
        .await?
        .map_err(|e| match e {
            // Only the time limit is a Conflict here: say so rather than "internal error".
            bosun_store::StoreError::Conflict(m) => reject(StatusCode::BAD_REQUEST, &m),
            e => internal(e),
        })?;
    Ok(Json(flows).into_response())
}

#[derive(Debug, Deserialize, Default)]
pub struct QueryCheckParams {
    q: Option<String>,
}

/// What a history query means: each recognised term with its place in the text, and every mistake. Nothing is
/// run. A front end uses this for chips and messages while the person types.
#[derive(Serialize, utoipa::ToSchema)]
pub struct QueryCheck {
    pub terms: Vec<bosun_store::query::TermSpan>,
    pub errors: Vec<bosun_store::query::QueryError>,
}

pub async fn check_flow_query(caller: Caller, Query(p): Query<QueryCheckParams>) -> R {
    caller.require(Role::Viewer)?;
    let parsed = bosun_store::query::parse(p.q.as_deref().unwrap_or(""));
    Ok(Json(QueryCheck {
        terms: parsed.terms,
        errors: parsed.errors,
    })
    .into_response())
}

/// A history query kept under a name, for the whole project.
#[derive(Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SavedFilter {
    pub name: String,
    pub query: String,
}

const MAX_SAVED_FILTERS: usize = 50;
const MAX_FILTER_NAME: usize = 60;

pub async fn get_saved_filters(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let p = st.project();
    let list: Option<Vec<SavedFilter>> = blocking(move || p.setting(SETTING_SAVED_FILTERS))
        .await?
        .map_err(internal)?;
    Ok(Json(list.unwrap_or_default()).into_response())
}

/// Replace the saved filters. Each query must be valid, so a saved filter always runs.
pub async fn put_saved_filters(
    State(st): State<AppState>,
    caller: Caller,
    Json(list): Json<Vec<SavedFilter>>,
) -> R {
    caller.require(Role::Tester)?;
    if list.len() > MAX_SAVED_FILTERS {
        return Err(reject(StatusCode::BAD_REQUEST, "too many saved filters"));
    }
    let mut seen = std::collections::HashSet::new();
    for f in &list {
        let name = f.name.trim();
        if name.is_empty() || name.chars().count() > MAX_FILTER_NAME || name.chars().any(char::is_control) {
            return Err(reject(
                StatusCode::BAD_REQUEST,
                "a filter name is 1 to 60 characters, without control characters",
            ));
        }
        if !seen.insert(name.to_string()) {
            return Err(reject(StatusCode::BAD_REQUEST, "two filters have the same name"));
        }
        if let Some(e) = bosun_store::query::parse(&f.query).errors.first() {
            return Err(reject(
                StatusCode::BAD_REQUEST,
                &format!("filter \"{name}\": {}", e.message),
            ));
        }
    }
    let list: Vec<SavedFilter> = list
        .into_iter()
        .map(|f| SavedFilter {
            name: f.name.trim().to_string(),
            query: f.query,
        })
        .collect();
    let _settings = st.inner.projects.settings_guard().await;
    save_setting(&st, SETTING_SAVED_FILTERS, list.clone()).await?;
    Ok(Json(list).into_response())
}

/// A flow without its bodies: summary, each message's header block and size. The bodies come from the
/// `/flows/{id}/{part}/body` endpoints, a piece at a time.
#[derive(Serialize, utoipa::ToSchema)]
pub struct FlowOverview {
    #[serde(flatten)]
    meta: bosun_store::FlowMeta,
    /// The response's `Content-Encoding`, when it has one. `?decoded=1` on the body endpoint undoes it.
    response_encoding: Option<String>,
}

pub async fn get_flow(State(st): State<AppState>, caller: Caller, Path(id): Path<FlowId>) -> R {
    caller.require(Role::Viewer)?;
    let p = st.project();
    let meta = blocking(move || p.flow_meta(id)).await?.map_err(internal)?;
    let Some(meta) = meta else {
        return Err(reject(StatusCode::NOT_FOUND, "no such flow"));
    };
    let response_encoding = meta
        .response
        .as_ref()
        .and_then(|r| head_header(&r.head, "content-encoding"));
    Ok(Json(FlowOverview {
        meta,
        response_encoding,
    })
    .into_response())
}

/// One header's value from a message head.
fn head_header(head: &[u8], name: &str) -> Option<String> {
    RawResponse::parse(head)
        .ok()
        .and_then(|r| {
            r.header(name)
                .map(|v| String::from_utf8_lossy(v).trim().to_string())
        })
        .filter(|v| !v.is_empty())
}

/// The most a single range request may ask to be buffered when the length of the result is not known up front
/// (a decoded body).
const MAX_BUFFERED_RANGE: u64 = 8 * 1024 * 1024;
/// How much of a decoded body is ever served: what the decoder is allowed to produce.
const DECODED_LIMIT: u64 = codec::DEFAULT_DECODE_LIMIT as u64;
const CHUNK: usize = 64 * 1024;

#[derive(Deserialize, Default)]
pub struct BodyQuery {
    #[serde(default)]
    decoded: Option<String>,
}

/// What the reader thread found out before it started streaming.
enum BodyPlan {
    Missing,
    Unsupported(String),
    Unsatisfiable {
        total: Option<u64>,
    },
    Send {
        partial: bool,
        start: u64,
        len: Option<u64>,
        total: Option<u64>,
    },
}

/// `bytes=a-b`, `bytes=a-` or `bytes=-n` (one range only).
#[derive(Clone, Copy)]
enum ByteRange {
    From(u64, Option<u64>),
    Last(u64),
}

fn parse_range(h: &str) -> Result<ByteRange, ()> {
    let spec = h.trim().strip_prefix("bytes=").ok_or(())?;
    if spec.contains(',') {
        return Err(());
    }
    let (a, b) = spec.split_once('-').ok_or(())?;
    match (a.trim(), b.trim()) {
        ("", n) => Ok(ByteRange::Last(n.parse().map_err(|_| ())?)),
        (a, "") => Ok(ByteRange::From(a.parse().map_err(|_| ())?, None)),
        (a, b) => {
            let (a, b): (u64, u64) = (a.parse().map_err(|_| ())?, b.parse().map_err(|_| ())?);
            if b < a {
                return Err(());
            }
            Ok(ByteRange::From(a, Some(b)))
        }
    }
}

/// The raw bytes of one stored message's body, with `Range` support. `?decoded=1` undoes the response's
/// `Content-Encoding` (capped at 32 MiB). The body is read from the database in pieces: memory use is a few
/// chunks, whatever the size, and for a range, the range.
pub async fn flow_body(
    State(st): State<AppState>,
    caller: Caller,
    Path((id, part)): Path<(FlowId, String)>,
    Query(q): Query<BodyQuery>,
    headers: axum::http::HeaderMap,
) -> R {
    caller.require(Role::Viewer)?;
    let which = match part.as_str() {
        "request" => bosun_store::Which::Request,
        "response" => bosun_store::Which::Response,
        "original-request" => bosun_store::Which::OriginalRequest,
        "original-response" => bosun_store::Which::OriginalResponse,
        _ => return Err(reject(StatusCode::NOT_FOUND, "no such part")),
    };
    let decoded = q.decoded.as_deref().is_some_and(|d| d == "1" || d == "true");
    if decoded
        && !matches!(
            which,
            bosun_store::Which::Response | bosun_store::Which::OriginalResponse
        )
    {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "only a response body has a content-encoding to undo",
        ));
    }
    let range = match headers.get(header::RANGE).map(|v| v.to_str().map_err(|_| ())) {
        None => None,
        Some(v) => Some(v.and_then(parse_range).map_err(|()| {
            reject(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "only a single byte range is supported",
            )
        })?),
    };

    let (plan_tx, plan_rx) = tokio::sync::oneshot::channel::<BodyPlan>();
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(2);
    let p = st.project();
    tokio::task::spawn_blocking(move || {
        let sent = tx.clone();
        let out = p.with_message(id, which, |m| {
            let Some(m) = m else {
                let _ = plan_tx.send(BodyPlan::Missing);
                return Ok(());
            };
            let head = m.head()?;
            let head_len = head.len() as u64;
            let body_len = m.size - head_len;
            let encoding = if decoded {
                head_header(&head, "content-encoding")
            } else {
                None
            };
            let mut reader: Box<dyn std::io::Read + '_> = Box::new(m.body(head_len, 0, None)?);
            let mut total = Some(body_len);
            let mut cap = body_len;
            if let Some(ce) = &encoding {
                match codec::stream_decoder(Some(ce), reader) {
                    Ok(Some(d)) => {
                        reader = Box::new(d);
                        total = None;
                        cap = DECODED_LIMIT;
                    }
                    Ok(None) => unreachable!("the encoding is not empty"),
                    Err(codec::StreamError::Unsupported(c)) => {
                        let _ = plan_tx.send(BodyPlan::Unsupported(c));
                        return Ok(());
                    }
                }
            }
            // Work out which bytes to send.
            let (start, len, partial) = match (range, total) {
                (None, _) => (0, None, false),
                (Some(ByteRange::From(a, b)), t) => {
                    if t.is_some_and(|t| a >= t) {
                        let _ = plan_tx.send(BodyPlan::Unsatisfiable { total: t });
                        return Ok(());
                    }
                    let want = b.map(|b| b - a + 1);
                    (a, want, true)
                }
                (Some(ByteRange::Last(n)), Some(t)) if n > 0 => (t.saturating_sub(n), Some(n.min(t)), true),
                (Some(ByteRange::Last(_)), _) => {
                    let _ = plan_tx.send(BodyPlan::Unsatisfiable { total });
                    return Ok(());
                }
            };
            // `None` length: the rest, up to the cap.
            let len = len.map(|l| l.min(cap.saturating_sub(start)));
            std::io::copy(&mut (&mut reader).take(start), &mut std::io::sink())
                .map_err(bosun_store::StoreError::Compress)?;
            if total.is_none() && partial {
                // The length of a decoded range is not known until it has been read, so read it (bounded).
                let want = len.unwrap_or(MAX_BUFFERED_RANGE).min(MAX_BUFFERED_RANGE);
                let mut buf = Vec::new();
                (&mut reader)
                    .take(want)
                    .read_to_end(&mut buf)
                    .map_err(bosun_store::StoreError::Compress)?;
                // A short read means the body ended: now the total is known.
                let known = ((buf.len() as u64) < want).then(|| start + buf.len() as u64);
                let n = buf.len() as u64;
                if n == 0 {
                    let _ = plan_tx.send(BodyPlan::Unsatisfiable { total: known });
                    return Ok(());
                }
                let _ = plan_tx.send(BodyPlan::Send {
                    partial: true,
                    start,
                    len: Some(n),
                    total: known,
                });
                let _ = tx.blocking_send(Ok(bytes::Bytes::from(buf)));
                return Ok(());
            }
            let send_len = len.unwrap_or_else(|| cap.saturating_sub(start));
            if plan_tx
                .send(BodyPlan::Send {
                    partial,
                    start,
                    len: total.map(|_| send_len),
                    total,
                })
                .is_err()
            {
                return Ok(());
            }
            let mut left = send_len;
            let mut buf = vec![0u8; CHUNK];
            while left > 0 {
                let want = usize::try_from(left).unwrap_or(CHUNK).min(CHUNK);
                match reader.read(&mut buf[..want]) {
                    Ok(0) => break,
                    Ok(n) => {
                        left -= n as u64;
                        if tx
                            .blocking_send(Ok(bytes::Bytes::copy_from_slice(&buf[..n])))
                            .is_err()
                        {
                            return Ok(()); // the client went away
                        }
                    }
                    Err(e) => {
                        let _ = tx.blocking_send(Err(e));
                        break;
                    }
                }
            }
            Ok(())
        });
        if let Err(e) = out {
            tracing::error!(error = %e, flow = id, "reading a body failed");
            let _ = sent.blocking_send(Err(std::io::Error::other("the stored body could not be read")));
        }
    });

    let plan = plan_rx.await.map_err(|_| internal("the body reader stopped"))?;
    let mut resp = match plan {
        BodyPlan::Missing => return Err(reject(StatusCode::NOT_FOUND, "no such flow or message")),
        BodyPlan::Unsupported(c) => {
            return Err(reject(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &format!("unsupported content-encoding {c}"),
            ));
        }
        BodyPlan::Unsatisfiable { total } => {
            let mut r = reject(StatusCode::RANGE_NOT_SATISFIABLE, "range outside the body");
            let v = format!("bytes */{}", total.map_or("*".to_string(), |t| t.to_string()));
            r.headers_mut().insert(header::CONTENT_RANGE, hv(&v));
            return Err(r);
        }
        BodyPlan::Send {
            partial,
            start,
            len,
            total,
        } => {
            let stream =
                futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|c| (c, rx)) });
            let mut r = Response::new(axum::body::Body::from_stream(stream));
            if partial {
                *r.status_mut() = StatusCode::PARTIAL_CONTENT;
                let range = match len {
                    Some(l) => format!(
                        "bytes {start}-{}/{}",
                        start + l - 1,
                        total.map_or("*".to_string(), |t| t.to_string())
                    ),
                    None => format!(
                        "bytes {start}-/{}",
                        total.map_or("*".to_string(), |t| t.to_string())
                    ),
                };
                r.headers_mut().insert(header::CONTENT_RANGE, hv(&range));
            }
            if let Some(l) = len {
                r.headers_mut().insert(header::CONTENT_LENGTH, hv(&l.to_string()));
            }
            r
        }
    };
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    // Target content is never shown by the browser itself, whatever it claims to be.
    h.insert(
        header::CONTENT_DISPOSITION,
        hv(&format!("attachment; filename=\"flow-{id}-{part}-body.bin\"")),
    );
    Ok(resp)
}

fn hv(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static(""))
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
    let p = st.project();
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
    let p = st.project();
    let n = blocking(move || p.delete_flows(&b.ids))
        .await?
        .map_err(internal)?;
    caller
        .audit(&st, "flows.delete", &format!("{n} of {n_ids} requested"))
        .await;
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
    let p = st.project();
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
    let p = st.project();
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
    let _settings = st.inner.projects.settings_guard().await;
    if spec.include.len() + spec.exclude.len() > 1000 {
        return Err(reject(StatusCode::BAD_REQUEST, "too many scope rules"));
    }
    let scope = Scope::compile(spec.clone()).map_err(|e| reject(StatusCode::BAD_REQUEST, &e.to_string()))?;
    save_setting(&st, SETTING_SCOPE, spec.clone()).await?;
    st.inner.gate.set_scope(scope);
    caller
        .audit(
            &st,
            "scope.update",
            &serde_json::to_string(&spec).unwrap_or_default(),
        )
        .await;
    Ok(Json(spec).into_response())
}

pub async fn get_rules(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(st.inner.proxy.rules()).into_response())
}

pub async fn put_rules(State(st): State<AppState>, caller: Caller, Json(rules): Json<Vec<RuleSpec>>) -> R {
    caller.require(Role::Tester)?;
    let _settings = st.inner.projects.settings_guard().await;
    if rules.len() > 500 {
        return Err(reject(StatusCode::BAD_REQUEST, "too many rules"));
    }
    st.inner
        .proxy
        .set_rules(rules.clone())
        .map_err(|e| reject(StatusCode::BAD_REQUEST, &e))?;
    save_setting(&st, SETTING_RULES, rules.clone()).await?;
    caller
        .audit(&st, "rules.update", &format!("{} rules", rules.len()))
        .await;
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
    let _settings = st.inner.projects.settings_guard().await;
    st.inner.proxy.intercept().set(s);
    caller
        .audit(
            &st,
            "intercept.settings",
            &format!(
                "requests={} responses={} in_scope_only={} timeout={}",
                s.requests,
                s.responses,
                s.in_scope_only,
                s.timeout_secs.map_or("none".into(), |t| format!("{t}s"))
            ),
        )
        .await;
    save_setting(&st, SETTING_INTERCEPT, s).await?;
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
    // Only changes are audited: a plain forward is what happens anyway.
    let what = match &d {
        Decision::Drop => Some(("intercept.drop", format!("item {id}"))),
        Decision::Forward { raw: Some(r) } => Some((
            "intercept.forward_edited",
            format!("item {id}, {} bytes", r.len()),
        )),
        Decision::Forward { raw: None } => None,
    };
    if st.inner.proxy.intercept().resolve(id, d) {
        if let Some((action, detail)) = what {
            caller.audit(&st, action, &detail).await;
        }
        Ok(empty(StatusCode::NO_CONTENT))
    } else {
        Err(reject(StatusCode::NOT_FOUND, "no such item (already forwarded?)"))
    }
}

pub async fn intercept_forward_all(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Tester)?;
    let n = st.inner.proxy.intercept().forward_all();
    caller
        .audit(&st, "intercept.forward_all", &format!("{n} items"))
        .await;
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
        "stats": st.inner.proxy.stats(),
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
    caller.audit(&st, "tools.stop", &b.stopped.to_string()).await;
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
            caller.audit(&st, "browser.launch", &info).await;
            Ok(Json(serde_json::json!({ "launched": info })).into_response())
        }
        Err(e) => Err(reject(StatusCode::SERVICE_UNAVAILABLE, &e)),
    }
}

// ---- Accounts ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct NewToken {
    name: String,
    /// Days until the token stops working (none: never; at most 3650).
    expires_days: Option<u32>,
    /// `read` tokens can only make GET requests. Defaults to `full`.
    #[serde(default)]
    scope: Option<TokenScope>,
}

pub async fn list_tokens(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let uid = caller.user.id;
    let tokens = st
        .with_app(move |a| a.list_api_tokens(uid))
        .await?
        .map_err(internal)?;
    Ok(Json(tokens).into_response())
}

pub async fn create_token(State(st): State<AppState>, caller: Caller, Json(b): Json<NewToken>) -> R {
    caller.require(Role::Viewer)?;
    if b.name.is_empty() || b.name.len() > 64 {
        return Err(reject(StatusCode::BAD_REQUEST, "token names are 1-64 characters"));
    }
    if b.expires_days.is_some_and(|d| d == 0 || d > 3650) {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "expires_days must be between 1 and 3650",
        ));
    }
    let expires = b
        .expires_days
        .map(|d| bosun_model::now_ms() + i64::from(d) * 86_400_000);
    let token = format!("bosun_{}", random_token());
    let (name, tok, uid, scope) = (
        b.name.clone(),
        token.clone(),
        caller.user.id,
        b.scope.unwrap_or_default(),
    );
    let t = st
        .with_app(move |a| a.create_api_token(&name, &tok, uid, scope, expires))
        .await?
        .map_err(internal)?;
    caller
        .audit(
            &st,
            "token.create",
            &format!(
                "{} ({}, {})",
                b.name,
                b.scope.unwrap_or_default().as_str(),
                b.expires_days.map_or("no expiry".into(), |d| format!("{d} days"))
            ),
        )
        .await;
    // The token is shown once; only its hash is stored.
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "token": token, "info": t })),
    )
        .into_response())
}

pub async fn delete_token(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Viewer)?;
    let uid = caller.user.id;
    if st
        .with_app(move |a| a.delete_api_token(id, uid))
        .await?
        .map_err(internal)?
    {
        caller.audit(&st, "token.delete", &id.to_string()).await;
        Ok(empty(StatusCode::NO_CONTENT))
    } else {
        Err(reject(StatusCode::NOT_FOUND, "no such token"))
    }
}

/// Your own sessions and tokens need the viewer role; anyone else's need admin.
fn own_or_admin(caller: &Caller, user_id: i64) -> Result<(), Response> {
    caller.require(if caller.user.id == user_id {
        Role::Viewer
    } else {
        Role::Admin
    })
}

#[derive(Deserialize)]
pub struct RoleBody {
    role: Role,
}

pub async fn set_user_role(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<i64>,
    Json(b): Json<RoleBody>,
) -> R {
    caller.require(Role::Admin)?;
    let role = b.role;
    let changed = st
        .with_app(move |a| {
            let r = a.set_role(id, role);
            // The new role applies at once: the user signs in again (their tokens keep their owner's role).
            if matches!(r, Ok(true)) {
                let _ = a.revoke_sessions(id);
            }
            r
        })
        .await?;
    match changed {
        Ok(true) => {
            caller
                .audit(&st, "user.role", &format!("user {id} -> {}", b.role.as_str()))
                .await;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        Ok(false) => Err(reject(StatusCode::NOT_FOUND, "no such user")),
        Err(bosun_store::StoreError::Conflict(m)) => Err(reject(StatusCode::CONFLICT, &m)),
        Err(e) => Err(internal(e)),
    }
}

pub async fn list_user_sessions(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    own_or_admin(&caller, id)?;
    let sessions = st
        .with_app(move |a| a.list_sessions(id))
        .await?
        .map_err(internal)?;
    Ok(Json(sessions).into_response())
}

pub async fn revoke_user_sessions(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    own_or_admin(&caller, id)?;
    let n = st
        .with_app(move |a| a.revoke_sessions(id))
        .await?
        .map_err(internal)?;
    caller
        .audit(&st, "session.revoke_all", &format!("user {id}, {n} sessions"))
        .await;
    Ok(Json(serde_json::json!({ "revoked": n })).into_response())
}

pub async fn revoke_user_session(
    State(st): State<AppState>,
    caller: Caller,
    Path((id, sid)): Path<(i64, String)>,
) -> R {
    own_or_admin(&caller, id)?;
    let sid_owned = sid.clone();
    if st
        .with_app(move |a| a.revoke_session(id, &sid_owned))
        .await?
        .map_err(internal)?
    {
        caller
            .audit(&st, "session.revoke", &format!("user {id}, session {sid}"))
            .await;
        Ok(empty(StatusCode::NO_CONTENT))
    } else {
        Err(reject(StatusCode::NOT_FOUND, "no such session"))
    }
}

pub async fn list_user_tokens(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    own_or_admin(&caller, id)?;
    let tokens = st
        .with_app(move |a| a.list_api_tokens(id))
        .await?
        .map_err(internal)?;
    Ok(Json(tokens).into_response())
}

pub async fn revoke_user_token(
    State(st): State<AppState>,
    caller: Caller,
    Path((id, tid)): Path<(i64, i64)>,
) -> R {
    own_or_admin(&caller, id)?;
    if st
        .with_app(move |a| a.delete_api_token(tid, id))
        .await?
        .map_err(internal)?
    {
        caller
            .audit(&st, "token.revoke", &format!("user {id}, token {tid}"))
            .await;
        Ok(empty(StatusCode::NO_CONTENT))
    } else {
        Err(reject(StatusCode::NOT_FOUND, "no such token"))
    }
}

pub async fn list_users(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Admin)?;
    let users = st.with_app(|a| a.list_users()).await?.map_err(internal)?;
    Ok(Json(users).into_response())
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
    let (name, role) = (b.username.clone(), b.role);
    let u = st
        .with_app(move |a| a.create_user(&name, &hash, role))
        .await?
        .map_err(|e| match e {
            bosun_store::StoreError::Conflict(m) => reject(StatusCode::CONFLICT, &m),
            e => internal(e),
        })?;
    caller
        .audit(
            &st,
            "user.create",
            &format!("{} ({})", u.username, u.role.as_str()),
        )
        .await;
    Ok((StatusCode::CREATED, Json(u)).into_response())
}

pub async fn delete_user(State(st): State<AppState>, caller: Caller, Path(id): Path<i64>) -> R {
    caller.require(Role::Admin)?;
    if id == caller.user.id {
        return Err(reject(StatusCode::BAD_REQUEST, "you cannot delete yourself"));
    }
    match st.with_app(move |a| a.delete_user(id)).await? {
        Ok(true) => {
            caller.audit(&st, "user.delete", &id.to_string()).await;
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
    let (before, limit) = (q.before, q.limit.unwrap_or(200));
    let entries = st
        .with_app(move |a| a.audit_log(before, limit))
        .await?
        .map_err(internal)?;
    Ok(Json(entries).into_response())
}
