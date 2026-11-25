//! The Repeater: send a raw request by hand, once or many times, and see exactly what came back.
//!
//! Requests and responses travel as base64 because they are bytes, not text. Every send goes through the scope
//! gate (with the Repeater's out-of-scope policy) and is recorded as a flow with source `repeater`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bosun_http::h2::H2Request;
use bosun_http::ws::{Frame, to_ws_message};
use bosun_http::{Exchange, SendError, SendOptions};
use bosun_model::{Direction, FlowSource, Scheme, Target};
use bosun_scope::OutOfScopePolicy;
use bosun_store::Role;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::Caller;
use crate::security::reject;

type R = Result<Response, Response>;

/// The most requests one send may make, and the most a single-packet batch may hold (HTTP/2 servers commonly
/// allow 100 concurrent streams).
const MAX_COUNT: u32 = 100;
const MAX_SINGLE_PACKET: u32 = 50;
const MAX_REQUEST: usize = 4 << 20;
const MAX_REDIRECTS: u8 = 10;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    Http1,
    /// The request is converted to HTTP/2 (`Host` becomes `:authority`, hop-by-hop headers are dropped).
    H2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// One after another.
    #[default]
    Sequential,
    /// All at once, each on its own connection (HTTP/1.1) or its own stream of the shared connection (HTTP/2).
    Parallel,
    /// HTTP/2 only: all requests written in one go, to land in the same packet. For race conditions.
    SinglePacket,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendBody {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// The request as written, base64.
    pub request: String,
    #[serde(default)]
    pub protocol: Protocol,
    /// Rewrite `Content-Length` to match the body. Off by default: what you wrote is what is sent.
    #[serde(default)]
    pub update_content_length: bool,
    #[serde(default)]
    pub verify_tls: bool,
    /// Follow redirects (HTTP/1.1 only), recording each hop.
    #[serde(default)]
    pub follow_redirects: bool,
    /// How many times to send it (1 to 100).
    #[serde(default = "one")]
    pub count: u32,
    #[serde(default)]
    pub mode: Mode,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TlsSummary {
    pub version: String,
    pub cipher: String,
    pub alpn: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TimingsOut {
    pub dns_ms: u64,
    pub connect_ms: u64,
    pub tls_ms: Option<u64>,
    pub first_byte_ms: Option<u64>,
    pub total_ms: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SendResult {
    /// Which of the `count` sends this is (0-based).
    pub index: u32,
    /// Which redirect hop (0 is the request itself).
    pub hop: u32,
    /// The recorded flow, when something was sent.
    pub flow_id: Option<i64>,
    pub status: Option<u16>,
    /// Why there is no (or only a partial) response.
    pub error: Option<String>,
    /// The scope gate or the kill switch stopped it; nothing was sent.
    pub refused: bool,
    pub truncated: bool,
    /// The connection came from the pool or was shared.
    pub reused: bool,
    pub in_scope: Option<bool>,
    /// What was written, base64.
    pub request: String,
    /// What was read, base64.
    pub response: String,
    pub peer: Option<String>,
    pub tls: Option<TlsSummary>,
    pub timings: Option<TimingsOut>,
    /// Number of HTTP/2 frames written and read, when the exchange was HTTP/2.
    pub h2_frames: Option<[u32; 2]>,
    pub started_ms: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SendReply {
    pub results: Vec<SendResult>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RepeaterSettings {
    /// Let the Repeater send to hosts outside the scope. Starts off, and goes back off when a project is opened.
    pub allow_out_of_scope: bool,
}

fn failed(index: u32, request: &[u8], e: &SendError) -> SendResult {
    SendResult {
        index,
        hop: 0,
        flow_id: None,
        status: None,
        error: Some(e.to_string()),
        refused: matches!(e, SendError::Refused(_)),
        truncated: false,
        reused: false,
        in_scope: None,
        request: B64.encode(request),
        response: String::new(),
        peer: None,
        tls: None,
        timings: None,
        h2_frames: None,
        started_ms: None,
    }
}

fn result(st: &AppState, index: u32, hop: u32, ex: &Exchange) -> SendResult {
    let id = st.project().next_flow_id();
    st.inner.proxy.record(ex.to_new_flow(id, FlowSource::Repeater));
    SendResult {
        index,
        hop,
        flow_id: Some(id),
        status: ex.status,
        error: ex.error.clone(),
        refused: false,
        truncated: ex.truncated,
        reused: ex.reused,
        in_scope: Some(ex.in_scope),
        request: B64.encode(&ex.request),
        response: B64.encode(&ex.response),
        peer: Some(ex.peer.to_string()),
        tls: ex.tls.as_ref().map(|t| TlsSummary {
            version: t.version.clone(),
            cipher: t.cipher.clone(),
            alpn: t.alpn.clone(),
        }),
        timings: Some(TimingsOut {
            dns_ms: ex.timings.dns_ms,
            connect_ms: ex.timings.connect_ms,
            tls_ms: ex.timings.tls_ms,
            first_byte_ms: ex.timings.first_byte_ms,
            total_ms: ex.timings.total_ms,
        }),
        h2_frames: ex
            .h2
            .as_ref()
            .map(|h| [h.frames_out.len() as u32, h.frames_in.len() as u32]),
        started_ms: Some(ex.started_ms),
    }
}

pub async fn send(State(st): State<AppState>, caller: Caller, Json(b): Json<SendBody>) -> R {
    caller.require(Role::Tester)?;
    if b.count == 0 || b.count > MAX_COUNT {
        return Err(reject(StatusCode::BAD_REQUEST, "count must be 1 to 100"));
    }
    if b.mode == Mode::SinglePacket && (b.protocol != Protocol::H2 || b.count > MAX_SINGLE_PACKET) {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "single-packet needs protocol h2 and at most 50 requests",
        ));
    }
    if b.follow_redirects && b.protocol == Protocol::H2 {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "redirects are followed over HTTP/1.1 only",
        ));
    }
    if b.host.is_empty() || b.host.len() > 255 || b.port == 0 {
        return Err(reject(StatusCode::BAD_REQUEST, "that target is not valid"));
    }
    let raw = B64
        .decode(b.request.as_bytes())
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "the request is not valid base64"))?;
    if raw.is_empty() || raw.len() > MAX_REQUEST {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "the request is empty or over 4 MiB",
        ));
    }
    let target = Target::new(b.scheme, b.host.clone(), b.port);
    let opts = SendOptions {
        source: FlowSource::Repeater,
        update_content_length: b.update_content_length,
        verify_tls: b.verify_tls,
        // Sequential sends on one connection show how a server treats a connection that is reused.
        reuse: b.mode == Mode::Sequential && b.count > 1,
        ..SendOptions::default()
    };
    let eng = st.inner.repeater.clone();
    let mut results = Vec::new();
    match b.protocol {
        Protocol::Http1 => {
            let one = |i: u32| {
                let (eng, target, raw, opts) = (eng.clone(), target.clone(), raw.clone(), opts.clone());
                let follow = b.follow_redirects;
                async move {
                    let r = if follow {
                        eng.send_following(&target, &raw, &opts, MAX_REDIRECTS).await
                    } else {
                        eng.send(&target, &raw, &opts).await.map(|e| vec![e])
                    };
                    (i, r)
                }
            };
            let outcomes = if b.mode == Mode::Parallel {
                futures_util::future::join_all((0..b.count).map(one)).await
            } else {
                let mut v = Vec::new();
                for i in 0..b.count {
                    let o = one(i).await;
                    // A refusal will repeat: stop asking.
                    let stop = matches!(o.1, Err(SendError::Refused(_)));
                    v.push(o);
                    if stop {
                        break;
                    }
                }
                v
            };
            for (i, r) in outcomes {
                match r {
                    Ok(chain) => {
                        for (hop, ex) in chain.iter().enumerate() {
                            results.push(result(&st, i, hop as u32, ex));
                        }
                    }
                    Err(e) => results.push(failed(i, &raw, &e)),
                }
            }
        }
        Protocol::H2 => {
            let scheme = b.scheme.as_str();
            let req = match H2Request::from_http1(&raw, scheme) {
                Ok(r) => r,
                Err(e) => return Err(reject(StatusCode::BAD_REQUEST, &e)),
            };
            let outcomes: Vec<(u32, Result<Exchange, SendError>)> = match b.mode {
                Mode::SinglePacket => {
                    let reqs = vec![req; b.count as usize];
                    match eng.send_h2_batch(&target, &reqs, &opts).await {
                        Ok(v) => v
                            .into_iter()
                            .enumerate()
                            .map(|(i, e)| (i as u32, Ok(e)))
                            .collect(),
                        Err(e) => vec![(0, Err(e))],
                    }
                }
                Mode::Parallel => {
                    futures_util::future::join_all((0..b.count).map(|i| {
                        let (eng, target, req, opts) =
                            (eng.clone(), target.clone(), req.clone(), opts.clone());
                        async move { (i, eng.send_h2_request(&target, &req, &opts).await) }
                    }))
                    .await
                }
                Mode::Sequential => {
                    let mut v = Vec::new();
                    for i in 0..b.count {
                        let o = eng.send_h2_request(&target, &req, &opts).await;
                        let stop = matches!(o, Err(SendError::Refused(_)));
                        v.push((i, o));
                        if stop {
                            break;
                        }
                    }
                    v
                }
            };
            for (i, r) in outcomes {
                match r {
                    Ok(ex) => results.push(result(&st, i, 0, &ex)),
                    Err(e) => results.push(failed(i, &raw, &e)),
                }
            }
        }
    }
    caller
        .audit(
            &st,
            "repeater.send",
            &format!(
                "{}://{}:{} x{} {:?}",
                b.scheme.as_str(),
                b.host,
                b.port,
                b.count,
                b.mode
            ),
        )
        .await;
    Ok(Json(SendReply { results }).into_response())
}

pub async fn get_settings(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    Ok(Json(RepeaterSettings {
        allow_out_of_scope: st.inner.gate.repeater_policy() == OutOfScopePolicy::Allow,
    })
    .into_response())
}

pub async fn put_settings(State(st): State<AppState>, caller: Caller, Json(s): Json<RepeaterSettings>) -> R {
    caller.require(Role::Tester)?;
    st.inner.gate.set_repeater_policy(if s.allow_out_of_scope {
        OutOfScopePolicy::Allow
    } else {
        OutOfScopePolicy::Refuse
    });
    caller
        .audit(
            &st,
            "repeater.settings",
            &format!("allow_out_of_scope={}", s.allow_out_of_scope),
        )
        .await;
    Ok(Json(s).into_response())
}

/// The Repeater's tabs as the page keeps them. The server stores them as the page wrote them and looks only at their
/// count and shape, so the page can add a field without a server change.
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
pub struct TabsDoc {
    /// One object per tab (target, request text, options). Responses are not stored.
    pub tabs: Vec<serde_json::Value>,
    /// Id of the tab that was open.
    #[serde(default)]
    pub active: i64,
    /// The id the next new tab gets.
    #[serde(default)]
    pub next: i64,
}

const MAX_TABS: usize = 100;
/// Largest stored tab set, bytes of JSON. The request body limit is lower, so this is a second guard.
const MAX_TABS_BYTES: usize = 8 << 20;

pub async fn get_tabs(State(st): State<AppState>, caller: Caller) -> R {
    caller.require(Role::Viewer)?;
    let p = st.project();
    let doc = tokio::task::spawn_blocking(move || p.setting::<TabsDoc>(crate::SETTING_REPEATER_TABS))
        .await
        .map_err(|_| {
            reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error (see the server log)",
            )
        })?
        // A stored value that no longer parses is treated as no tabs rather than breaking the page.
        .unwrap_or(None)
        .unwrap_or_default();
    Ok(Json(doc).into_response())
}

pub async fn put_tabs(State(st): State<AppState>, caller: Caller, Json(doc): Json<TabsDoc>) -> R {
    caller.require(Role::Tester)?;
    if doc.tabs.len() > MAX_TABS {
        return Err(reject(StatusCode::BAD_REQUEST, "too many tabs"));
    }
    if doc.tabs.iter().any(|t| !t.is_object()) {
        return Err(reject(StatusCode::BAD_REQUEST, "each tab must be an object"));
    }
    if serde_json::to_vec(&doc).map_or(true, |b| b.len() > MAX_TABS_BYTES) {
        return Err(reject(StatusCode::PAYLOAD_TOO_LARGE, "the tabs are too large"));
    }
    let _settings = st.inner.projects.settings_guard().await;
    let p = st.project();
    let d = doc.clone();
    tokio::task::spawn_blocking(move || p.set_setting(crate::SETTING_REPEATER_TABS, &d))
        .await
        .map_err(|_| {
            reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error (see the server log)",
            )
        })?
        .map_err(|e| {
            tracing::error!(error = %e, "could not store the Repeater tabs");
            reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error (see the server log)",
            )
        })?;
    Ok(Json(doc).into_response())
}

// ---- WebSocket sends -------------------------------------------------------------------------------------------

const MAX_WS_FRAMES: usize = 100;
const MAX_WS_FRAME: usize = 1 << 20;
const MAX_WS_RECEIVED: usize = 200;
const MAX_WS_LISTEN_MS: u32 = 10_000;
/// Longest payload kept in the stored record of a frame.
const WS_RECORD_LIMIT: usize = 1 << 20;

fn yes() -> bool {
    true
}
fn listen_default() -> u32 {
    1500
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct WsFrameIn {
    /// 0 continuation, 1 text, 2 binary, 8 close, 9 ping, 10 pong; anything from 0 to 15 is sent as given.
    pub opcode: u8,
    #[serde(default = "yes")]
    pub fin: bool,
    /// The three reserved bits as a number from 0 to 7.
    #[serde(default)]
    pub rsv: u8,
    /// `random` (the default), `none` (send unmasked, which a compliant client never does) or four bytes as eight
    /// hex digits.
    #[serde(default)]
    pub mask: Option<String>,
    /// The payload, base64.
    #[serde(default)]
    pub payload: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct WsBody {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// The handshake, a raw HTTP/1.1 upgrade request, base64.
    pub request: String,
    /// Frames to send, in order, once the server has answered `101`.
    #[serde(default)]
    pub frames: Vec<WsFrameIn>,
    /// How long to keep listening after the last frame, in milliseconds (at most 10000).
    #[serde(default = "listen_default")]
    pub listen_ms: u32,
    #[serde(default)]
    pub verify_tls: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WsFrameOut {
    pub direction: Direction,
    pub fin: bool,
    pub rsv: u8,
    pub opcode: u8,
    pub masked: bool,
    /// The payload, unmasked, base64.
    pub payload: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WsReply {
    /// The handshake as a recorded flow; the frames are its messages.
    pub flow_id: Option<i64>,
    pub status: Option<u16>,
    /// Why there is no open connection or why listening stopped early.
    pub error: Option<String>,
    /// The scope gate or the kill switch stopped it; nothing was sent.
    pub refused: bool,
    pub in_scope: Option<bool>,
    /// The handshake request and the server's answer, base64.
    pub request: String,
    pub response: String,
    /// Frames sent and received, in the order they happened (sent ones first, then what came back).
    pub frames: Vec<WsFrameOut>,
    /// The server sent a close frame.
    pub closed_by_server: bool,
}

fn parse_mask(m: &Option<String>) -> Result<Option<[u8; 4]>, String> {
    match m.as_deref() {
        None | Some("random") => Ok(Frame::binary(Vec::new()).mask),
        Some("none") => Ok(None),
        Some(h) if h.len() == 8 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
            let mut k = [0u8; 4];
            for (i, b) in k.iter_mut().enumerate() {
                *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|_| "bad mask".to_string())?;
            }
            Ok(Some(k))
        }
        _ => Err("mask must be random, none, or eight hex digits".into()),
    }
}

fn ws_out(direction: Direction, f: &Frame) -> WsFrameOut {
    WsFrameOut {
        direction,
        fin: f.fin,
        rsv: f.rsv,
        opcode: f.opcode,
        masked: f.mask.is_some(),
        payload: B64.encode(&f.payload),
    }
}

fn ws_empty(request: &[u8], error: Option<String>, refused: bool) -> WsReply {
    WsReply {
        flow_id: None,
        status: None,
        error,
        refused,
        in_scope: None,
        request: B64.encode(request),
        response: String::new(),
        frames: Vec::new(),
        closed_by_server: false,
    }
}

pub async fn ws_send(State(st): State<AppState>, caller: Caller, Json(b): Json<WsBody>) -> R {
    caller.require(Role::Tester)?;
    if b.host.is_empty() || b.host.len() > 255 || b.port == 0 {
        return Err(reject(StatusCode::BAD_REQUEST, "that target is not valid"));
    }
    if b.frames.len() > MAX_WS_FRAMES || b.listen_ms > MAX_WS_LISTEN_MS {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "at most 100 frames, and listen for at most 10000 ms",
        ));
    }
    let raw = B64
        .decode(b.request.as_bytes())
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "the handshake is not valid base64"))?;
    if raw.is_empty() || raw.len() > MAX_REQUEST {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "the handshake is empty or over 4 MiB",
        ));
    }
    let mut frames = Vec::with_capacity(b.frames.len());
    for f in &b.frames {
        if f.opcode > 15 || f.rsv > 7 {
            return Err(reject(
                StatusCode::BAD_REQUEST,
                "opcode is 0 to 15 and rsv is 0 to 7",
            ));
        }
        let payload = B64
            .decode(f.payload.as_bytes())
            .map_err(|_| reject(StatusCode::BAD_REQUEST, "a frame payload is not valid base64"))?;
        if payload.len() > MAX_WS_FRAME {
            return Err(reject(StatusCode::BAD_REQUEST, "a frame payload is over 1 MiB"));
        }
        let mask = parse_mask(&f.mask).map_err(|e| reject(StatusCode::BAD_REQUEST, &e))?;
        frames.push(Frame {
            fin: f.fin,
            rsv: f.rsv,
            opcode: f.opcode,
            mask,
            payload,
        });
    }
    let target = Target::new(b.scheme, b.host.clone(), b.port);
    let opts = SendOptions {
        source: FlowSource::Repeater,
        verify_tls: b.verify_tls,
        ..SendOptions::default()
    };
    let eng = st.inner.repeater.clone();
    let reply = match eng.connect_ws(&target, &raw, &opts).await {
        Err(SendError::NotUpgraded(ex)) => {
            // Not an upgrade: still an exchange worth recording and showing.
            let id = st.project().next_flow_id();
            st.inner.proxy.record(ex.to_new_flow(id, FlowSource::Repeater));
            WsReply {
                flow_id: Some(id),
                status: ex.status,
                error: Some("the server did not switch protocols".into()),
                refused: false,
                in_scope: Some(ex.in_scope),
                request: B64.encode(&ex.request),
                response: B64.encode(&ex.response),
                frames: Vec::new(),
                closed_by_server: false,
            }
        }
        Err(e) => ws_empty(&raw, Some(e.to_string()), matches!(e, SendError::Refused(_))),
        Ok(mut ws) => {
            let id = st.project().next_flow_id();
            let hs = ws.handshake().clone();
            st.inner.proxy.record(hs.to_new_flow(id, FlowSource::Repeater));
            let mut out = Vec::new();
            let mut error = None;
            for f in &frames {
                if let Err(e) = ws.send(f).await {
                    error = Some(e.to_string());
                    break;
                }
                st.inner
                    .proxy
                    .record_ws(to_ws_message(id, Direction::ClientToServer, f, WS_RECORD_LIMIT));
                out.push(ws_out(Direction::ClientToServer, f));
            }
            let end = std::time::Instant::now() + std::time::Duration::from_millis(u64::from(b.listen_ms));
            let mut closed = false;
            let mut received = 0;
            while error.is_none() && received < MAX_WS_RECEIVED {
                let left = end.saturating_duration_since(std::time::Instant::now());
                match ws.recv(left).await {
                    Ok(Some(f)) => {
                        received += 1;
                        st.inner.proxy.record_ws(to_ws_message(
                            id,
                            Direction::ServerToClient,
                            &f,
                            WS_RECORD_LIMIT,
                        ));
                        out.push(ws_out(Direction::ServerToClient, &f));
                        if f.opcode == 0x8 {
                            closed = true;
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        error = Some(e.to_string());
                        break;
                    }
                }
            }
            if !closed && error.is_none() {
                // A clean goodbye, recorded like the rest.
                let bye = Frame::close(1000, "");
                if ws.send(&bye).await.is_ok() {
                    st.inner.proxy.record_ws(to_ws_message(
                        id,
                        Direction::ClientToServer,
                        &bye,
                        WS_RECORD_LIMIT,
                    ));
                    out.push(ws_out(Direction::ClientToServer, &bye));
                }
            }
            ws.shutdown().await;
            WsReply {
                flow_id: Some(id),
                status: hs.status,
                error,
                refused: false,
                in_scope: Some(hs.in_scope),
                request: B64.encode(&hs.request),
                response: B64.encode(&hs.response),
                frames: out,
                closed_by_server: closed,
            }
        }
    };
    caller
        .audit(
            &st,
            "repeater.ws",
            &format!(
                "{}://{}:{} {} frames",
                b.scheme.as_str(),
                b.host,
                b.port,
                frames.len()
            ),
        )
        .await;
    Ok(Json(reply).into_response())
}
