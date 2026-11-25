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
use bosun_http::{Exchange, SendError, SendOptions};
use bosun_model::{FlowSource, Scheme, Target};
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
