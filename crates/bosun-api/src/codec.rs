//! The Decoder and the Comparer. Pure computation on the bytes in the request: nothing is fetched, stored or
//! sent anywhere, so these need only the viewer role. Inputs and outputs are bounded (see the constants) and the
//! work runs off the async threads.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bosun_codec::{DiffLevel, DiffResult, Op, Schema};
use bosun_store::Role;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Caller;
use crate::security::reject;

type R = Result<Response, Response>;

/// The largest input the Decoder takes, and the largest output of any step.
const MAX_INPUT: usize = 4 << 20;
/// The largest input of either side of a diff.
const MAX_DIFF: usize = 1 << 20;
/// The longest chain.
const MAX_STEPS: usize = 16;
/// How much of an intermediate step's output is returned (the final output is returned whole).
const PREVIEW: usize = 64 << 10;

fn decode_input(s: &str, max: usize) -> Result<Vec<u8>, Response> {
    // The decoded size is at most 3/4 of the text, so refuse before allocating for anything far too big.
    if s.len() / 4 * 3 > max + 3 {
        return Err(reject(StatusCode::PAYLOAD_TOO_LARGE, "the input is too large"));
    }
    let v = B64
        .decode(s)
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "the input is not valid base64"))?;
    if v.len() > max {
        return Err(reject(StatusCode::PAYLOAD_TOO_LARGE, "the input is too large"));
    }
    Ok(v)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DecodeBody {
    /// The input, base64.
    pub input: String,
    /// The steps to run, in order.
    pub ops: Vec<Op>,
    /// A `.proto` schema (up to 256 KiB) for the protobuf and gRPC steps, so they show field names and types.
    #[serde(default)]
    pub schema: Option<String>,
    /// The message the schema describes (its full name, or a short one that is unique).
    #[serde(default)]
    pub message: Option<String>,
    /// Instead of `message`: a gRPC call's path (`/package.Service/Method`), which names the request and response
    /// messages in the schema.
    #[serde(default)]
    pub rpc: Option<String>,
    /// With `rpc`: use the call's response message (default: its request).
    #[serde(default)]
    pub response: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StepOut {
    pub op: Op,
    /// The step's full output size in bytes.
    pub size: usize,
    /// The output, base64: whole for the last step, up to 64 KiB for the others.
    pub output: String,
    /// `output` is cut short.
    pub truncated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StepError {
    /// Which step failed (0-based).
    pub step: usize,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DecodeReply {
    /// One entry per step that ran.
    pub steps: Vec<StepOut>,
    /// Set when a step failed; the steps before it are still returned.
    pub error: Option<StepError>,
}

fn steps_out(outs: Vec<(Op, Vec<u8>)>) -> Vec<StepOut> {
    let last = outs.len().saturating_sub(1);
    outs.into_iter()
        .enumerate()
        .map(|(i, (op, o))| {
            let cut = if i == last { o.len() } else { o.len().min(PREVIEW) };
            StepOut {
                op,
                size: o.len(),
                output: B64.encode(&o[..cut]),
                truncated: cut < o.len(),
            }
        })
        .collect()
}

pub async fn decode(caller: Caller, Json(b): Json<DecodeBody>) -> R {
    caller.require(Role::Viewer)?;
    if b.ops.len() > MAX_STEPS {
        return Err(reject(StatusCode::BAD_REQUEST, "too many steps (the most is 16)"));
    }
    let input = decode_input(&b.input, MAX_INPUT)?;
    let ops = b.ops;
    // Reading the schema is bounded work, but it is still done off the async threads.
    let (schema, message, rpc, response) = (b.schema, b.message, b.rpc, b.response);
    let reply = tokio::task::spawn_blocking(move || {
        let schema = match schema.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(src) => Some(Schema::parse(src).map_err(|e| format!("the schema: {e}"))?),
            None => None,
        };
        let typed = match (&schema, message.as_deref().filter(|m| !m.trim().is_empty()), rpc.as_deref()) {
            (None, ..) => None,
            (Some(s), Some(m), _) => Some(s.typed(m).ok_or_else(|| format!("the schema has no message `{m}`"))?),
            // A call the schema does not describe is decoded without names.
            (Some(s), None, Some(path)) => s.rpc(path).map(|(req, resp)| if response { resp } else { req }),
            (Some(_), None, None) => None,
        };
        let (outs, err) = bosun_codec::apply_chain_with(&ops, &input, MAX_INPUT, typed);
        let pairs: Vec<(Op, Vec<u8>)> = ops.iter().copied().zip(outs).collect();
        Ok::<_, String>(DecodeReply {
            steps: steps_out(pairs),
            error: err.map(|(step, e)| StepError {
                step,
                message: e.to_string(),
            }),
        })
    })
    .await
    .map_err(|_| reject(StatusCode::INTERNAL_SERVER_ERROR, "the decoder failed"))?
    .map_err(|m| reject(StatusCode::BAD_REQUEST, &m))?;
    Ok(Json(reply).into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SmartBody {
    /// The input, base64.
    pub input: String,
}

pub async fn smart(caller: Caller, Json(b): Json<SmartBody>) -> R {
    caller.require(Role::Viewer)?;
    let input = decode_input(&b.input, MAX_INPUT)?;
    let steps = tokio::task::spawn_blocking(move || bosun_codec::smart_decode(&input, MAX_INPUT, MAX_STEPS))
        .await
        .map_err(|_| reject(StatusCode::INTERNAL_SERVER_ERROR, "the decoder failed"))?;
    Ok(Json(DecodeReply {
        steps: steps_out(steps),
        error: None,
    })
    .into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DiffBody {
    /// The left side, base64 (up to 1 MiB).
    pub a: String,
    /// The right side, base64 (up to 1 MiB).
    pub b: String,
    pub level: DiffLevel,
}

pub async fn compare(caller: Caller, Json(body): Json<DiffBody>) -> R {
    caller.require(Role::Viewer)?;
    let (a, b) = (decode_input(&body.a, MAX_DIFF)?, decode_input(&body.b, MAX_DIFF)?);
    let level = body.level;
    let r: DiffResult = tokio::task::spawn_blocking(move || bosun_codec::diff(&a, &b, level))
        .await
        .map_err(|_| reject(StatusCode::INTERNAL_SERVER_ERROR, "the comparison failed"))?;
    Ok(Json(r).into_response())
}
