//! The Decoder and the Comparer. Pure computation on the bytes in the request: nothing is fetched, stored or
//! sent anywhere, so these need only the viewer role. Inputs and outputs are bounded (see the constants) and the
//! work runs off the async threads.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bosun_codec::{DiffLevel, DiffResult, Op};
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
    let reply = tokio::task::spawn_blocking(move || {
        let (outs, err) = bosun_codec::apply_chain(&ops, &input, MAX_INPUT);
        let pairs: Vec<(Op, Vec<u8>)> = ops.iter().copied().zip(outs).collect();
        DecodeReply {
            steps: steps_out(pairs),
            error: err.map(|(step, e)| StepError {
                step,
                message: e.to_string(),
            }),
        }
    })
    .await
    .map_err(|_| reject(StatusCode::INTERNAL_SERVER_ERROR, "the decoder failed"))?;
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
