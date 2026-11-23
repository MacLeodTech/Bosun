use bosun_model::{Direction, FlowId, FlowSummary};
use serde::Serialize;

use crate::intercept::InterceptSummary;

/// Events the proxy publishes for front ends (sent over the API's event stream).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProxyEvent {
    /// A flow was written to history.
    Flow {
        flow: FlowSummary,
    },
    WsMessage {
        flow_id: FlowId,
        direction: Direction,
        opcode: u8,
        len: usize,
    },
    InterceptQueued {
        item: InterceptSummary,
    },
    InterceptResolved {
        id: u64,
    },
    /// A message could not be held (queue full) and was refused.
    InterceptRefused {
        reason: String,
    },
    /// A batch of history could not be written even after a retry, and is lost.
    RecorderFailed {
        lost: u64,
        error: String,
    },
    InterceptState {
        requests: bool,
        responses: bool,
    },
}

pub type EventSender = tokio::sync::broadcast::Sender<ProxyEvent>;
