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
    InterceptState {
        requests: bool,
        responses: bool,
    },
}

pub type EventSender = tokio::sync::broadcast::Sender<ProxyEvent>;
