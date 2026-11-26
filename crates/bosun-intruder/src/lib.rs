//! The Intruder engine: take a request with marked positions, fill them with payloads, and send every combination
//! through the raw request engine ([`bosun_http::Engine`]) and so through the scope gate.
//!
//! - [`Template`] parses the request: `§value§` marks a position and `value` is what is sent when the position is
//!   not being attacked.
//! - [`PayloadSet`] is a source (a list, numbers, a brute-force alphabet, null payloads, case changes) with
//!   processing rules (prefix, suffix, encode or hash, regex replace, skip).
//! - [`Plan`] combines a template and sets by attack type (sniper, battering ram, pitchfork, cluster bomb) and can
//!   build the n-th request without building the others, so a large attack costs no memory.
//! - [`run`] sends the plan with a concurrency, a delay and retries, always inside the gate's own rate limit and the
//!   shared memory budget, and stops at once when asked.

mod payload;
mod plan;
mod run;
mod template;

pub use payload::{CompiledSet, NumberBase, PayloadSet, PayloadSource, Processing};
pub use plan::{AttackType, Job, Plan};
pub use run::{
    Attack, Finish, GrepExtract, GrepMatch, Greps, Options, Progress, Row, Sink, Stop, Summary, run,
};
pub use template::Template;

/// The most requests one attack may make.
pub const MAX_REQUESTS: u64 = 1_000_000;
/// The most items in one payload list.
pub const MAX_ITEMS: usize = 200_000;
/// The most positions in a request.
pub const MAX_POSITIONS: usize = 20;
/// The largest request template, bytes.
pub const MAX_TEMPLATE: usize = 1 << 20;
/// The largest payload after processing, bytes.
pub const MAX_PAYLOAD: usize = 64 * 1024;

/// Why an attack cannot be built. The message is safe to show.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("{0}")]
    Invalid(String),
}

pub(crate) fn invalid<T>(msg: impl Into<String>) -> Result<T, PlanError> {
    Err(PlanError::Invalid(msg.into()))
}
