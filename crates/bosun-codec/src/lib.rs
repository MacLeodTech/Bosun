//! The Decoder and the Comparer.
//!
//! Pure functions on bytes: no I/O, no network. Every step is bounded by an output limit, so a
//! decompression bomb or an absurd diff cannot use more memory than the caller allows.

mod diff;
pub mod engage;
pub mod graphql;
mod ops;
pub mod proto;
pub mod schema;

pub use diff::{DiffKind, DiffLevel, DiffOp, DiffResult, diff};
pub use ops::{Op, apply, apply_chain, apply_chain_with, apply_with, smart_decode};
pub use schema::{Schema, Typed};

/// Why a step failed. The message is safe to show to the user.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("the input is not valid {0}")]
    Invalid(&'static str),
    #[error("the output would be larger than the {0}-byte limit")]
    TooLarge(usize),
}
