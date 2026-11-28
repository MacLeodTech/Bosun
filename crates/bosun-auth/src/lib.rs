//! Authentication and authorisation testing.
//!
//! - [`matrix`]: replay each recorded request as every account and compare what comes back with what its owner got.
//!   A request that another account (or nobody) can make as successfully as the owner is an access-control finding
//!   (IDOR, a missing check, a missing login).
//!
//! - [`session`]: a login macro that signs in, keeps the session's headers and signs in again when it expires.
//!
//! Every request goes through [`bosun_http::Engine`], so through the scope gate.

pub mod matrix;
pub mod session;

pub use matrix::{
    Cell, Finding, FindingKind, Identity, MAX_IDENTITIES, MAX_PROBES, Options, Probe, Row, Verdict, run,
    with_identity,
};
pub use session::{Capture, Expiry, LoginMacro, Session, SessionError};
