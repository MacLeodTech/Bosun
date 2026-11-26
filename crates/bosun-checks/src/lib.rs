//! `bosun-checks`: the check language, the Nuclei importer and the passive checks.
//!
//! - [`lang`] is the YAML check language: request templates, matchers, extractors and OAST hooks, versioned and
//!   validated. A check is data, so it can come from a file, an import or a person without being trusted.
//! - [`nuclei`] converts a compatible subset of Nuclei templates into checks.
//! - [`passive`] and the YAML files in `builtin/` are the checks the passive scanner (`bosun-scan`) runs on recorded
//!   flows. Nothing here sends a request: active checks are sent by the scan engine, through the scope gate.

pub mod head;
mod issue;
pub mod lang;
pub mod nuclei;
pub mod passive;

pub use lang::{Check, CheckError, Compiled, Interaction};
pub use passive::{all_ids, scan_flow, scan_flow_with};
