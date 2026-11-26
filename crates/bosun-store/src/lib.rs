//! Storage for Bosun: project files ([`Project`]) and the install-wide account database ([`AppDb`]).
//!
//! Both are SQLite. Callers are async; every method here blocks, so call them from `spawn_blocking` (the proxy
//! batches writes on its own thread).

pub mod app;
pub mod codec;
pub mod migrate;
pub(crate) mod pool;
pub mod project;
pub mod query;

pub use app::{ApiToken, AppDb, AuditEntry, Role, Session, SessionInfo, TokenScope, TotpRow, User};
pub use project::checks::{MAX_CHECKS, StoredCheck};
pub use project::intruder::{MAX_ATTACKS, NewAttack, StoredAttack, StoredRow};
pub use project::issues::{
    Confidence, Evidence, EvidencePart, Issue, IssueFilter, IssueStatus, MAX_ISSUES, NewIssue, Severity,
};
pub use project::{
    FlowFilter, FlowMeta, FlowSort, HostRequest, MAX_ORGANIZER_NOTE, Message, NewFlow, NewWsMessage,
    OrganizerItem, OrganizerStatus, PartInfo, Project, ProjectLock, SiteMapEntry, Which, import_foreign,
    settle,
};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("compression error: {0}")]
    Compress(std::io::Error),
    #[error("JSON error: {0}")]
    Json(serde_json::Error),
    #[error("I/O error on {0}: {1}")]
    Io(String, std::io::Error),
    #[error("this file was written by a newer version of Bosun (schema {0})")]
    NewerSchema(i64),
    #[error("refusing to open this file: {0}")]
    Untrusted(String),
    #[error("schema migration failed, the file was left as it was: {0}")]
    Migration(String),
    #[error("{0}")]
    Locked(String),
    #[error("{0}")]
    Conflict(String),
}
