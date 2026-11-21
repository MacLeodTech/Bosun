//! Storage for Bosun: project files ([`Project`]) and the install-wide account database ([`AppDb`]).
//!
//! Both are SQLite. Callers are async; every method here blocks, so call them from `spawn_blocking` (the proxy
//! batches writes on its own thread).

pub mod app;
pub mod codec;
pub mod project;

pub use app::{ApiToken, AppDb, AuditEntry, Role, Session, User};
pub use project::{FlowFilter, NewFlow, NewWsMessage, Project, SiteMapEntry};

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
    #[error("{0}")]
    Conflict(String),
}
