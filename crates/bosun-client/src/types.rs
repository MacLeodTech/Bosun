//! The shapes the API sends and receives. They mirror `docs/openapi.json`; the tests run each one against a real
//! engine, so a change on the server that this crate does not follow fails there.

use bosun_model::{b64, b64_opt};
use serde::{Deserialize, Serialize};

pub use bosun_model::{Direction, FlowId, FlowSource, FlowSummary, Scheme, WsMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Tester,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: Role,
    pub created_ms: i64,
}

/// The signed-in user. `csrf` is set for cookie sessions (the client sends it for you).
#[derive(Debug, Clone, Deserialize)]
pub struct Me {
    pub user: User,
    pub csrf: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    pub name: String,
    pub version: String,
    pub setup_required: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SsoButton {
    pub name: String,
    pub login: String,
    pub edge: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SsoInfo {
    pub sso: Option<SsoButton>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenScope {
    Read,
    #[default]
    Full,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    pub user_id: i64,
    pub created_ms: i64,
    pub last_used_ms: Option<i64>,
    pub expires_ms: Option<i64>,
    pub scope: TokenScope,
}

/// A token as created: the secret is shown once.
#[derive(Debug, Clone, Deserialize)]
pub struct NewToken {
    pub token: String,
    pub info: ApiToken,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub user_id: i64,
    pub created_ms: i64,
    pub expires_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub time_ms: i64,
    pub username: Option<String>,
    pub action: String,
    pub detail: String,
    pub remote: Option<String>,
}

/// Filters for `GET /flows`. Everything is optional.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FlowQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Comma-separated, such as `GET,POST`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub methods: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_min: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_max: Option<u16>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub in_scope_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Comma-separated extensions to hide, such as `png,css`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hide_ext: Option<String>,
    /// Flows older than this id (for paging).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<FlowId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<FlowId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// `id` (the default), `time`, `method`, `host`, `path`, `status`, `size`, `duration` or `mime`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,
    /// Oldest or smallest first.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub asc: bool,
    /// Rows to skip, for paging a list sorted by something other than the id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// A history query, such as `host:example.com status:4xx -ext:png login`. A mistake in it is an error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
}

/// One stored message: its header block and sizes. The body comes from [`Client::flow_body`](crate::Client::flow_body).
#[derive(Debug, Clone, Deserialize)]
pub struct PartInfo {
    #[serde(with = "b64")]
    pub head: Vec<u8>,
    pub total_len: u64,
    pub body_len: u64,
}

/// A flow without bodies (`GET /flows/{id}`).
#[derive(Debug, Clone, Deserialize)]
pub struct FlowMeta {
    #[serde(flatten)]
    pub summary: FlowSummary,
    pub request: PartInfo,
    pub original_request: Option<PartInfo>,
    pub response: Option<PartInfo>,
    pub original_response: Option<PartInfo>,
    pub response_truncated: bool,
    /// The response's `Content-Encoding`, if it has one.
    pub response_encoding: Option<String>,
}

/// Which stored message of a flow to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Request,
    Response,
    OriginalRequest,
    OriginalResponse,
}

impl Part {
    pub(crate) fn path(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::OriginalRequest => "original-request",
            Self::OriginalResponse => "original-response",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SiteMapEntry {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub methods: Vec<String>,
    pub last_status: Option<u16>,
    pub count: i64,
    pub in_scope: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ScopeRule {
    #[serde(default)]
    pub scheme: Option<Scheme>,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub allow_private: bool,
}

impl ScopeRule {
    /// A rule for one host name (any scheme, port and path).
    pub fn host(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ScopeSpec {
    #[serde(default)]
    pub include: Vec<ScopeRule>,
    #[serde(default)]
    pub exclude: Vec<ScopeRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTarget {
    RequestFirstLine,
    RequestHeader,
    RequestBody,
    ResponseFirstLine,
    ResponseHeader,
    ResponseBody,
}

/// A match-and-replace rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchRule {
    #[serde(default = "yes")]
    pub enabled: bool,
    pub target: RuleTarget,
    #[serde(rename = "match", default)]
    pub pattern: String,
    #[serde(default)]
    pub replace: String,
    #[serde(default)]
    pub regex: bool,
    #[serde(default)]
    pub comment: String,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptSettings {
    pub requests: bool,
    pub responses: bool,
    pub in_scope_only: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Request,
    Response,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InterceptSummary {
    pub id: u64,
    pub flow_id: FlowId,
    pub phase: Phase,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub queued_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InterceptItem {
    #[serde(flatten)]
    pub summary: InterceptSummary,
    /// The held message as HTTP/1.1-style text.
    #[serde(with = "b64")]
    pub raw: Vec<u8>,
}

/// What to do with a held message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Decision {
    /// Forward it, with these bytes instead if given.
    Forward {
        #[serde(skip_serializing_if = "Option::is_none", with = "b64_opt")]
        raw: Option<Vec<u8>>,
    },
    Drop,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyStats {
    pub memory_budget: usize,
    pub memory_used: usize,
    pub memory_refused: u64,
    pub connections_refused: u64,
    pub recorder_bodies_dropped: u64,
    pub recorder_records_dropped: u64,
    pub recorder_write_failures: u64,
    pub recorder_records_lost: u64,
    pub intercept_refused: u64,
    pub intercept_queued_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyInfo {
    pub listen: String,
    pub http2: bool,
    pub invisible: bool,
    pub verify_upstream_tls: bool,
    pub upstream: Option<String>,
    pub tls_passthrough: Vec<String>,
    pub auth_required: bool,
    pub record_out_of_scope: bool,
    pub tools_stopped: bool,
    pub stats: ProxyStats,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaInfo {
    pub fingerprint_sha256: String,
    pub spki_sha256: String,
    pub pem: String,
}

/// One message on the event stream, without its sequence number (see [`crate::Sequenced`]).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// First message of a connection: this engine run's name and the latest sequence number.
    Hello {
        epoch: String,
        seq: u64,
    },
    /// Events were missed that cannot be replayed: fetch the data again.
    Reload,
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
    InterceptRefused {
        reason: String,
    },
    RecorderFailed {
        lost: u64,
        error: String,
    },
    InterceptState {
        requests: bool,
        responses: bool,
    },
    /// Another project is open: everything held from the old one is stale.
    ProjectSwitched {
        name: Option<String>,
        temporary: bool,
    },
}

/// The project that is open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentProject {
    /// None for the temporary project.
    pub name: Option<String>,
    pub temporary: bool,
    pub external: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub name: String,
    pub size_bytes: u64,
    pub modified_ms: i64,
    pub current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectList {
    pub current: CurrentProject,
    pub projects: Vec<ProjectInfo>,
    pub recent: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupInfo {
    pub path: String,
    pub size_bytes: u64,
}

/// A term of a history query that the server recognised.
#[derive(Debug, Clone, Deserialize)]
pub struct QueryTerm {
    pub key: String,
    pub label: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QueryProblem {
    pub message: String,
    pub start: usize,
    pub end: usize,
}

/// The result of `check_flow_query`.
#[derive(Debug, Clone, Deserialize)]
pub struct QueryCheck {
    pub terms: Vec<QueryTerm>,
    pub errors: Vec<QueryProblem>,
}

/// A history query kept under a name for the whole project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedFilter {
    pub name: String,
    pub query: String,
}

/// Where a request in the Organizer stands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizerStatus {
    #[default]
    Todo,
    InProgress,
    Done,
    Ignored,
}

/// A request kept in the Organizer.
#[derive(Debug, Clone, Deserialize)]
pub struct OrganizerItem {
    pub id: i64,
    pub flow_id: FlowId,
    pub status: OrganizerStatus,
    pub note: String,
    pub added_ms: i64,
    pub updated_ms: i64,
    pub flow: FlowSummary,
}

/// What a response holds that is worth a look (WP-45).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Comment,
    InlineScript,
    ScriptSrc,
    Link,
    FormAction,
    Resource,
    Url,
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub value: String,
    pub offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamWhere {
    Query,
    Form,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    #[serde(rename = "where")]
    pub location: ParamWhere,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngageReport {
    pub findings: Vec<Finding>,
    pub params: Vec<Param>,
    pub truncated: bool,
    pub undecoded: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StatusCount {
    pub status: u16,
    pub count: u32,
}

/// One endpoint of a host: a method and a path with its ids replaced.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EndpointStat {
    pub method: String,
    pub path: String,
    pub count: u32,
    pub statuses: Vec<StatusCount>,
    pub params: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ParamStat {
    pub name: String,
    #[serde(rename = "where")]
    pub location: ParamWhere,
    pub count: u32,
    pub endpoints: u32,
    pub values: Vec<String>,
    pub more_values: bool,
}

/// The endpoints and parameters of one host across the history (WP-45).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HostAnalysis {
    pub host: String,
    pub port: Option<u16>,
    pub capped: bool,
    pub requests: u32,
    pub endpoints: Vec<EndpointStat>,
    pub params: Vec<ParamStat>,
    pub truncated: bool,
}
