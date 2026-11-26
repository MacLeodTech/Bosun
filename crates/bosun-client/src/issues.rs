//! The passive scanner's issues.

use bosun_model::FlowId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueStatus {
    #[default]
    New,
    Confirmed,
    FalsePositive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePart {
    Request,
    Response,
}

/// A highlighted byte range (end exclusive) in a flow's stored request or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub part: EvidencePart,
    pub start: u64,
    pub end: u64,
}

/// A finding of the passive scanner.
#[derive(Debug, Clone, Deserialize)]
pub struct Issue {
    pub id: i64,
    pub rule: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: IssueStatus,
    pub flow_id: Option<FlowId>,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub detail: String,
    pub evidence: Vec<Evidence>,
    pub remediation: String,
    pub cwe: Vec<u32>,
    pub owasp: Vec<String>,
    pub count: i64,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssueList {
    pub issues: Vec<Issue>,
    /// Flows the scanner has not read yet.
    pub pending: i64,
    pub rules: Vec<String>,
}

/// Filters for `Client::issues`; every field is optional.
#[derive(Debug, Clone, Default, Serialize)]
pub struct IssueQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<IssueStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<FlowId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}
