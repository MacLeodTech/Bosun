//! Turning a hit into a stored issue.

use bosun_model::FlowDetail;
use bosun_store::{Confidence, Evidence, NewIssue, Severity};

pub struct Spec<'a> {
    pub rule: &'a str,
    pub title: &'a str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub remediation: &'a str,
    pub cwe: &'a [u32],
    pub owasp: &'a [String],
}

pub fn origin(flow: &FlowDetail) -> String {
    let s = &flow.summary;
    format!(
        "{}://{}:{}",
        s.scheme.as_str(),
        s.host.to_ascii_lowercase(),
        s.port
    )
}

pub fn base_path(flow: &FlowDetail) -> &str {
    let p = &flow.summary.path;
    p.split(['?', '#']).next().unwrap_or(p)
}

/// `key` makes the fingerprint: the same weakness at the same origin and key is one issue with a count.
pub fn make(
    flow: &FlowDetail,
    spec: &Spec<'_>,
    key: &str,
    detail: String,
    evidence: Vec<Evidence>,
    now: i64,
) -> NewIssue {
    let s = &flow.summary;
    NewIssue {
        rule: spec.rule.into(),
        title: spec.title.into(),
        severity: spec.severity,
        confidence: spec.confidence,
        flow_id: s.id,
        scheme: s.scheme.as_str().into(),
        host: s.host.to_ascii_lowercase(),
        port: s.port,
        path: base_path(flow).chars().take(512).collect(),
        detail,
        evidence,
        remediation: spec.remediation.into(),
        cwe: spec.cwe.to_vec(),
        owasp: spec.owasp.to_vec(),
        fingerprint: format!("{}|{}|{key}", spec.rule, origin(flow)),
        time_ms: now,
    }
}
