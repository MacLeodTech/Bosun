//! Issues found by the passive scanner, and the scanner's queue (the flows not yet read).

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::Project;
use crate::StoreError;

/// Issues kept in a project. Past this, new kinds of issue are dropped (counts of existing ones still grow), so
/// a hostile target cannot grow the project without bound.
pub const MAX_ISSUES: i64 = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "info" => Self::Info,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tentative => "tentative",
            Self::Firm => "firm",
            Self::Certain => "certain",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "tentative" => Self::Tentative,
            "firm" => Self::Firm,
            "certain" => Self::Certain,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IssueStatus {
    #[default]
    New,
    Confirmed,
    FalsePositive,
}

impl IssueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Confirmed => "confirmed",
            Self::FalsePositive => "false_positive",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "new" => Self::New,
            "confirmed" => Self::Confirmed,
            "false_positive" => Self::FalsePositive,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePart {
    Request,
    Response,
}

/// A highlighted byte range in the stored request or response (end exclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Evidence {
    pub part: EvidencePart,
    pub start: u64,
    pub end: u64,
}

/// What a rule found in one flow, before it is stored.
#[derive(Debug, Clone)]
pub struct NewIssue {
    pub rule: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub flow_id: i64,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub detail: String,
    pub evidence: Vec<Evidence>,
    pub remediation: String,
    pub cwe: Vec<u32>,
    pub owasp: Vec<String>,
    /// Two findings with the same fingerprint are one issue seen twice.
    pub fingerprint: String,
    pub time_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Issue {
    pub id: i64,
    pub rule: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: IssueStatus,
    /// The flow that shows the issue (the first one it was seen in); `None` once that flow is deleted.
    pub flow_id: Option<i64>,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub detail: String,
    pub evidence: Vec<Evidence>,
    pub remediation: String,
    pub cwe: Vec<u32>,
    pub owasp: Vec<String>,
    /// How many flows showed it.
    pub count: i64,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct IssueFilter {
    pub status: Option<IssueStatus>,
    pub severity: Option<Severity>,
    pub confidence: Option<Confidence>,
    pub rule: Option<String>,
    pub host: Option<String>,
    pub flow_id: Option<i64>,
    /// Text in the title, detail or path.
    pub text: Option<String>,
    pub limit: Option<u32>,
}

const COLS: &str = "id, rule, title, severity, confidence, status, flow_id, scheme, host, port, path, detail, \
                    evidence, remediation, cwe, owasp, count, first_seen_ms, last_seen_ms";

fn issue_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<Issue> {
    let bad = |i: usize, what: &str| {
        rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Text, what.into())
    };
    let text = |i: usize| r.get::<_, String>(i);
    Ok(Issue {
        id: r.get(0)?,
        rule: text(1)?,
        title: text(2)?,
        severity: Severity::parse(&text(3)?).ok_or_else(|| bad(3, "severity"))?,
        confidence: Confidence::parse(&text(4)?).ok_or_else(|| bad(4, "confidence"))?,
        status: IssueStatus::parse(&text(5)?).ok_or_else(|| bad(5, "status"))?,
        flow_id: r.get(6)?,
        scheme: text(7)?,
        host: text(8)?,
        port: r.get(9)?,
        path: text(10)?,
        detail: text(11)?,
        evidence: serde_json::from_str(&text(12)?).map_err(|_| bad(12, "evidence"))?,
        remediation: text(13)?,
        cwe: serde_json::from_str(&text(14)?).map_err(|_| bad(14, "cwe"))?,
        owasp: serde_json::from_str(&text(15)?).map_err(|_| bad(15, "owasp"))?,
        count: r.get(16)?,
        first_seen_ms: r.get(17)?,
        last_seen_ms: r.get(18)?,
    })
}

fn json<T: Serialize>(v: &T) -> Result<String, StoreError> {
    serde_json::to_string(v).map_err(StoreError::Json)
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

impl Project {
    /// The next flows the scanner has not read, oldest first.
    pub fn scan_pending(&self, limit: usize) -> Result<Vec<i64>, StoreError> {
        let conn = self.db.read()?;
        let mut stmt = conn.prepare_cached("SELECT id FROM flows WHERE scanned = 0 ORDER BY id LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// How many flows wait for the scanner.
    pub fn scan_backlog(&self) -> Result<i64, StoreError> {
        let conn = self.db.read()?;
        Ok(conn.query_row("SELECT count(*) FROM flows WHERE scanned = 0", [], |r| r.get(0))?)
    }

    /// Store what the scanner found in `flows` and mark them read, in one transaction. An issue already there
    /// (same fingerprint) only has its count and last-seen time raised; its status and evidence stay.
    pub fn scan_commit(&self, flows: &[i64], found: &[NewIssue]) -> Result<(), StoreError> {
        let mut conn = self.db.write();
        let tx = conn.transaction()?;
        {
            let mut have: i64 = tx.query_row("SELECT count(*) FROM issues", [], |r| r.get(0))?;
            let mut up = tx.prepare_cached(
                "UPDATE issues SET count = count + 1, last_seen_ms = max(last_seen_ms, ?2),
                    flow_id = coalesce(flow_id, ?3)
                 WHERE fingerprint = ?1",
            )?;
            let mut ins = tx.prepare_cached(
                "INSERT INTO issues (fingerprint, rule, title, severity, confidence, flow_id, scheme, host, port,
                    path, detail, evidence, remediation, cwe, owasp, first_seen_ms, last_seen_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16)",
            )?;
            for i in found {
                if up.execute(params![i.fingerprint, i.time_ms, i.flow_id])? > 0 {
                    continue;
                }
                if have >= MAX_ISSUES {
                    continue;
                }
                ins.execute(params![
                    i.fingerprint,
                    i.rule,
                    i.title,
                    i.severity.as_str(),
                    i.confidence.as_str(),
                    i.flow_id,
                    i.scheme,
                    i.host,
                    i.port,
                    i.path,
                    i.detail,
                    json(&i.evidence)?,
                    i.remediation,
                    json(&i.cwe)?,
                    json(&i.owasp)?,
                    i.time_ms
                ])?;
                have += 1;
            }
            let mut mark = tx.prepare_cached("UPDATE flows SET scanned = 1 WHERE id = ?1")?;
            for id in flows {
                mark.execute([id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Mark every flow unread again, so the scanner reads the whole history with the current rules. Counts start
    /// over; statuses stay.
    pub fn scan_restart(&self) -> Result<(), StoreError> {
        let mut conn = self.db.write();
        let tx = conn.transaction()?;
        tx.execute("UPDATE flows SET scanned = 0 WHERE scanned = 1", [])?;
        tx.execute("UPDATE issues SET count = 0", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Newest first (by last sighting).
    pub fn issues(&self, f: &IssueFilter) -> Result<Vec<Issue>, StoreError> {
        let mut sql = format!("SELECT {COLS} FROM issues WHERE 1 = 1");
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let mut add = |clause: &str, v: rusqlite::types::Value| {
            args.push(v);
            sql.push_str(&format!(
                " AND {}",
                clause.replace('?', &format!("?{}", args.len()))
            ));
        };
        if let Some(s) = f.status {
            add("status = ?", s.as_str().to_string().into());
        }
        if let Some(s) = f.severity {
            add("severity = ?", s.as_str().to_string().into());
        }
        if let Some(s) = f.confidence {
            add("confidence = ?", s.as_str().to_string().into());
        }
        if let Some(s) = &f.rule {
            add("rule = ?", s.clone().into());
        }
        if let Some(s) = &f.host {
            add("host = ?", s.to_ascii_lowercase().into());
        }
        if let Some(s) = f.flow_id {
            add("flow_id = ?", s.into());
        }
        if let Some(t) = f.text.as_deref().filter(|t| !t.is_empty()) {
            let pat = format!("%{}%", escape_like(t));
            add(
                "(title LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\')",
                pat.into(),
            );
        }
        let limit = f.limit.map_or(1_000, |l| l.clamp(1, 5_000));
        sql.push_str(&format!(" ORDER BY last_seen_ms DESC, id DESC LIMIT {limit}"));
        let conn = self.db.read()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args), issue_of)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn issue(&self, id: i64) -> Result<Option<Issue>, StoreError> {
        let conn = self.db.read()?;
        Ok(conn
            .query_row(
                &format!("SELECT {COLS} FROM issues WHERE id = ?1"),
                [id],
                issue_of,
            )
            .optional()?)
    }

    /// `false` when there is no such issue.
    pub fn issue_set_status(&self, id: i64, status: IssueStatus) -> Result<bool, StoreError> {
        let n = self.db.write().execute(
            "UPDATE issues SET status = ?2 WHERE id = ?1",
            params![id, status.as_str()],
        )?;
        Ok(n > 0)
    }
}
