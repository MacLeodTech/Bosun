//! The Intruder's attacks and results.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::Project;
use crate::StoreError;

/// Attacks kept in a project; creating one over the limit is refused until some are deleted.
pub const MAX_ATTACKS: i64 = 200;

/// An attack to start.
#[derive(Debug, Clone)]
pub struct NewAttack {
    pub name: String,
    pub created_ms: i64,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub kind: String,
    /// The request with its position markers.
    pub request: Vec<u8>,
    /// The whole configuration as the API took it (JSON), so the attack can be reopened and repeated.
    pub config: String,
    pub total: u64,
}

/// An attack as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAttack {
    pub id: i64,
    pub name: String,
    pub created_ms: i64,
    pub finished_ms: Option<i64>,
    /// `running`, `completed`, `stopped`, `failed` or `interrupted`.
    pub state: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub kind: String,
    pub request: Vec<u8>,
    pub config: String,
    pub total: u64,
    pub done: u64,
    pub skipped: u64,
    pub errors: u64,
    pub error: Option<String>,
}

/// One result as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRow {
    pub index: u64,
    pub position: Option<u32>,
    pub payloads: Vec<String>,
    pub status: Option<u16>,
    pub length: u64,
    pub time_ms: u64,
    pub flow_id: Option<i64>,
    pub error: Option<String>,
    pub matches: Vec<bool>,
    pub extracts: Vec<Option<String>>,
    pub attempts: u32,
}

const ATTACK_COLS: &str = "id, name, created_ms, finished_ms, state, scheme, host, port, kind, request, config, \
                           total, done, skipped, errors, error";

fn attack_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAttack> {
    Ok(StoredAttack {
        id: r.get(0)?,
        name: r.get(1)?,
        created_ms: r.get(2)?,
        finished_ms: r.get(3)?,
        state: r.get(4)?,
        scheme: r.get(5)?,
        host: r.get(6)?,
        port: r.get(7)?,
        kind: r.get(8)?,
        request: r.get(9)?,
        config: r.get(10)?,
        total: r.get::<_, i64>(11)? as u64,
        done: r.get::<_, i64>(12)? as u64,
        skipped: r.get::<_, i64>(13)? as u64,
        errors: r.get::<_, i64>(14)? as u64,
        error: r.get(15)?,
    })
}

impl Project {
    /// Add a running attack. Returns its id, or a conflict when the project already holds too many.
    pub fn intruder_create(&self, a: &NewAttack) -> Result<i64, StoreError> {
        let mut conn = self.db.write();
        let tx = conn.transaction()?;
        let n: i64 = tx.query_row("SELECT count(*) FROM intruder_attacks", [], |r| r.get(0))?;
        if n >= MAX_ATTACKS {
            return Err(StoreError::Conflict(format!(
                "the project holds {MAX_ATTACKS} attacks: delete some first"
            )));
        }
        tx.execute(
            "INSERT INTO intruder_attacks (name, created_ms, state, scheme, host, port, kind, request, config, total)
             VALUES (?1, ?2, 'running', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                a.name,
                a.created_ms,
                a.scheme,
                a.host,
                a.port,
                a.kind,
                a.request,
                a.config,
                a.total as i64
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Store a batch of results. A result for an index that is already there is replaced.
    pub fn intruder_add_rows(&self, attack_id: i64, rows: &[StoredRow]) -> Result<(), StoreError> {
        let mut conn = self.db.write();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO intruder_results
                 (attack_id, idx, position, payloads, status, length, time_ms, flow_id, error, matches, extracts, attempts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?;
            for r in rows {
                stmt.execute(params![
                    attack_id,
                    r.index as i64,
                    r.position,
                    json(&r.payloads)?,
                    r.status,
                    r.length as i64,
                    r.time_ms as i64,
                    r.flow_id,
                    r.error,
                    json(&r.matches)?,
                    json(&r.extracts)?,
                    r.attempts
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Update the counters of a running attack.
    pub fn intruder_progress(&self, id: i64, done: u64, skipped: u64, errors: u64) -> Result<(), StoreError> {
        self.db.write().execute(
            "UPDATE intruder_attacks SET done = ?2, skipped = ?3, errors = ?4 WHERE id = ?1",
            params![id, done as i64, skipped as i64, errors as i64],
        )?;
        Ok(())
    }

    /// Mark an attack as over.
    #[allow(clippy::too_many_arguments)]
    pub fn intruder_finish(
        &self,
        id: i64,
        state: &str,
        error: Option<&str>,
        now_ms: i64,
        done: u64,
        skipped: u64,
        errors: u64,
    ) -> Result<(), StoreError> {
        self.db.write().execute(
            "UPDATE intruder_attacks SET state = ?2, error = ?3, finished_ms = ?4, done = ?5, skipped = ?6, errors = ?7
             WHERE id = ?1",
            params![id, state, error, now_ms, done as i64, skipped as i64, errors as i64],
        )?;
        Ok(())
    }

    /// Newest first.
    pub fn intruder_attacks(&self) -> Result<Vec<StoredAttack>, StoreError> {
        let conn = self.db.read()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {ATTACK_COLS} FROM intruder_attacks ORDER BY id DESC LIMIT {MAX_ATTACKS}"
        ))?;
        let rows = stmt.query_map([], attack_of)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn intruder_attack(&self, id: i64) -> Result<Option<StoredAttack>, StoreError> {
        let conn = self.db.read()?;
        Ok(conn
            .query_row(
                &format!("SELECT {ATTACK_COLS} FROM intruder_attacks WHERE id = ?1"),
                [id],
                attack_of,
            )
            .optional()?)
    }

    /// Results in order of request number, `limit` from `offset`.
    pub fn intruder_rows(
        &self,
        attack_id: i64,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<StoredRow>, StoreError> {
        let conn = self.db.read()?;
        let mut stmt = conn.prepare_cached(
            "SELECT idx, position, payloads, status, length, time_ms, flow_id, error, matches, extracts, attempts
             FROM intruder_results WHERE attack_id = ?1 ORDER BY idx LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(params![attack_id, limit as i64, offset as i64], |r| {
            let text = |i: usize| r.get::<_, String>(i);
            let bad = |e: serde_json::Error| {
                rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
            };
            Ok(StoredRow {
                index: r.get::<_, i64>(0)? as u64,
                position: r.get(1)?,
                payloads: serde_json::from_str(&text(2)?).map_err(bad)?,
                status: r.get(3)?,
                length: r.get::<_, i64>(4)? as u64,
                time_ms: r.get::<_, i64>(5)? as u64,
                flow_id: r.get(6)?,
                error: r.get(7)?,
                matches: serde_json::from_str(&text(8)?).map_err(bad)?,
                extracts: serde_json::from_str(&text(9)?).map_err(bad)?,
                attempts: r.get(10)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Delete an attack and its results. False if there is no such attack.
    pub fn intruder_delete(&self, id: i64) -> Result<bool, StoreError> {
        let mut conn = self.db.write();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM intruder_results WHERE attack_id = ?1", [id])?;
        let n = tx.execute("DELETE FROM intruder_attacks WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(n > 0)
    }
}

fn json<T: Serialize>(v: &T) -> Result<String, StoreError> {
    serde_json::to_string(v).map_err(StoreError::Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_attack() -> NewAttack {
        NewAttack {
            name: "a".into(),
            created_ms: 1,
            scheme: "http".into(),
            host: "h".into(),
            port: 80,
            kind: "sniper".into(),
            request: b"GET /\xc2\xa7a\xc2\xa7 HTTP/1.1\r\n\r\n".to_vec(),
            config: "{}".into(),
            total: 2,
        }
    }

    fn row(i: u64) -> StoredRow {
        StoredRow {
            index: i,
            position: Some(0),
            payloads: vec![format!("p{i}")],
            status: Some(200),
            length: 10,
            time_ms: 3,
            flow_id: Some(i as i64 + 1),
            error: None,
            matches: vec![true, false],
            extracts: vec![Some("x".into()), None],
            attempts: 1,
        }
    }

    #[test]
    fn attacks_and_results_round_trip_and_delete() {
        let p = Project::open_in_memory().unwrap();
        let id = p.intruder_create(&new_attack()).unwrap();
        p.intruder_add_rows(id, &[row(1), row(0)]).unwrap();
        assert_eq!(p.intruder_rows(id, 0, 10).unwrap(), [row(0), row(1)]);
        assert_eq!(p.intruder_rows(id, 1, 10).unwrap(), [row(1)]);
        p.intruder_finish(id, "completed", None, 9, 2, 0, 0).unwrap();
        let a = p.intruder_attack(id).unwrap().unwrap();
        assert_eq!(
            (a.state.as_str(), a.done, a.finished_ms),
            ("completed", 2, Some(9))
        );
        assert_eq!(p.intruder_attacks().unwrap().len(), 1);
        assert!(p.intruder_delete(id).unwrap());
        assert!(!p.intruder_delete(id).unwrap());
        assert!(p.intruder_rows(id, 0, 10).unwrap().is_empty());
        assert!(p.intruder_attack(id).unwrap().is_none());
    }

    #[test]
    fn a_running_attack_is_interrupted_when_the_project_is_opened_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.bosun");
        let id = {
            let p = Project::open(&path).unwrap();
            p.intruder_create(&new_attack()).unwrap()
        };
        let p = Project::open(&path).unwrap();
        assert_eq!(p.intruder_attack(id).unwrap().unwrap().state, "interrupted");
    }
}
