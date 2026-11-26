//! Custom passive checks (YAML text) kept in the project. The store keeps the text and flags only; the API
//! validates it with the check loader before it gets here, and the scanner compiles it again when it loads it.

use rusqlite::{OptionalExtension, params};
use serde::Serialize;

use super::Project;
use crate::StoreError;

/// Custom checks kept in a project.
pub const MAX_CHECKS: i64 = 200;

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct StoredCheck {
    pub id: i64,
    /// The `id` inside the YAML; it is the issue rule name.
    pub check_id: String,
    pub yaml: String,
    pub enabled: bool,
    pub created_ms: i64,
    pub updated_ms: i64,
}

const COLS: &str = "id, check_id, yaml, enabled, created_ms, updated_ms";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredCheck> {
    Ok(StoredCheck {
        id: r.get(0)?,
        check_id: r.get(1)?,
        yaml: r.get(2)?,
        enabled: r.get::<_, i64>(3)? != 0,
        created_ms: r.get(4)?,
        updated_ms: r.get(5)?,
    })
}

fn unique(e: rusqlite::Error, check_id: &str) -> StoreError {
    match &e {
        rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
            StoreError::Conflict(format!("a check with the id `{check_id}` already exists"))
        }
        _ => e.into(),
    }
}

const NEXT_REV: &str = "(SELECT coalesce(max(rev), 0) + 1 FROM checks)";

impl Project {
    pub fn checks(&self) -> Result<Vec<StoredCheck>, StoreError> {
        let conn = self.db.read()?;
        let mut stmt = conn.prepare(&format!("SELECT {COLS} FROM checks ORDER BY id"))?;
        let rows = stmt.query_map([], row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn check(&self, id: i64) -> Result<Option<StoredCheck>, StoreError> {
        let conn = self.db.read()?;
        Ok(conn
            .query_row(&format!("SELECT {COLS} FROM checks WHERE id = ?1"), [id], row)
            .optional()?)
    }

    /// Changes whenever a check is added, edited, switched or deleted; the scanner reloads when it moves.
    pub fn checks_stamp(&self) -> Result<(i64, i64, i64), StoreError> {
        let conn = self.db.read()?;
        Ok(conn.query_row(
            "SELECT count(*), coalesce(max(rev), 0), coalesce(max(id), 0) FROM checks",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?)
    }

    /// The enabled checks' text, oldest first.
    pub fn checks_enabled(&self) -> Result<Vec<(String, String)>, StoreError> {
        let conn = self.db.read()?;
        let mut stmt = conn.prepare("SELECT check_id, yaml FROM checks WHERE enabled = 1 ORDER BY id")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Add a check; the new row's id. `Conflict` when the check id is taken or the project holds [`MAX_CHECKS`].
    pub fn check_add(&self, check_id: &str, yaml: &str, now_ms: i64) -> Result<i64, StoreError> {
        let mut conn = self.db.write();
        let tx = conn.transaction()?;
        let n: i64 = tx.query_row("SELECT count(*) FROM checks", [], |r| r.get(0))?;
        if n >= MAX_CHECKS {
            return Err(StoreError::Conflict(format!(
                "a project holds at most {MAX_CHECKS} custom checks"
            )));
        }
        tx.execute(
            &format!(
                "INSERT INTO checks (check_id, yaml, enabled, rev, created_ms, updated_ms)
                 VALUES (?1, ?2, 1, {NEXT_REV}, ?3, ?3)"
            ),
            params![check_id, yaml, now_ms],
        )
        .map_err(|e| unique(e, check_id))?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Replace a check's text. False when there is no such check.
    pub fn check_update(&self, id: i64, check_id: &str, yaml: &str, now_ms: i64) -> Result<bool, StoreError> {
        let conn = self.db.write();
        let n = conn
            .execute(
                &format!(
                    "UPDATE checks SET check_id = ?2, yaml = ?3, updated_ms = ?4, rev = {NEXT_REV} WHERE id = ?1"
                ),
                params![id, check_id, yaml, now_ms],
            )
            .map_err(|e| unique(e, check_id))?;
        Ok(n > 0)
    }

    pub fn check_set_enabled(&self, id: i64, enabled: bool, now_ms: i64) -> Result<bool, StoreError> {
        let conn = self.db.write();
        let n = conn.execute(
            &format!("UPDATE checks SET enabled = ?2, updated_ms = ?3, rev = {NEXT_REV} WHERE id = ?1"),
            params![id, enabled, now_ms],
        )?;
        Ok(n > 0)
    }

    pub fn check_delete(&self, id: i64) -> Result<bool, StoreError> {
        let conn = self.db.write();
        Ok(conn.execute("DELETE FROM checks WHERE id = ?1", [id])? > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_are_kept_listed_switched_and_deleted() {
        let p = Project::open_in_memory().unwrap();
        let s0 = p.checks_stamp().unwrap();
        let a = p.check_add("a", "yaml-a", 1).unwrap();
        let b = p.check_add("b", "yaml-b", 2).unwrap();
        assert!(matches!(p.check_add("a", "x", 3), Err(StoreError::Conflict(_))));
        let s1 = p.checks_stamp().unwrap();
        assert_ne!(s0, s1);
        assert!(p.check_set_enabled(a, false, 4).unwrap());
        assert_ne!(p.checks_stamp().unwrap(), s1);
        assert_eq!(
            p.checks_enabled().unwrap(),
            [("b".to_string(), "yaml-b".to_string())]
        );
        assert!(p.check_update(b, "b2", "yaml-b2", 5).unwrap());
        assert!(matches!(
            p.check_update(b, "a", "x", 6),
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(p.check(b).unwrap().unwrap().check_id, "b2");
        assert!(!p.check_update(99, "z", "x", 7).unwrap());
        assert!(p.check_delete(a).unwrap());
        assert!(!p.check_delete(a).unwrap());
        assert_eq!(p.checks().unwrap().len(), 1);
    }
}
