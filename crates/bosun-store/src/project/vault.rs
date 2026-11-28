//! The credential vault: named secrets (auth configs, passwords, tokens, keys). The secret is sealed with the data
//! key by the API layer before it gets here, so the project file only ever holds ciphertext. Lists carry a masked
//! hint, never the secret.

use rusqlite::{OptionalExtension, params};
use serde::Serialize;

use super::Project;
use crate::StoreError;

pub const MAX_VAULT_ENTRIES: i64 = 500;

/// What a list shows: no secret.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct VaultEntry {
    pub id: i64,
    pub name: String,
    pub kind: String,
    /// A masked hint such as `••••ab`; never enough to recover the secret.
    pub hint: String,
    pub created_ms: i64,
    pub updated_ms: i64,
}

fn entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<VaultEntry> {
    Ok(VaultEntry {
        id: r.get(0)?,
        name: r.get(1)?,
        kind: r.get(2)?,
        hint: r.get(3)?,
        created_ms: r.get(4)?,
        updated_ms: r.get(5)?,
    })
}

const COLS: &str = "id, name, kind, hint, created_ms, updated_ms";

fn conflict(name: &str, e: rusqlite::Error) -> StoreError {
    match &e {
        rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
            StoreError::Conflict(format!("a vault entry named `{name}` already exists"))
        }
        _ => e.into(),
    }
}

impl Project {
    pub fn vault_list(&self) -> Result<Vec<VaultEntry>, StoreError> {
        let conn = self.db.read()?;
        let mut stmt = conn.prepare(&format!("SELECT {COLS} FROM vault ORDER BY name"))?;
        let rows = stmt.query_map([], entry)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The sealed secret of one entry, for the API layer to open.
    pub fn vault_sealed(&self, id: i64) -> Result<Option<Vec<u8>>, StoreError> {
        let conn = self.db.read()?;
        Ok(conn
            .query_row("SELECT sealed FROM vault WHERE id = ?1", [id], |r| r.get(0))
            .optional()?)
    }

    /// Add an entry. `seal` gets the new row's id (so the ciphertext can be bound to it) and returns the sealed bytes.
    pub fn vault_add(
        &self,
        name: &str,
        kind: &str,
        hint: &str,
        now_ms: i64,
        seal: impl FnOnce(i64) -> Result<Vec<u8>, StoreError>,
    ) -> Result<VaultEntry, StoreError> {
        let mut conn = self.db.write();
        let tx = conn.transaction()?;
        let n: i64 = tx.query_row("SELECT count(*) FROM vault", [], |r| r.get(0))?;
        if n >= MAX_VAULT_ENTRIES {
            return Err(StoreError::Conflict(format!(
                "the vault holds at most {MAX_VAULT_ENTRIES} entries"
            )));
        }
        tx.execute(
            "INSERT INTO vault (name, kind, sealed, hint, created_ms, updated_ms) VALUES (?1, ?2, x'', ?3, ?4, ?4)",
            params![name, kind, hint, now_ms],
        )
        .map_err(|e| conflict(name, e))?;
        let id = tx.last_insert_rowid();
        let sealed = seal(id)?;
        tx.execute("UPDATE vault SET sealed = ?1 WHERE id = ?2", params![sealed, id])?;
        let e = tx.query_row(&format!("SELECT {COLS} FROM vault WHERE id = ?1"), [id], entry)?;
        tx.commit()?;
        Ok(e)
    }

    /// Rename, change the kind, and/or replace the secret (`secret` is the new sealed value and its hint).
    /// `None` when there is no such entry.
    pub fn vault_update(
        &self,
        id: i64,
        name: Option<&str>,
        kind: Option<&str>,
        secret: Option<(&[u8], &str)>,
        now_ms: i64,
    ) -> Result<Option<VaultEntry>, StoreError> {
        let mut conn = self.db.write();
        let tx = conn.transaction()?;
        let exists: Option<i64> = tx
            .query_row("SELECT id FROM vault WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        if exists.is_none() {
            return Ok(None);
        }
        if let Some(n) = name {
            tx.execute("UPDATE vault SET name = ?1 WHERE id = ?2", params![n, id])
                .map_err(|e| conflict(n, e))?;
        }
        if let Some(k) = kind {
            tx.execute("UPDATE vault SET kind = ?1 WHERE id = ?2", params![k, id])?;
        }
        if let Some((sealed, hint)) = secret {
            tx.execute(
                "UPDATE vault SET sealed = ?1, hint = ?2 WHERE id = ?3",
                params![sealed, hint, id],
            )?;
        }
        tx.execute(
            "UPDATE vault SET updated_ms = ?1 WHERE id = ?2",
            params![now_ms, id],
        )?;
        let e = tx.query_row(&format!("SELECT {COLS} FROM vault WHERE id = ?1"), [id], entry)?;
        tx.commit()?;
        Ok(Some(e))
    }

    /// Delete one; returns its name if it existed.
    pub fn vault_delete(&self, id: i64) -> Result<Option<String>, StoreError> {
        let conn = self.db.write();
        let name: Option<String> = conn
            .query_row("SELECT name FROM vault WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        if name.is_some() {
            conn.execute("DELETE FROM vault WHERE id = ?1", [id])?;
        }
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_list_update_delete_never_lists_the_secret() {
        let p = Project::open_in_memory().unwrap();
        let e = p
            .vault_add("api", "token", "••••", 1, |id| {
                Ok(format!("sealed{id}").into_bytes())
            })
            .unwrap();
        assert_eq!(
            p.vault_sealed(e.id).unwrap().unwrap(),
            format!("sealed{}", e.id).into_bytes()
        );
        assert!(matches!(
            p.vault_add("api", "token", "", 2, |_| Ok(vec![1])),
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(p.vault_list().unwrap().len(), 1);
        let u = p
            .vault_update(e.id, Some("api2"), None, Some((b"new", "••ew")), 5)
            .unwrap()
            .unwrap();
        assert_eq!(
            (u.name.as_str(), u.hint.as_str(), u.updated_ms),
            ("api2", "••ew", 5)
        );
        assert_eq!(p.vault_sealed(e.id).unwrap().unwrap(), b"new");
        assert!(p.vault_update(999, None, None, None, 6).unwrap().is_none());
        assert_eq!(p.vault_delete(e.id).unwrap().as_deref(), Some("api2"));
        assert_eq!(p.vault_delete(e.id).unwrap(), None);
    }
}
