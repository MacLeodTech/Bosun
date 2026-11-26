//! Client certificates for mutual-TLS targets. The chain is public; the private key is stored sealed with the
//! data key by the API layer and is never returned by any list.

use rusqlite::{OptionalExtension, params};
use serde::Serialize;

use super::Project;
use crate::StoreError;

pub const MAX_CLIENT_CERTS: i64 = 100;

/// What a list shows: no key material.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ClientCertMeta {
    pub id: i64,
    /// Host pattern: `api.example.com` or `*.example.com`.
    pub host: String,
    pub subject: String,
    pub not_after_ms: i64,
    pub created_ms: i64,
}

/// A stored certificate with its sealed key, for loading into the connector.
#[derive(Debug, Clone)]
pub struct ClientCertRow {
    pub host: String,
    pub chain_der: Vec<Vec<u8>>,
    pub sealed_key: Vec<u8>,
}

fn join(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut v = Vec::new();
    for c in chain {
        v.extend_from_slice(&(c.len() as u32).to_be_bytes());
        v.extend_from_slice(c);
    }
    v
}

fn split(mut b: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if b.len() < 4 + n {
            break;
        }
        out.push(b[4..4 + n].to_vec());
        b = &b[4 + n..];
    }
    out
}

impl Project {
    pub fn client_certs(&self) -> Result<Vec<ClientCertMeta>, StoreError> {
        let conn = self.db.read()?;
        let mut stmt = conn
            .prepare("SELECT id, host, subject, not_after_ms, created_ms FROM client_certs ORDER BY host")?;
        let rows = stmt.query_map([], |r| {
            Ok(ClientCertMeta {
                id: r.get(0)?,
                host: r.get(1)?,
                subject: r.get(2)?,
                not_after_ms: r.get(3)?,
                created_ms: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn client_cert_rows(&self) -> Result<Vec<ClientCertRow>, StoreError> {
        let conn = self.db.read()?;
        let mut stmt = conn.prepare("SELECT host, chain, sealed_key FROM client_certs ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok(ClientCertRow {
                host: r.get(0)?,
                chain_der: split(&r.get::<_, Vec<u8>>(1)?),
                sealed_key: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Add a certificate for a host pattern. A pattern that already has one is a conflict.
    pub fn client_cert_add(
        &self,
        host: &str,
        subject: &str,
        not_after_ms: i64,
        chain_der: &[Vec<u8>],
        sealed_key: &[u8],
        now_ms: i64,
    ) -> Result<i64, StoreError> {
        let mut conn = self.db.write();
        let tx = conn.transaction()?;
        let n: i64 = tx.query_row("SELECT count(*) FROM client_certs", [], |r| r.get(0))?;
        if n >= MAX_CLIENT_CERTS {
            return Err(StoreError::Conflict(format!(
                "a project holds at most {MAX_CLIENT_CERTS} client certificates"
            )));
        }
        tx.execute(
            "INSERT INTO client_certs (host, subject, not_after_ms, chain, sealed_key, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![host, subject, not_after_ms, join(chain_der), sealed_key, now_ms],
        )
        .map_err(|e| match &e {
            rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                StoreError::Conflict(format!("a client certificate for `{host}` already exists"))
            }
            _ => e.into(),
        })?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Delete one; returns its host pattern if it existed.
    pub fn client_cert_delete(&self, id: i64) -> Result<Option<String>, StoreError> {
        let conn = self.db.write();
        let host: Option<String> = conn
            .query_row("SELECT host FROM client_certs WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        if host.is_some() {
            conn.execute("DELETE FROM client_certs WHERE id = ?1", [id])?;
        }
        Ok(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_listed_without_key_and_deleted() {
        let p = Project::open_in_memory().unwrap();
        let chain = vec![vec![1, 2, 3], vec![4]];
        let id = p.client_cert_add("a.test", "CN=a", 10, &chain, b"sealed", 1).unwrap();
        assert!(matches!(
            p.client_cert_add("a.test", "CN=a", 10, &chain, b"x", 2),
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(p.client_certs().unwrap()[0].subject, "CN=a");
        let rows = p.client_cert_rows().unwrap();
        assert_eq!(rows[0].chain_der, chain);
        assert_eq!(rows[0].sealed_key, b"sealed");
        assert_eq!(p.client_cert_delete(id).unwrap().as_deref(), Some("a.test"));
        assert_eq!(p.client_cert_delete(id).unwrap(), None);
    }
}
