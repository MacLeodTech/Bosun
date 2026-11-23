//! The install-wide database: users, sessions, API tokens and the audit log. Separate from project files so a
//! project can be shared without leaking accounts, and so accounts survive switching projects.
//!
//! Only hashes of session and API tokens are stored (SHA-256: tokens are 256-bit random values, so a fast hash
//! is enough). Password hashing happens in the API layer (argon2id); this module only stores the PHC string.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::StoreError;

const SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read history and findings.
    Viewer,
    /// Everything a tester does: proxy, tools, scans.
    Tester,
    /// Users, settings, CA and listeners.
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Tester => "tester",
            Self::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "tester" => Some(Self::Tester),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: Role,
    pub created_ms: i64,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user: User,
    pub csrf: String,
    pub expires_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    pub user_id: i64,
    pub created_ms: i64,
    pub last_used_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub time_ms: i64,
    pub username: Option<String>,
    pub action: String,
    pub detail: String,
    pub remote: Option<String>,
}

#[derive(Debug)]
pub struct AppDb {
    conn: Mutex<Connection>,
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

impl AppDb {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| StoreError::Io(path.display().to_string(), e))?;
        }
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::NewerSchema(version));
        }
        if version < 1 {
            conn.execute_batch(
                r#"
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_ms INTEGER NOT NULL
                );
                CREATE TABLE sessions (
                    token_hash BLOB PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    csrf TEXT NOT NULL,
                    created_ms INTEGER NOT NULL,
                    expires_ms INTEGER NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE api_tokens (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    token_hash BLOB NOT NULL UNIQUE,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_ms INTEGER NOT NULL,
                    last_used_ms INTEGER
                );
                -- Append-only: nothing in the code updates or deletes rows here.
                CREATE TABLE audit (
                    id INTEGER PRIMARY KEY,
                    time_ms INTEGER NOT NULL,
                    username TEXT,
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    remote TEXT
                );
                CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
                CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                PRAGMA user_version = 1;
                "#,
            )?;
        }
        if version < 2 {
            // Single sign-on: the provider identity (issuer|subject) an account is linked to.
            conn.execute_batch(
                r#"
                ALTER TABLE users ADD COLUMN sso TEXT;
                CREATE UNIQUE INDEX users_sso ON users(sso) WHERE sso IS NOT NULL;
                PRAGMA user_version = 2;
                "#,
            )?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn user_count(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn()
            .query_row("SELECT count(*) FROM users", [], |r| r.get(0))?)
    }

    pub fn create_user(&self, username: &str, password_hash: &str, role: Role) -> Result<User, StoreError> {
        let now = bosun_model::now_ms();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_ms) VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, role.as_str(), now],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                StoreError::Conflict(format!("user {username:?} already exists"))
            }
            e => e.into(),
        })?;
        Ok(User {
            id: conn.last_insert_rowid(),
            username: username.into(),
            role,
            created_ms: now,
        })
    }

    /// Create the first admin only if there are no users yet, atomically (two racing setup requests cannot both
    /// succeed).
    pub fn create_first_admin(&self, username: &str, password_hash: &str) -> Result<User, StoreError> {
        let now = bosun_model::now_ms();
        let conn = self.conn();
        let n = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_ms)
             SELECT ?1, ?2, 'admin', ?3 WHERE NOT EXISTS (SELECT 1 FROM users)",
            params![username, password_hash, now],
        )?;
        if n == 0 {
            return Err(StoreError::Conflict("setup has already been completed".into()));
        }
        Ok(User {
            id: conn.last_insert_rowid(),
            username: username.into(),
            role: Role::Admin,
            created_ms: now,
        })
    }

    /// The account linked to a single sign-on identity (`issuer|subject`), created the first time with a name derived
    /// from `email` and no usable password (the stored hash is not a valid hash, so no password ever verifies). The
    /// role follows `role` at every sign-in, except that the last admin is never demoted.
    pub fn ensure_sso_user(&self, key: &str, email: &str, role: Role) -> Result<User, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let found = tx
            .query_row(
                "SELECT id, username, role, created_ms FROM users WHERE sso = ?1",
                [key],
                user_from_row,
            )
            .optional()?;
        if let Some(mut u) = found {
            if u.role != role {
                let admins: i64 =
                    tx.query_row("SELECT count(*) FROM users WHERE role = 'admin'", [], |r| {
                        r.get(0)
                    })?;
                if !(u.role == Role::Admin && admins <= 1) {
                    tx.execute(
                        "UPDATE users SET role = ?1 WHERE id = ?2",
                        params![role.as_str(), u.id],
                    )?;
                    u.role = role;
                }
            }
            tx.commit()?;
            return Ok(u);
        }
        let base: String = email.chars().take(60).collect();
        let mut name = base.clone();
        let mut n = 2;
        while tx.query_row("SELECT count(*) FROM users WHERE username = ?1", [&name], |r| {
            r.get::<_, i64>(0)
        })? > 0
        {
            name = format!("{base}-{n}");
            n += 1;
        }
        let now = bosun_model::now_ms();
        tx.execute(
            "INSERT INTO users (username, password_hash, role, created_ms, sso) VALUES (?1, '!sso', ?2, ?3, ?4)",
            params![name, role.as_str(), now, key],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(User {
            id,
            username: name,
            role,
            created_ms: now,
        })
    }

    /// The user and their password hash, for login.
    pub fn user_for_login(&self, username: &str) -> Result<Option<(User, String)>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT id, username, role, created_ms, password_hash FROM users WHERE username = ?1",
                [username],
                |r| Ok((user_from_row(r)?, r.get(4)?)),
            )
            .optional()?)
    }

    pub fn set_password(&self, user_id: i64, password_hash: &str) -> Result<(), StoreError> {
        let conn = self.conn();
        conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            params![password_hash, user_id],
        )?;
        // A password change ends every session of that user.
        conn.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?;
        Ok(())
    }

    pub fn list_users(&self) -> Result<Vec<User>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT id, username, role, created_ms FROM users ORDER BY id")?;
        Ok(stmt.query_map([], user_from_row)?.collect::<Result<_, _>>()?)
    }

    pub fn delete_user(&self, id: i64) -> Result<bool, StoreError> {
        let conn = self.conn();
        let admins: i64 = conn.query_row(
            "SELECT count(*) FROM users WHERE role = 'admin' AND id != ?1",
            [id],
            |r| r.get(0),
        )?;
        let is_admin: bool = conn
            .query_row("SELECT role = 'admin' FROM users WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(false);
        if is_admin && admins == 0 {
            return Err(StoreError::Conflict("cannot delete the last admin".into()));
        }
        Ok(conn.execute("DELETE FROM users WHERE id = ?1", [id])? > 0)
    }

    pub fn create_session(
        &self,
        token: &str,
        user_id: i64,
        csrf: &str,
        ttl_ms: i64,
    ) -> Result<(), StoreError> {
        let now = bosun_model::now_ms();
        let conn = self.conn();
        conn.execute("DELETE FROM sessions WHERE expires_ms < ?1", [now])?;
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, csrf, created_ms, expires_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![token_hash(token), user_id, csrf, now, now + ttl_ms],
        )?;
        Ok(())
    }

    /// Look up a live session and slide its expiry forward.
    pub fn session(&self, token: &str, ttl_ms: i64) -> Result<Option<Session>, StoreError> {
        let now = bosun_model::now_ms();
        let conn = self.conn();
        let h = token_hash(token);
        let s = conn
            .query_row(
                "SELECT u.id, u.username, u.role, u.created_ms, s.csrf, s.expires_ms
                 FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?1 AND s.expires_ms > ?2",
                params![h, now],
                |r| Ok(Session { user: user_from_row(r)?, csrf: r.get(4)?, expires_ms: r.get(5)? }),
            )
            .optional()?;
        if s.is_some() {
            conn.execute(
                "UPDATE sessions SET expires_ms = ?1 WHERE token_hash = ?2",
                params![now + ttl_ms, h],
            )?;
        }
        Ok(s)
    }

    pub fn delete_session(&self, token: &str) -> Result<(), StoreError> {
        self.conn()
            .execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash(token)])?;
        Ok(())
    }

    pub fn create_api_token(&self, name: &str, token: &str, user_id: i64) -> Result<ApiToken, StoreError> {
        let now = bosun_model::now_ms();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO api_tokens (name, token_hash, user_id, created_ms) VALUES (?1, ?2, ?3, ?4)",
            params![name, token_hash(token), user_id, now],
        )?;
        Ok(ApiToken {
            id: conn.last_insert_rowid(),
            name: name.into(),
            user_id,
            created_ms: now,
            last_used_ms: None,
        })
    }

    pub fn user_for_api_token(&self, token: &str) -> Result<Option<User>, StoreError> {
        let conn = self.conn();
        let h = token_hash(token);
        let u = conn
            .query_row(
                "SELECT u.id, u.username, u.role, u.created_ms FROM api_tokens t JOIN users u ON u.id = t.user_id
                 WHERE t.token_hash = ?1",
                [&h],
                user_from_row,
            )
            .optional()?;
        if u.is_some() {
            conn.execute(
                "UPDATE api_tokens SET last_used_ms = ?1 WHERE token_hash = ?2",
                params![bosun_model::now_ms(), h],
            )?;
        }
        Ok(u)
    }

    pub fn list_api_tokens(&self, user_id: i64) -> Result<Vec<ApiToken>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, name, user_id, created_ms, last_used_ms FROM api_tokens WHERE user_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([user_id], |r| {
            Ok(ApiToken {
                id: r.get(0)?,
                name: r.get(1)?,
                user_id: r.get(2)?,
                created_ms: r.get(3)?,
                last_used_ms: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn delete_api_token(&self, id: i64, user_id: i64) -> Result<bool, StoreError> {
        Ok(self.conn().execute(
            "DELETE FROM api_tokens WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )? > 0)
    }

    pub fn audit(
        &self,
        username: Option<&str>,
        action: &str,
        detail: &str,
        remote: Option<&str>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO audit (time_ms, username, action, detail, remote) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![bosun_model::now_ms(), username, action, detail, remote],
        )?;
        Ok(())
    }

    pub fn audit_log(&self, before: Option<i64>, limit: u32) -> Result<Vec<AuditEntry>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, time_ms, username, action, detail, remote FROM audit WHERE id < ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![before.unwrap_or(i64::MAX), limit.clamp(1, 1000)], |r| {
            Ok(AuditEntry {
                id: r.get(0)?,
                time_ms: r.get(1)?,
                username: r.get(2)?,
                action: r.get(3)?,
                detail: r.get(4)?,
                remote: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn()
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

fn user_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    let role: String = r.get(2)?;
    Ok(User {
        id: r.get(0)?,
        username: r.get(1)?,
        role: Role::parse(&role).unwrap_or(Role::Viewer),
        created_ms: r.get(3)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_admin_only_once_and_sessions_work() {
        let db = AppDb::open_in_memory().unwrap();
        let admin = db.create_first_admin("root", "$hash").unwrap();
        assert!(db.create_first_admin("other", "$hash").is_err());
        assert!(matches!(
            db.create_user("ROOT", "$h", Role::Tester),
            Err(StoreError::Conflict(_))
        ));

        db.create_session("tok", admin.id, "csrf1", 60_000).unwrap();
        let s = db.session("tok", 60_000).unwrap().unwrap();
        assert_eq!(s.user.username, "root");
        assert_eq!(s.csrf, "csrf1");
        assert!(db.session("wrong", 60_000).unwrap().is_none());

        db.set_password(admin.id, "$new").unwrap();
        assert!(
            db.session("tok", 60_000).unwrap().is_none(),
            "password change ends sessions"
        );

        db.create_session("expired", admin.id, "c", -1).unwrap();
        assert!(db.session("expired", 60_000).unwrap().is_none());
        assert!(db.delete_user(admin.id).is_err(), "last admin cannot be deleted");
    }

    #[test]
    fn api_tokens_and_append_only_audit() {
        let db = AppDb::open_in_memory().unwrap();
        let u = db.create_user("ci", "$h", Role::Tester).unwrap();
        let t = db.create_api_token("pipeline", "secret-token", u.id).unwrap();
        assert_eq!(db.user_for_api_token("secret-token").unwrap().unwrap().id, u.id);
        assert!(db.user_for_api_token("nope").unwrap().is_none());
        assert!(db.delete_api_token(t.id, u.id).unwrap());
        assert!(db.user_for_api_token("secret-token").unwrap().is_none());

        db.audit(Some("ci"), "login", "ok", Some("127.0.0.1")).unwrap();
        assert_eq!(db.audit_log(None, 10).unwrap().len(), 1);
        let conn = db.conn();
        assert!(conn.execute("DELETE FROM audit", []).is_err());
        assert!(conn.execute("UPDATE audit SET action = 'x'", []).is_err());
    }
}
