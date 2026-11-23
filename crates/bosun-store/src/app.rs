//! The install-wide database: users, sessions, API tokens and the audit log. Separate from project files so a
//! project can be shared without leaking accounts, and so accounts survive switching projects.
//!
//! Only hashes of session and API tokens are stored (SHA-256: tokens are 256-bit random values, so a fast hash
//! is enough). Password hashing happens in the API layer (argon2id); this module only stores the PHC string.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::pool::Db;
use crate::{StoreError, migrate};

/// A session's expiry is only rewritten when it would move by more than this, so a busy client doesn't cause a
/// database write on every request.
const SLIDE_GRANULARITY_MS: i64 = 60_000;
/// `last_used_ms` of a token is refreshed at most this often.
const TOKEN_USED_GRANULARITY_MS: i64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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

/// What an API token may do. A `Read` token can only make requests that don't change anything (GET, HEAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenScope {
    Read,
    #[default]
    Full,
}

impl TokenScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Full => "full",
        }
    }

    fn parse(s: &str) -> Self {
        // Anything unrecognised gets the narrower scope.
        if s == "full" { Self::Full } else { Self::Read }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    pub user_id: i64,
    pub created_ms: i64,
    pub last_used_ms: Option<i64>,
    pub expires_ms: Option<i64>,
    pub scope: TokenScope,
}

/// A signed-in browser session, as shown to its owner and to admins. The id is a prefix of the stored hash; it
/// cannot be used to sign in.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SessionInfo {
    pub id: String,
    pub user_id: i64,
    pub created_ms: i64,
    pub expires_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuditEntry {
    pub id: i64,
    pub time_ms: i64,
    pub username: Option<String>,
    pub action: String,
    pub detail: String,
    pub remote: Option<String>,
}

/// The account database's history. Never edit an entry that has shipped; add a new one at the end.
const MIGRATIONS: &[migrate::Migration] = &[
    migrate::Migration {
        version: 1,
        rebuild: false,
        what: "accounts, sessions, tokens, audit log",
        sql: r#"
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
        "#,
    },
    migrate::Migration {
        version: 2,
        rebuild: false,
        what: "single sign-on identity on accounts",
        sql: r#"
            ALTER TABLE users ADD COLUMN sso TEXT;
            CREATE UNIQUE INDEX users_sso ON users(sso) WHERE sso IS NOT NULL;
        "#,
    },
    migrate::Migration {
        version: 3,
        rebuild: false,
        what: "token expiry and scope (existing tokens keep full access and no expiry)",
        sql: r#"
            ALTER TABLE api_tokens ADD COLUMN expires_ms INTEGER;
            ALTER TABLE api_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT 'full';
        "#,
    },
];

#[derive(Debug)]
pub struct AppDb {
    db: Db,
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
        Self::init(conn, Some(path.to_path_buf()))
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?, None)
    }

    fn init(mut conn: Connection, path: Option<std::path::PathBuf>) -> Result<Self, StoreError> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        migrate::run(&mut conn, MIGRATIONS)?;
        Ok(Self {
            db: Db::new(conn, path, |c| c.pragma_update(None, "foreign_keys", "ON")),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.write()
    }

    pub fn user_count(&self) -> Result<i64, StoreError> {
        Ok(self
            .db
            .read()?
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

    /// The account a desktop login ticket signs in as: the oldest admin. With no users at all, a local admin named
    /// `name` is created first, with no usable password (the stored hash is not a valid hash, so none verifies;
    /// `bosun user passwd` can set one later). Returns the user and whether it was just created.
    pub fn ticket_user(&self, name: &str) -> Result<(User, bool), StoreError> {
        let now = bosun_model::now_ms();
        let conn = self.conn();
        let n = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_ms)
             SELECT ?1, '!ticket', 'admin', ?2 WHERE NOT EXISTS (SELECT 1 FROM users)",
            params![name, now],
        )?;
        let created = n > 0;
        let user = conn.query_row(
            "SELECT id, username, role, created_ms FROM users WHERE role = 'admin' ORDER BY id LIMIT 1",
            [],
            |r| {
                Ok(User {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    role: Role::parse(&r.get::<_, String>(2)?).unwrap_or(Role::Viewer),
                    created_ms: r.get(3)?,
                })
            },
        )?;
        Ok((user, created))
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
            .db
            .read()?
            .query_row(
                "SELECT id, username, role, created_ms, password_hash FROM users WHERE username = ?1",
                [username],
                |r| Ok((user_from_row(r)?, r.get(4)?)),
            )
            .optional()?)
    }

    /// Change a password. Every session of the user ends; their API tokens too when `revoke_tokens` is set (a
    /// stolen password must not leave behind a token that outlives the reset).
    pub fn set_password(
        &self,
        user_id: i64,
        password_hash: &str,
        revoke_tokens: bool,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            params![password_hash, user_id],
        )?;
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?;
        if revoke_tokens {
            tx.execute("DELETE FROM api_tokens WHERE user_id = ?1", [user_id])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Change a user's role. The last admin cannot be demoted. Their sessions end so the new role applies at once.
    pub fn set_role(&self, user_id: i64, role: Role) -> Result<bool, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let current: Option<String> = tx
            .query_row("SELECT role FROM users WHERE id = ?1", [user_id], |r| r.get(0))
            .optional()?;
        let Some(current) = current else { return Ok(false) };
        if current == "admin" && role != Role::Admin {
            let others: i64 = tx.query_row(
                "SELECT count(*) FROM users WHERE role = 'admin' AND id != ?1",
                [user_id],
                |r| r.get(0),
            )?;
            if others == 0 {
                return Err(StoreError::Conflict("cannot demote the last admin".into()));
            }
        }
        tx.execute(
            "UPDATE users SET role = ?1 WHERE id = ?2",
            params![role.as_str(), user_id],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn list_users(&self) -> Result<Vec<User>, StoreError> {
        let conn = self.db.read()?;
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

    /// Look up a live session. It dies when idle for `idle_ms` or when it is `max_ms` old, whichever comes first.
    /// The idle expiry slides forward, but is only rewritten when it has moved by more than a minute.
    pub fn session(&self, token: &str, idle_ms: i64, max_ms: i64) -> Result<Option<Session>, StoreError> {
        let now = bosun_model::now_ms();
        let conn = self.conn();
        let h = token_hash(token);
        let found = conn
            .query_row(
                "SELECT u.id, u.username, u.role, u.created_ms, s.csrf, s.expires_ms, s.created_ms
                 FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?1 AND s.expires_ms > ?2",
                params![h, now],
                |r| Ok((Session { user: user_from_row(r)?, csrf: r.get(4)?, expires_ms: r.get(5)? }, r.get::<_, i64>(6)?)),
            )
            .optional()?;
        let Some((mut s, created)) = found else {
            return Ok(None);
        };
        let hard_end = created.saturating_add(max_ms);
        if now >= hard_end {
            conn.execute("DELETE FROM sessions WHERE token_hash = ?1", [&h])?;
            return Ok(None);
        }
        let want = (now + idle_ms).min(hard_end);
        if want - s.expires_ms > SLIDE_GRANULARITY_MS {
            conn.execute(
                "UPDATE sessions SET expires_ms = ?1 WHERE token_hash = ?2",
                params![want, h],
            )?;
            s.expires_ms = want;
        }
        Ok(Some(s))
    }

    pub fn list_sessions(&self, user_id: i64) -> Result<Vec<SessionInfo>, StoreError> {
        let now = bosun_model::now_ms();
        let conn = self.db.read()?;
        let mut stmt = conn.prepare(
            "SELECT hex(substr(token_hash, 1, 8)), user_id, created_ms, expires_ms FROM sessions
             WHERE user_id = ?1 AND expires_ms > ?2 ORDER BY created_ms",
        )?;
        let rows = stmt.query_map(params![user_id, now], |r| {
            Ok(SessionInfo {
                id: r.get::<_, String>(0)?.to_ascii_lowercase(),
                user_id: r.get(1)?,
                created_ms: r.get(2)?,
                expires_ms: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// End one session of a user (by the id from [`Self::list_sessions`]).
    pub fn revoke_session(&self, user_id: i64, id: &str) -> Result<bool, StoreError> {
        Ok(self.conn().execute(
            "DELETE FROM sessions WHERE user_id = ?1 AND lower(hex(substr(token_hash, 1, 8))) = ?2",
            params![user_id, id.to_ascii_lowercase()],
        )? > 0)
    }

    /// End every session of a user. Returns how many there were.
    pub fn revoke_sessions(&self, user_id: i64) -> Result<usize, StoreError> {
        Ok(self
            .conn()
            .execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?)
    }

    pub fn delete_session(&self, token: &str) -> Result<(), StoreError> {
        self.conn()
            .execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash(token)])?;
        Ok(())
    }

    pub fn create_api_token(
        &self,
        name: &str,
        token: &str,
        user_id: i64,
        scope: TokenScope,
        expires_ms: Option<i64>,
    ) -> Result<ApiToken, StoreError> {
        let now = bosun_model::now_ms();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO api_tokens (name, token_hash, user_id, created_ms, expires_ms, scope)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![name, token_hash(token), user_id, now, expires_ms, scope.as_str()],
        )?;
        Ok(ApiToken {
            id: conn.last_insert_rowid(),
            name: name.into(),
            user_id,
            created_ms: now,
            last_used_ms: None,
            expires_ms,
            scope,
        })
    }

    /// The owner and scope of a live (not expired) token. `last_used_ms` is refreshed at most once a minute.
    pub fn user_for_api_token(&self, token: &str) -> Result<Option<(User, TokenScope)>, StoreError> {
        let now = bosun_model::now_ms();
        let conn = self.conn();
        let h = token_hash(token);
        let found = conn
            .query_row(
                "SELECT u.id, u.username, u.role, u.created_ms, t.scope, t.last_used_ms
                 FROM api_tokens t JOIN users u ON u.id = t.user_id
                 WHERE t.token_hash = ?1 AND (t.expires_ms IS NULL OR t.expires_ms > ?2)",
                params![h, now],
                |r| {
                    Ok((
                        user_from_row(r)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((user, scope, last)) = found else {
            return Ok(None);
        };
        if last.is_none_or(|l| now - l > TOKEN_USED_GRANULARITY_MS) {
            conn.execute(
                "UPDATE api_tokens SET last_used_ms = ?1 WHERE token_hash = ?2",
                params![now, h],
            )?;
        }
        Ok(Some((user, TokenScope::parse(&scope))))
    }

    pub fn list_api_tokens(&self, user_id: i64) -> Result<Vec<ApiToken>, StoreError> {
        let conn = self.db.read()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, user_id, created_ms, last_used_ms, expires_ms, scope FROM api_tokens
             WHERE user_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([user_id], |r| {
            Ok(ApiToken {
                id: r.get(0)?,
                name: r.get(1)?,
                user_id: r.get(2)?,
                created_ms: r.get(3)?,
                last_used_ms: r.get(4)?,
                expires_ms: r.get(5)?,
                scope: TokenScope::parse(&r.get::<_, String>(6)?),
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
        let conn = self.db.read()?;
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
            .db
            .read()?
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
        let s = db.session("tok", 60_000, 3_600_000).unwrap().unwrap();
        assert_eq!(s.user.username, "root");
        assert_eq!(s.csrf, "csrf1");
        assert!(db.session("wrong", 60_000, 3_600_000).unwrap().is_none());

        db.set_password(admin.id, "$new", true).unwrap();
        assert!(
            db.session("tok", 60_000, 3_600_000).unwrap().is_none(),
            "password change ends sessions"
        );

        db.create_session("expired", admin.id, "c", -1).unwrap();
        assert!(db.session("expired", 60_000, 3_600_000).unwrap().is_none());
        assert!(db.delete_user(admin.id).is_err(), "last admin cannot be deleted");
    }

    #[test]
    fn api_tokens_and_append_only_audit() {
        let db = AppDb::open_in_memory().unwrap();
        let u = db.create_user("ci", "$h", Role::Tester).unwrap();
        let t = db
            .create_api_token("pipeline", "secret-token", u.id, TokenScope::Full, None)
            .unwrap();
        assert_eq!(db.user_for_api_token("secret-token").unwrap().unwrap().0.id, u.id);
        assert!(db.user_for_api_token("nope").unwrap().is_none());
        assert!(db.delete_api_token(t.id, u.id).unwrap());
        assert!(db.user_for_api_token("secret-token").unwrap().is_none());

        db.audit(Some("ci"), "login", "ok", Some("127.0.0.1")).unwrap();
        assert_eq!(db.audit_log(None, 10).unwrap().len(), 1);
        let conn = db.conn();
        assert!(conn.execute("DELETE FROM audit", []).is_err());
        assert!(conn.execute("UPDATE audit SET action = 'x'", []).is_err());
    }

    #[test]
    fn a_password_change_revokes_tokens_when_asked() {
        let db = AppDb::open_in_memory().unwrap();
        let u = db.create_user("a", "$h", Role::Tester).unwrap();
        db.create_api_token("t", "tok-a", u.id, TokenScope::Full, None)
            .unwrap();
        db.set_password(u.id, "$n", false).unwrap();
        assert!(db.user_for_api_token("tok-a").unwrap().is_some());
        db.set_password(u.id, "$n", true).unwrap();
        assert!(db.user_for_api_token("tok-a").unwrap().is_none());
    }

    #[test]
    fn tokens_expire_and_carry_a_scope() {
        let db = AppDb::open_in_memory().unwrap();
        let u = db.create_user("a", "$h", Role::Tester).unwrap();
        let now = bosun_model::now_ms();
        db.create_api_token("old", "t-old", u.id, TokenScope::Full, Some(now - 1))
            .unwrap();
        db.create_api_token("ro", "t-ro", u.id, TokenScope::Read, Some(now + 60_000))
            .unwrap();
        assert!(db.user_for_api_token("t-old").unwrap().is_none());
        assert_eq!(
            db.user_for_api_token("t-ro").unwrap().unwrap().1,
            TokenScope::Read
        );
        assert_eq!(db.list_api_tokens(u.id).unwrap().len(), 2);
    }

    #[test]
    fn sessions_have_an_absolute_lifetime_and_slide_sparingly() {
        let db = AppDb::open_in_memory().unwrap();
        let u = db.create_user("a", "$h", Role::Tester).unwrap();
        db.create_session("s1", u.id, "c", 10 * 60_000).unwrap();
        let first = db.session("s1", 10 * 60_000, 3_600_000).unwrap().unwrap();
        let again = db.session("s1", 10 * 60_000 + 5_000, 3_600_000).unwrap().unwrap();
        assert_eq!(
            first.expires_ms, again.expires_ms,
            "a move of under a minute is not written"
        );
        // Created long ago relative to the maximum: dead no matter how recently it was used.
        assert!(db.session("s1", 10 * 60_000, 0).unwrap().is_none());
        assert!(
            db.session("s1", 10 * 60_000, 3_600_000).unwrap().is_none(),
            "and it was deleted"
        );
        // The idle extension never passes the absolute end.
        db.create_session("s2", u.id, "c", 1000).unwrap();
        let s = db.session("s2", 10 * 60_000, 120_000).unwrap().unwrap();
        assert!(s.expires_ms <= bosun_model::now_ms() + 120_000);
    }

    #[test]
    fn roles_change_but_the_last_admin_stays() {
        let db = AppDb::open_in_memory().unwrap();
        let a = db.create_first_admin("root", "$h").unwrap();
        let b = db.create_user("b", "$h", Role::Tester).unwrap();
        assert!(matches!(
            db.set_role(a.id, Role::Viewer),
            Err(StoreError::Conflict(_))
        ));
        assert!(db.set_role(b.id, Role::Admin).unwrap());
        assert!(db.set_role(a.id, Role::Viewer).unwrap());
        assert!(!db.set_role(999, Role::Viewer).unwrap());
    }

    #[test]
    fn sessions_can_be_listed_and_revoked() {
        let db = AppDb::open_in_memory().unwrap();
        let u = db.create_user("a", "$h", Role::Tester).unwrap();
        db.create_session("s1", u.id, "c", 60_000).unwrap();
        db.create_session("s2", u.id, "c", 60_000).unwrap();
        let list = db.list_sessions(u.id).unwrap();
        assert_eq!(list.len(), 2);
        assert!(db.revoke_session(u.id, &list[0].id).unwrap());
        assert!(
            !db.revoke_session(u.id + 1, &list[1].id).unwrap(),
            "only the owner's"
        );
        assert_eq!(db.revoke_sessions(u.id).unwrap(), 1);
    }

    #[test]
    fn a_database_from_each_earlier_version_upgrades_and_keeps_its_accounts() {
        for from in 1..migrate::latest(MIGRATIONS) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("app.db");
            {
                let mut c = Connection::open(&path).unwrap();
                migrate::run(&mut c, &MIGRATIONS[..from as usize]).unwrap();
                c.execute(
                    "INSERT INTO users (username, password_hash, role, created_ms) VALUES ('ann', 'h', 'admin', 1)",
                    [],
                )
                .unwrap();
            }
            let db = AppDb::open(&path).unwrap();
            assert_eq!(db.user_count().unwrap(), 1, "from v{from}");
            // The newest columns exist and work.
            db.create_user("bob", "h", Role::Viewer).unwrap();
            let back = Connection::open(migrate::backup_path(path.to_str().unwrap(), from)).unwrap();
            let v: i64 = back
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap();
            assert_eq!(v, from, "the backup is the file as it was");
        }
    }
}
