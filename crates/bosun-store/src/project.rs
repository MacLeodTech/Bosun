//! A project file: recorded flows, bodies, WebSocket messages and project settings in one SQLite database.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};

use bosun_model::{
    Direction, FlowDetail, FlowId, FlowSource, FlowSummary, RawRequest, RawResponse, Scheme, WsMessage,
};
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{StoreError, codec};

const SCHEMA_VERSION: i64 = 1;
/// The most a stored body may claim to be once decompressed. The proxy never records more than its buffer caps
/// (64 MiB), so a larger claim means a corrupt or hostile file.
const MAX_BLOB: u64 = 128 * 1024 * 1024;
/// The most a stored WebSocket payload may decompress to (the proxy records up to 1 MiB per message).
const MAX_WS_PAYLOAD: u64 = 4 * 1024 * 1024;
/// How much decoded text per flow goes into the search index.
const INDEX_TEXT_LIMIT: usize = 64 * 1024;

/// A finished flow, ready to be written.
#[derive(Debug, Clone)]
pub struct NewFlow {
    pub id: FlowId,
    pub source: FlowSource,
    pub started_ms: i64,
    pub duration_ms: Option<i64>,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub http_version: String,
    pub status: Option<u16>,
    pub in_scope: bool,
    pub edited: bool,
    pub error: Option<String>,
    pub request: Vec<u8>,
    pub original_request: Option<Vec<u8>>,
    pub response: Option<Vec<u8>>,
    pub original_response: Option<Vec<u8>>,
    pub response_truncated: bool,
}

#[derive(Debug, Clone)]
pub struct NewWsMessage {
    pub flow_id: FlowId,
    pub time_ms: i64,
    pub direction: Direction,
    pub opcode: u8,
    pub payload: Vec<u8>,
    pub truncated: bool,
}

/// History filter. Every field is optional; results are newest first.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowFilter {
    /// Full-text (substring) search over the request line, headers and decoded text bodies.
    pub text: Option<String>,
    pub host: Option<String>,
    pub methods: Option<Vec<String>>,
    pub status_min: Option<u16>,
    pub status_max: Option<u16>,
    #[serde(default)]
    pub in_scope_only: bool,
    pub source: Option<FlowSource>,
    /// File extensions to hide, e.g. `["png", "css", "woff2"]`.
    pub hide_extensions: Option<Vec<String>>,
    /// Only flows with an id below this (for paging backwards).
    pub before_id: Option<FlowId>,
    /// Only flows with an id above this (for polling for new ones).
    pub after_id: Option<FlowId>,
    pub limit: Option<u32>,
}

/// A host and the paths seen on it, for the site map.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug)]
pub struct Project {
    conn: Mutex<Connection>,
    next_id: AtomicI64,
    /// Held for as long as the project is open; the OS releases it if we die.
    _lock: Option<std::fs::File>,
}

/// Every statement that creates this version's schema.
const SCHEMA_V1: &str = r#"
    CREATE TABLE blobs (
        hash BLOB PRIMARY KEY,
        size INTEGER NOT NULL,
        data BLOB NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE flows (
        id INTEGER PRIMARY KEY,
        source TEXT NOT NULL,
        started_ms INTEGER NOT NULL,
        duration_ms INTEGER,
        scheme TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        base_path TEXT NOT NULL,
        http_version TEXT NOT NULL,
        status INTEGER,
        request_len INTEGER NOT NULL,
        response_len INTEGER,
        mime TEXT,
        in_scope INTEGER NOT NULL,
        edited INTEGER NOT NULL,
        error TEXT,
        tags TEXT NOT NULL DEFAULT '[]',
        note TEXT,
        req_blob BLOB NOT NULL REFERENCES blobs(hash),
        orig_req_blob BLOB REFERENCES blobs(hash),
        resp_blob BLOB REFERENCES blobs(hash),
        orig_resp_blob BLOB REFERENCES blobs(hash),
        resp_truncated INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX flows_host ON flows(host);
    CREATE INDEX flows_site ON flows(scheme, host, port, base_path);
    CREATE VIRTUAL TABLE flow_text USING fts5(body, content='', contentless_delete=1, tokenize='trigram');
    CREATE TABLE ws_messages (
        id INTEGER PRIMARY KEY,
        flow_id INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
        time_ms INTEGER NOT NULL,
        direction INTEGER NOT NULL,
        opcode INTEGER NOT NULL,
        payload BLOB NOT NULL,
        truncated INTEGER NOT NULL
    );
    CREATE INDEX ws_by_flow ON ws_messages(flow_id);
    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
"#;

/// The schema objects in a database as (type, name, sql), ignoring SQLite's own bookkeeping tables.
fn schema_objects(conn: &Connection) -> Result<BTreeSet<(String, String, String)>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT type, name, coalesce(sql, '') FROM sqlite_master WHERE substr(name, 1, 7) <> 'sqlite_'",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// A project file may come from someone else: refuse anything that is not exactly the schema this version
/// creates. Triggers and views in particular run SQL of the file author's choosing on our connection.
fn verify_schema(conn: &Connection) -> Result<(), StoreError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SCHEMA_V1)?;
    let want = schema_objects(&expected)?;
    let have = schema_objects(conn)?;
    if let Some(extra) = have.difference(&want).next() {
        return Err(StoreError::Untrusted(format!(
            "unexpected {} `{}`",
            extra.0, extra.1
        )));
    }
    if let Some(missing) = want.difference(&have).next() {
        return Err(StoreError::Untrusted(format!(
            "missing or altered {} `{}`",
            missing.0, missing.1
        )));
    }
    Ok(())
}

/// Decompress a stored body, refusing to produce more than `limit` bytes. `expect` is the size the file claims.
/// Public so the fuzz targets can reach it.
pub fn bounded_decode(data: &[u8], limit: u64, expect: Option<u64>) -> Result<Vec<u8>, StoreError> {
    let corrupt = |why: &str| {
        StoreError::Compress(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            why.to_string(),
        ))
    };
    if let Some(n) = expect
        && n > limit
    {
        return Err(corrupt("stored size exceeds the limit"));
    }
    let cap = expect.unwrap_or(limit);
    let mut out = Vec::new();
    let dec = zstd::stream::read::Decoder::new(data).map_err(StoreError::Compress)?;
    dec.take(cap + 1)
        .read_to_end(&mut out)
        .map_err(StoreError::Compress)?;
    if out.len() as u64 > cap {
        return Err(corrupt("decompressed data is larger than recorded"));
    }
    if let Some(n) = expect
        && out.len() as u64 != n
    {
        return Err(corrupt("decompressed size does not match the recorded size"));
    }
    Ok(out)
}

/// The lock file beside a project: `<project>.lock`.
fn lock_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

fn take_lock(path: &Path) -> Result<std::fs::File, StoreError> {
    use std::io::Write;
    let lp = lock_path(path);
    let io = |e| StoreError::Io(lp.display().to_string(), e);
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lp)
        .map_err(io)?;
    match f.try_lock() {
        Ok(()) => {
            let _ = f.set_len(0);
            let _ = write!(f, "{}", std::process::id());
            Ok(f)
        }
        Err(std::fs::TryLockError::WouldBlock) => {
            let mut who = String::new();
            let _ = f.read_to_string(&mut who);
            let who = who.trim();
            Err(StoreError::Locked(if who.is_empty() {
                format!("{} is open in another Bosun process", path.display())
            } else {
                format!("{} is open in another Bosun process (pid {who})", path.display())
            }))
        }
        Err(std::fs::TryLockError::Error(e)) => Err(io(e)),
    }
}

impl Project {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let lock = take_lock(path)?;
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Projects hold credentials and session tokens captured from targets.
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Self::init(conn, Some(lock))
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?, None)
    }

    fn init(conn: Connection, lock: Option<std::fs::File>) -> Result<Self, StoreError> {
        // The file may be hostile: no SQL stored in it (triggers, views, generated columns) may call
        // functions that have side effects, corrupt pages must not be followed, and the connection must not
        // allow the schema to be rewritten from under us.
        conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
        conn.pragma_update(None, "trusted_schema", "OFF")?;
        conn.pragma_update(None, "cell_size_check", "ON")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::NewerSchema(version));
        }
        if version == 1 {
            verify_schema(&conn)?;
        } else if !schema_objects(&conn)?.is_empty() {
            return Err(StoreError::Untrusted("not a Bosun project".into()));
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        if version < 1 {
            conn.execute_batch(SCHEMA_V1)?;
            conn.pragma_update(None, "user_version", 1)?;
        }
        let max: Option<i64> = conn.query_row("SELECT max(id) FROM flows", [], |r| r.get(0))?;
        Ok(Self {
            conn: Mutex::new(conn),
            next_id: AtomicI64::new(max.unwrap_or(0) + 1),
            _lock: lock,
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reserve an id for a flow that will be written later (so WebSocket messages and events can refer to it).
    pub fn next_flow_id(&self) -> FlowId {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Write a batch of flows and WebSocket messages in one transaction.
    pub fn write_batch(&self, flows: &[NewFlow], ws: &[NewWsMessage]) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for f in flows {
            let req = put_blob(&tx, &f.request)?;
            let orig_req = f
                .original_request
                .as_deref()
                .map(|b| put_blob(&tx, b))
                .transpose()?;
            let resp = f.response.as_deref().map(|b| put_blob(&tx, b)).transpose()?;
            let orig_resp = f
                .original_response
                .as_deref()
                .map(|b| put_blob(&tx, b))
                .transpose()?;
            let parsed_resp = f.response.as_deref().and_then(|r| RawResponse::parse(r).ok());
            let mime = parsed_resp.as_ref().and_then(|r| {
                r.header("content-type").map(|v| {
                    String::from_utf8_lossy(v)
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase()
                })
            });
            tx.execute(
                "INSERT INTO flows (id, source, started_ms, duration_ms, scheme, host, port, method, path,
                    base_path, http_version, status, request_len, response_len, mime, in_scope, edited, error,
                    req_blob, orig_req_blob, resp_blob, orig_resp_blob, resp_truncated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19,
                    ?20, ?21, ?22, ?23)",
                params![
                    f.id,
                    f.source.as_str(),
                    f.started_ms,
                    f.duration_ms,
                    f.scheme.as_str(),
                    f.host,
                    f.port,
                    f.method,
                    f.path,
                    base_path(&f.path),
                    f.http_version,
                    f.status,
                    f.request.len() as i64,
                    f.response.as_ref().map(|r| r.len() as i64),
                    mime,
                    f.in_scope,
                    f.edited,
                    f.error,
                    req,
                    orig_req,
                    resp,
                    orig_resp,
                    f.response_truncated,
                ],
            )?;
            let text = index_text(f, parsed_resp.as_ref());
            tx.execute(
                "INSERT INTO flow_text (rowid, body) VALUES (?1, ?2)",
                params![f.id, text],
            )?;
        }
        for m in ws {
            tx.execute(
                "INSERT INTO ws_messages (flow_id, time_ms, direction, opcode, payload, truncated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    m.flow_id,
                    m.time_ms,
                    matches!(m.direction, Direction::ServerToClient) as i64,
                    m.opcode,
                    zstd::encode_all(&m.payload[..], 1).map_err(StoreError::Compress)?,
                    m.truncated
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_flows(&self, f: &FlowFilter) -> Result<Vec<FlowSummary>, StoreError> {
        let mut sql = String::from("SELECT ");
        sql.push_str(SUMMARY_COLS);
        sql.push_str(" FROM flows WHERE 1=1");
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        use rusqlite::types::Value as V;
        if let Some(t) = f.text.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            // The trigram tokenizer needs at least three characters; shorter terms fall back to the URL.
            if t.chars().count() >= 3 {
                sql.push_str(" AND id IN (SELECT rowid FROM flow_text WHERE flow_text MATCH ?)");
                args.push(V::Text(format!("\"{}\"", t.replace('"', "\"\""))));
            } else {
                sql.push_str(" AND (host || path) LIKE ? ESCAPE '\\'");
                args.push(V::Text(format!("%{}%", like_escape(t))));
            }
        }
        if let Some(h) = f.host.as_deref().map(str::trim).filter(|h| !h.is_empty()) {
            sql.push_str(" AND host LIKE ? ESCAPE '\\'");
            args.push(V::Text(format!("%{}%", like_escape(&h.to_ascii_lowercase()))));
        }
        if let Some(ms) = f.methods.as_ref().filter(|m| !m.is_empty()) {
            sql.push_str(" AND method IN (");
            sql.push_str(&vec!["?"; ms.len()].join(","));
            sql.push(')');
            args.extend(ms.iter().map(|m| V::Text(m.to_ascii_uppercase())));
        }
        if let Some(s) = f.status_min {
            sql.push_str(" AND status >= ?");
            args.push(V::Integer(s.into()));
        }
        if let Some(s) = f.status_max {
            sql.push_str(" AND status <= ?");
            args.push(V::Integer(s.into()));
        }
        if f.in_scope_only {
            sql.push_str(" AND in_scope = 1");
        }
        if let Some(s) = f.source {
            sql.push_str(" AND source = ?");
            args.push(V::Text(s.as_str().into()));
        }
        if let Some(exts) = f.hide_extensions.as_ref() {
            for e in exts
                .iter()
                .filter(|e| e.chars().all(|c| c.is_ascii_alphanumeric()) && !e.is_empty())
            {
                sql.push_str(" AND lower(base_path) NOT LIKE ?");
                args.push(V::Text(format!("%.{}", e.to_ascii_lowercase())));
            }
        }
        if let Some(b) = f.before_id {
            sql.push_str(" AND id < ?");
            args.push(V::Integer(b));
        }
        if let Some(a) = f.after_id {
            sql.push_str(" AND id > ?");
            args.push(V::Integer(a));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        args.push(V::Integer(f.limit.unwrap_or(200).clamp(1, 5000).into()));
        let conn = self.conn();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), summary_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Summaries for specific flows, in id order.
    pub fn summaries(&self, ids: &[FlowId]) -> Result<Vec<FlowSummary>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn();
        let mut out = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(500) {
            let sql = format!(
                "SELECT {SUMMARY_COLS} FROM flows WHERE id IN ({}) ORDER BY id",
                vec!["?"; chunk.len()].join(",")
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(chunk.iter()), summary_from_row)?;
            for r in rows {
                out.push(r?);
            }
        }
        Ok(out)
    }

    pub fn get_flow(&self, id: FlowId) -> Result<Option<FlowDetail>, StoreError> {
        let conn = self.conn();
        let sql = format!(
            "SELECT {SUMMARY_COLS}, req_blob, orig_req_blob, resp_blob, orig_resp_blob, resp_truncated
             FROM flows WHERE id = ?1"
        );
        let row = conn
            .query_row(&sql, [id], |r| {
                Ok((
                    summary_from_row(r)?,
                    r.get::<_, Vec<u8>>(20)?,
                    r.get::<_, Option<Vec<u8>>>(21)?,
                    r.get::<_, Option<Vec<u8>>>(22)?,
                    r.get::<_, Option<Vec<u8>>>(23)?,
                    r.get::<_, bool>(24)?,
                ))
            })
            .optional()?;
        let Some((summary, req, orig_req, resp, orig_resp, truncated)) = row else {
            return Ok(None);
        };
        let get = |h: Option<Vec<u8>>| h.map(|h| get_blob(&conn, &h)).transpose();
        Ok(Some(FlowDetail {
            summary,
            request: get_blob(&conn, &req)?,
            original_request: get(orig_req)?,
            response: get(resp)?,
            original_response: get(orig_resp)?,
            response_truncated: truncated,
        }))
    }

    pub fn set_annotations(
        &self,
        id: FlowId,
        tags: Option<&[String]>,
        note: Option<&str>,
    ) -> Result<bool, StoreError> {
        let conn = self.conn();
        let mut n = 0;
        if let Some(t) = tags {
            n = conn.execute(
                "UPDATE flows SET tags = ?1 WHERE id = ?2",
                params![serde_json::to_string(t).map_err(StoreError::Json)?, id],
            )?;
        }
        if let Some(note) = note {
            let note = if note.is_empty() { None } else { Some(note) };
            n = conn.execute("UPDATE flows SET note = ?1 WHERE id = ?2", params![note, id])?;
        }
        Ok(n > 0)
    }

    /// Delete flows (and blobs nothing refers to any more).
    pub fn delete_flows(&self, ids: &[FlowId]) -> Result<usize, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let mut n = 0;
        for id in ids {
            tx.execute("DELETE FROM flow_text WHERE rowid = ?1", [id])?;
            n += tx.execute("DELETE FROM flows WHERE id = ?1", [id])?;
        }
        tx.execute(
            "DELETE FROM blobs WHERE hash NOT IN (
                SELECT req_blob FROM flows UNION SELECT orig_req_blob FROM flows WHERE orig_req_blob IS NOT NULL
                UNION SELECT resp_blob FROM flows WHERE resp_blob IS NOT NULL
                UNION SELECT orig_resp_blob FROM flows WHERE orig_resp_blob IS NOT NULL)",
            [],
        )?;
        tx.commit()?;
        Ok(n)
    }

    pub fn ws_messages(
        &self,
        flow_id: FlowId,
        after: Option<i64>,
        limit: u32,
    ) -> Result<Vec<WsMessage>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, flow_id, time_ms, direction, opcode, payload, truncated FROM ws_messages
             WHERE flow_id = ?1 AND id > ?2 ORDER BY id LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![flow_id, after.unwrap_or(0), limit.clamp(1, 5000)], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, u8>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, bool>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, flow_id, time_ms, dir, opcode, payload, truncated) = row?;
            out.push(WsMessage {
                id,
                flow_id,
                time_ms,
                direction: if dir == 1 {
                    Direction::ServerToClient
                } else {
                    Direction::ClientToServer
                },
                opcode,
                payload: bounded_decode(&payload, MAX_WS_PAYLOAD, None)?,
                truncated,
            });
        }
        Ok(out)
    }

    /// The site map: one entry per distinct (origin, path without query).
    pub fn site_map(&self, host: Option<&str>) -> Result<Vec<SiteMapEntry>, StoreError> {
        let conn = self.conn();
        // The bare `status` column in an aggregate with max(id) takes its value from the newest row (SQLite's
        // documented min/max bare-column behaviour).
        let mut stmt = conn.prepare(
            "SELECT scheme, host, port, base_path, group_concat(DISTINCT method), status, count(*), max(in_scope),
                    max(id)
             FROM flows WHERE (?1 IS NULL OR host = ?1)
             GROUP BY scheme, host, port, base_path ORDER BY host, port, base_path LIMIT 100000",
        )?;
        let rows = stmt.query_map([host], |r| {
            let scheme: String = r.get(0)?;
            Ok(SiteMapEntry {
                scheme: Scheme::parse(&scheme).unwrap_or(Scheme::Http),
                host: r.get(1)?,
                port: r.get(2)?,
                path: r.get(3)?,
                methods: r
                    .get::<_, String>(4)?
                    .split(',')
                    .map(str::to_string)
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                last_status: r.get(5)?,
                count: r.get(6)?,
                in_scope: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn setting<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, StoreError> {
        let conn = self.conn();
        let v: Option<String> = conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0))
            .optional()?;
        v.map(|v| serde_json::from_str(&v).map_err(StoreError::Json))
            .transpose()
    }

    pub fn set_setting<T: Serialize>(&self, key: &str, value: &T) -> Result<(), StoreError> {
        let v = serde_json::to_string(value).map_err(StoreError::Json)?;
        self.conn().execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, v],
        )?;
        Ok(())
    }

    pub fn flow_count(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn()
            .query_row("SELECT count(*) FROM flows", [], |r| r.get(0))?)
    }
}

const SUMMARY_COLS: &str = "id, source, started_ms, duration_ms, scheme, host, port, method, path, http_version, \
     status, request_len, response_len, mime, in_scope, edited, error, tags, note, 0";

fn summary_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<FlowSummary> {
    let source: String = r.get(1)?;
    let scheme: String = r.get(4)?;
    let tags: String = r.get(17)?;
    Ok(FlowSummary {
        id: r.get(0)?,
        source: FlowSource::parse(&source).unwrap_or(FlowSource::Proxy),
        started_ms: r.get(2)?,
        duration_ms: r.get(3)?,
        scheme: Scheme::parse(&scheme).unwrap_or(Scheme::Http),
        host: r.get(5)?,
        port: r.get(6)?,
        method: r.get(7)?,
        path: r.get(8)?,
        http_version: r.get(9)?,
        status: r.get(10)?,
        request_len: r.get(11)?,
        response_len: r.get(12)?,
        mime: r.get(13)?,
        in_scope: r.get(14)?,
        edited: r.get(15)?,
        error: r.get(16)?,
        tags: serde_json::from_str(&tags).unwrap_or_default(),
        note: r.get(18)?,
    })
}

fn base_path(path: &str) -> &str {
    let p = path.split(['?', '#']).next().unwrap_or("");
    if p.is_empty() { "/" } else { p }
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

/// Content-addressed, zstd-compressed body storage. Identical bodies (the same script on every page) are kept
/// once.
fn put_blob(tx: &rusqlite::Transaction<'_>, data: &[u8]) -> Result<Vec<u8>, StoreError> {
    let hash = Sha256::digest(data).to_vec();
    let exists: bool = tx
        .query_row("SELECT 1 FROM blobs WHERE hash = ?1", [&hash], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    if !exists {
        let compressed = zstd::encode_all(data, 3).map_err(StoreError::Compress)?;
        tx.execute(
            "INSERT INTO blobs (hash, size, data) VALUES (?1, ?2, ?3)",
            params![hash, data.len() as i64, compressed],
        )?;
    }
    Ok(hash)
}

fn get_blob(conn: &Connection, hash: &[u8]) -> Result<Vec<u8>, StoreError> {
    let (size, data): (i64, Vec<u8>) =
        conn.query_row("SELECT size, data FROM blobs WHERE hash = ?1", [hash], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let size = u64::try_from(size).map_err(|_| StoreError::Untrusted("negative blob size".into()))?;
    bounded_decode(&data, MAX_BLOB, Some(size))
}

/// What gets indexed for search: the request (head and text body) and the response (head and decoded text
/// body), capped.
fn index_text(f: &NewFlow, resp: Option<&RawResponse>) -> String {
    let mut out = String::new();
    let mut push = |bytes: &[u8]| {
        if out.len() < INDEX_TEXT_LIMIT {
            let room = INDEX_TEXT_LIMIT - out.len();
            let s = String::from_utf8_lossy(&bytes[..bytes.len().min(room)]);
            out.push_str(&s);
            out.push('\n');
        }
    };
    match RawRequest::parse(&f.request) {
        Ok(r) => {
            push(format!("{} {} {}\n", r.method, r.target, r.version).as_bytes());
            for (n, v) in &r.headers {
                push(format!("{n}: {}", String::from_utf8_lossy(v)).as_bytes());
            }
            if is_text(r.header_str("content-type")) {
                push(&r.body);
            }
        }
        Err(_) => push(&f.request),
    }
    if let Some(r) = resp {
        push(format!("{} {} {}", r.version, r.status, r.reason).as_bytes());
        for (n, v) in &r.headers {
            push(format!("{n}: {}", String::from_utf8_lossy(v)).as_bytes());
        }
        let ct = r
            .header("content-type")
            .map(|v| String::from_utf8_lossy(v).to_string());
        if is_text(ct.as_deref()) {
            let ce = r
                .header("content-encoding")
                .map(|v| String::from_utf8_lossy(v).to_string());
            match codec::decode(ce.as_deref(), &r.body, INDEX_TEXT_LIMIT) {
                codec::Decoded::Plain => push(&r.body),
                codec::Decoded::Ok { data, .. } => push(&data),
                _ => {}
            }
        }
    }
    out
}

fn is_text(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else { return true };
    let ct = ct.to_ascii_lowercase();
    ct.starts_with("text/")
        || [
            "json",
            "xml",
            "javascript",
            "x-www-form-urlencoded",
            "graphql",
            "yaml",
            "csv",
        ]
        .iter()
        .any(|t| ct.contains(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(p: &Project, host: &str, path: &str, status: u16, body: &str) -> NewFlow {
        NewFlow {
            id: p.next_flow_id(),
            source: FlowSource::Proxy,
            started_ms: 1,
            duration_ms: Some(5),
            scheme: Scheme::Https,
            host: host.into(),
            port: 443,
            method: "GET".into(),
            path: path.into(),
            http_version: "HTTP/1.1".into(),
            status: Some(status),
            in_scope: host.ends_with("in.test"),
            edited: false,
            error: None,
            request: format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes(),
            original_request: None,
            response: Some(
                format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .into_bytes(),
            ),
            original_response: None,
            response_truncated: false,
        }
    }

    #[test]
    fn write_list_filter_get_delete() {
        let p = Project::open_in_memory().unwrap();
        let a = flow(&p, "a.in.test", "/login?x=1", 200, "<p>secret-token-123</p>");
        let b = flow(&p, "b.out.test", "/img/logo.png", 404, "nope");
        let c = flow(&p, "a.in.test", "/login", 302, "same");
        p.write_batch(&[a.clone(), b.clone(), c.clone()], &[]).unwrap();
        assert_eq!(p.flow_count().unwrap(), 3);

        let all = p.list_flows(&FlowFilter::default()).unwrap();
        assert_eq!(
            all.iter().map(|f| f.id).collect::<Vec<_>>(),
            vec![c.id, b.id, a.id]
        );
        assert_eq!(all[0].mime.as_deref(), Some("text/html"));

        let hits = p
            .list_flows(&FlowFilter {
                text: Some("token-123".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, a.id);
        let scoped = p
            .list_flows(&FlowFilter {
                in_scope_only: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(scoped.len(), 2);
        let no_png = p
            .list_flows(&FlowFilter {
                hide_extensions: Some(vec!["png".into()]),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(no_png.len(), 2);
        let errs = p
            .list_flows(&FlowFilter {
                status_min: Some(400),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(errs.len(), 1);
        // A quote or SQL in the search box is just text.
        p.list_flows(&FlowFilter {
            text: Some("\"') OR 1=1 --".into()),
            ..Default::default()
        })
        .unwrap();

        let d = p.get_flow(a.id).unwrap().unwrap();
        assert_eq!(d.request, a.request);
        assert_eq!(d.response, a.response);

        let site = p.site_map(Some("a.in.test")).unwrap();
        assert_eq!(site.len(), 1, "query strings collapse into one site-map path");
        assert_eq!(site[0].count, 2);
        assert_eq!(site[0].last_status, Some(302));

        assert!(
            p.set_annotations(a.id, Some(&["auth".into()]), Some("check this"))
                .unwrap()
        );
        let d = p.get_flow(a.id).unwrap().unwrap();
        assert_eq!(d.summary.tags, vec!["auth"]);
        assert_eq!(d.summary.note.as_deref(), Some("check this"));

        assert_eq!(p.delete_flows(&[a.id, b.id]).unwrap(), 2);
        assert!(p.get_flow(a.id).unwrap().is_none());
        assert_eq!(
            p.list_flows(&FlowFilter {
                text: Some("token-123".into()),
                ..Default::default()
            })
            .unwrap()
            .len(),
            0
        );
    }

    #[test]
    fn ids_continue_after_reopen_and_settings_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.bosun");
        let id = {
            let p = Project::open(&path).unwrap();
            let f = flow(&p, "x.test", "/", 200, "");
            p.write_batch(std::slice::from_ref(&f), &[]).unwrap();
            p.set_setting("scope", &vec!["a"]).unwrap();
            f.id
        };
        let p = Project::open(&path).unwrap();
        assert!(p.next_flow_id() > id);
        assert_eq!(
            p.setting::<Vec<String>>("scope").unwrap(),
            Some(vec!["a".to_string()])
        );
    }

    #[test]
    fn websocket_messages_round_trip() {
        let p = Project::open_in_memory().unwrap();
        let f = flow(&p, "ws.test", "/socket", 101, "");
        let msg = NewWsMessage {
            flow_id: f.id,
            time_ms: 2,
            direction: Direction::ServerToClient,
            opcode: 1,
            payload: b"{\"hi\":1}".to_vec(),
            truncated: false,
        };
        p.write_batch(
            std::slice::from_ref(&f),
            &[
                msg.clone(),
                NewWsMessage {
                    direction: Direction::ClientToServer,
                    ..msg
                },
            ],
        )
        .unwrap();
        let got = p.ws_messages(f.id, None, 10).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].direction, Direction::ServerToClient);
        assert_eq!(got[1].payload, b"{\"hi\":1}");
        assert_eq!(p.ws_messages(f.id, Some(got[0].id), 10).unwrap().len(), 1);
    }

    fn raw(path: &Path) -> Connection {
        Connection::open(path).unwrap()
    }

    #[test]
    fn a_zstd_bomb_in_a_blob_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.bosun");
        let hash = {
            let p = Project::open(&path).unwrap();
            let f = flow(&p, "a.test", "/", 200, "hello");
            let id = f.id;
            p.write_batch(&[f], &[]).unwrap();
            p.get_flow(id).unwrap().unwrap();
            let c = raw(&path);
            c.query_row("SELECT req_blob FROM flows", [], |r| r.get::<_, Vec<u8>>(0))
                .unwrap()
        };
        // 200 MiB of zeros compresses to a few KiB; claim it is small.
        let bomb = zstd::encode_all(std::io::repeat(0).take(200 * 1024 * 1024), 3).unwrap();
        assert!(bomb.len() < 64 * 1024);
        let c = raw(&path);
        c.execute(
            "UPDATE blobs SET data = ?1, size = 10 WHERE hash = ?2",
            params![bomb, hash],
        )
        .unwrap();
        drop(c);
        let p = Project::open(&path).unwrap();
        assert!(matches!(p.get_flow(1).unwrap_err(), StoreError::Compress(_)));
        // Claiming an enormous size is refused before decoding anything.
        raw(&path)
            .execute("UPDATE blobs SET size = 9000000000", [])
            .unwrap();
        assert!(matches!(p.get_flow(1).unwrap_err(), StoreError::Compress(_)));
        // A size that disagrees with the data is corruption too.
        let ok = zstd::encode_all(&b"hello"[..], 3).unwrap();
        raw(&path)
            .execute("UPDATE blobs SET data = ?1, size = 99", [ok])
            .unwrap();
        assert!(matches!(p.get_flow(1).unwrap_err(), StoreError::Compress(_)));
    }

    #[test]
    fn a_zstd_bomb_in_a_websocket_payload_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.bosun");
        {
            let p = Project::open(&path).unwrap();
            let f = flow(&p, "a.test", "/ws", 101, "");
            let id = f.id;
            let m = NewWsMessage {
                flow_id: id,
                time_ms: 1,
                direction: Direction::ClientToServer,
                opcode: 1,
                payload: b"hi".to_vec(),
                truncated: false,
            };
            p.write_batch(&[f], &[m]).unwrap();
        }
        let bomb = zstd::encode_all(std::io::repeat(0).take(64 * 1024 * 1024), 3).unwrap();
        raw(&path)
            .execute("UPDATE ws_messages SET payload = ?1", [bomb])
            .unwrap();
        let p = Project::open(&path).unwrap();
        assert!(matches!(
            p.ws_messages(1, None, 10).unwrap_err(),
            StoreError::Compress(_)
        ));
    }

    #[test]
    fn files_with_extra_triggers_views_or_tables_are_refused() {
        for (n, sql) in [
            (
                "trigger",
                "CREATE TRIGGER t AFTER INSERT ON settings BEGIN DELETE FROM flows; END",
            ),
            ("view", "CREATE VIEW v AS SELECT * FROM settings"),
            ("table", "CREATE TABLE extra (x)"),
            ("index", "CREATE INDEX extra_idx ON settings(value)"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("p.bosun");
            drop(Project::open(&path).unwrap());
            raw(&path).execute_batch(sql).unwrap();
            let err = Project::open(&path).unwrap_err();
            assert!(matches!(err, StoreError::Untrusted(_)), "{n}: {err}");
        }
    }

    #[test]
    fn a_changed_column_is_refused_and_foreign_databases_are_not_adopted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.bosun");
        drop(Project::open(&path).unwrap());
        raw(&path)
            .execute_batch("ALTER TABLE settings ADD COLUMN sneaky TEXT")
            .unwrap();
        assert!(matches!(
            Project::open(&path).unwrap_err(),
            StoreError::Untrusted(_)
        ));
        // Some other application's database (user_version 0, but has tables) is not a project.
        let other = dir.path().join("other.db");
        raw(&other).execute_batch("CREATE TABLE people (name)").unwrap();
        assert!(matches!(
            Project::open(&other).unwrap_err(),
            StoreError::Untrusted(_)
        ));
    }

    #[test]
    fn a_second_open_of_a_locked_project_is_refused_until_the_first_closes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.bosun");
        let first = Project::open(&path).unwrap();
        let err = Project::open(&path).unwrap_err();
        assert!(matches!(err, StoreError::Locked(_)), "{err}");
        // Windows refuses to read a byte-range-locked file, so only elsewhere can the other pid be named.
        #[cfg(unix)]
        assert!(err.to_string().contains(&std::process::id().to_string()), "{err}");
        drop(first);
        Project::open(&path).unwrap();
    }
}
