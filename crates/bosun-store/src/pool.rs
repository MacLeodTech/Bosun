//! One writer connection plus a few read-only ones.
//!
//! SQLite in WAL mode lets readers run beside a writer, so reading the history never waits for the recorder's
//! batch, and the other way round. A database held in memory (tests) cannot be opened twice, so it falls back to
//! the single connection for reads too.

use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OpenFlags};

use crate::StoreError;

/// Read connections kept open between calls. More can exist at once under load; the extras are closed.
const IDLE_READERS: usize = 4;

#[derive(Debug)]
pub struct Db {
    writer: Mutex<Connection>,
    readers: Option<Readers>,
}

#[derive(Debug)]
pub struct Readers {
    path: PathBuf,
    idle: Mutex<Vec<Connection>>,
    /// Applied to every new read connection (the same hardening the writer has).
    setup: fn(&Connection) -> rusqlite::Result<()>,
}

impl Db {
    /// `path` is the file the writer is open on, or `None` for an in-memory database.
    pub fn new(
        writer: Connection,
        path: Option<PathBuf>,
        setup: fn(&Connection) -> rusqlite::Result<()>,
    ) -> Self {
        Self {
            writer: Mutex::new(writer),
            readers: path.map(|path| Readers {
                path,
                idle: Mutex::new(Vec::new()),
                setup,
            }),
        }
    }

    /// The writer. Hold it only for the SQL itself: do hashing and compression before taking it.
    pub fn write(&self) -> MutexGuard<'_, Connection> {
        self.writer.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A read-only connection (or the writer, for an in-memory database).
    pub fn read(&self) -> Result<Reader<'_>, StoreError> {
        let Some(r) = &self.readers else {
            return Ok(Reader::Shared(self.write()));
        };
        let idle = r.idle.lock().unwrap_or_else(|e| e.into_inner()).pop();
        let conn = match idle {
            Some(c) => c,
            None => {
                let c = Connection::open_with_flags(
                    &r.path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?;
                (r.setup)(&c)?;
                c.pragma_update(None, "query_only", "ON")?;
                c
            }
        };
        Ok(Reader::Pooled {
            conn: Some(conn),
            home: r,
        })
    }
}

pub enum Reader<'a> {
    Pooled {
        conn: Option<Connection>,
        home: &'a Readers,
    },
    Shared(MutexGuard<'a, Connection>),
}

impl Deref for Reader<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        match self {
            // `conn` is only taken in `drop`.
            Reader::Pooled { conn, .. } => conn.as_ref().expect("connection is present until dropped"),
            Reader::Shared(g) => g,
        }
    }
}

impl DerefMut for Reader<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        match self {
            Reader::Pooled { conn, .. } => conn.as_mut().expect("connection is present until dropped"),
            Reader::Shared(g) => g,
        }
    }
}

impl Drop for Reader<'_> {
    fn drop(&mut self) {
        if let Reader::Pooled { conn, home } = self
            && let Some(c) = conn.take()
        {
            let mut idle = home.idle.lock().unwrap_or_else(|e| e.into_inner());
            if idle.len() < IDLE_READERS {
                idle.push(c);
            }
        }
    }
}
