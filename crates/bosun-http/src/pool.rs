//! Connections kept for reuse.
//!
//! Idle HTTP/1.1 connections wait here between requests; a shared HTTP/2 connection (see [`crate::mux`]) is
//! kept per target. A connection is only handed out for the key it was made for, only if its address is one the
//! gate has just pinned for the name (so a name that moved does not reach an old connection), and only if it is
//! still alive.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bosun_model::{Scheme, Target};
use bosun_proxy::upstream::Registration;
use tokio::io::AsyncReadExt;

use crate::{Io, Opened, TlsInfo, mux};

/// Idle connections kept per target.
const MAX_IDLE_PER_KEY: usize = 4;
/// Idle connections kept in all.
const MAX_IDLE_TOTAL: usize = 64;
/// An idle connection older than this is dropped, not reused.
const IDLE_TTL: Duration = Duration::from_secs(30);
/// A connection is retired after this many requests.
const MAX_USES: u32 = 200;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    scheme: Scheme,
    host: String,
    port: u16,
    /// Certificate checking is part of the identity: a connection made without it must not serve a send
    /// that asked for it.
    verify: bool,
}

impl Key {
    pub fn new(t: &Target, verify: bool) -> Self {
        Self {
            scheme: t.scheme,
            host: t.host.to_ascii_lowercase(),
            port: t.port,
            verify,
        }
    }
}

pub(crate) struct Idle {
    pub io: Box<dyn Io>,
    pub reg: Registration,
    pub peer: SocketAddr,
    pub tls: Option<TlsInfo>,
    pub uses: u32,
    since: Instant,
}

type Slot = Arc<tokio::sync::Mutex<Option<Arc<mux::Conn>>>>;

#[derive(Default)]
pub(crate) struct Pool {
    idle: Mutex<HashMap<Key, Vec<Idle>>>,
    h2: Mutex<HashMap<Key, Slot>>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool").finish_non_exhaustive()
    }
}

impl Pool {
    /// A pooled connection for `key` whose address is in `addrs`, and that is still open.
    pub async fn take_idle(&self, key: &Key, addrs: &[SocketAddr]) -> Option<Idle> {
        loop {
            let cand = {
                let mut m = self.idle.lock().unwrap_or_else(|e| e.into_inner());
                let v = m.get_mut(key)?;
                v.retain(|i| i.since.elapsed() < IDLE_TTL);
                let pos = v.iter().rposition(|i| addrs.contains(&i.peer))?;
                v.remove(pos)
            };
            let mut cand = cand;
            // Alive means nothing to read yet. An end of stream, an error or unexpected data means it is not.
            let mut b = [0u8; 1];
            if tokio::time::timeout(Duration::ZERO, cand.io.read(&mut b)).await.is_err() {
                return Some(cand);
            }
        }
    }

    /// Put a connection that the last exchange left clean back for the next send.
    pub fn put_idle(&self, o: Opened) {
        if o.uses >= MAX_USES {
            return;
        }
        let mut m = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let total: usize = m.values().map(Vec::len).sum();
        let v = m.entry(o.key).or_default();
        if v.len() >= MAX_IDLE_PER_KEY || total >= MAX_IDLE_TOTAL {
            return;
        }
        v.push(Idle {
            io: o.io,
            reg: o._reg,
            peer: o.ex.peer,
            tls: o.ex.tls,
            uses: o.uses,
            since: Instant::now(),
        });
    }

    /// The slot that serializes making the shared HTTP/2 connection for `key`.
    pub fn h2_slot(&self, key: &Key) -> Slot {
        self.h2
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .or_default()
            .clone()
    }

    pub fn clear(&self) {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).clear();
        // Dropping the handles ends each connection's driver once its streams are done.
        self.h2.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub fn counts(&self) -> (usize, usize) {
        let idle = self.idle.lock().unwrap_or_else(|e| e.into_inner()).values().map(Vec::len).sum();
        let h2 = self
            .h2
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|s| s.try_lock().is_ok_and(|g| g.as_ref().is_some_and(|c| c.is_alive())))
            .count();
        (idle, h2)
    }
}

/// Does this raw request ask for the connection to be closed after it?
pub(crate) fn request_closes(raw: &[u8]) -> bool {
    let end = crate::wire::head_end(raw).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end])
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .any(|(n, v)| n.trim().eq_ignore_ascii_case("connection") && v.to_ascii_lowercase().contains("close"))
}

#[cfg(test)]
mod tests {
    use super::request_closes;

    #[test]
    fn a_close_request_is_recognised() {
        assert!(request_closes(b"GET / HTTP/1.1\r\nHost: a\r\nconnection: Keep-Alive, close\r\n\r\n"));
        assert!(!request_closes(b"GET / HTTP/1.1\r\nHost: a\r\nX-Connection: close\r\n\r\n"));
        assert!(!request_closes(b"GET /close HTTP/1.1\r\nHost: a\r\n\r\n"));
    }
}
