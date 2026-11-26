//! Caps on concurrent connections, shared by the proxy and API listeners.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// At most `max` connections at once. Past that, new connections are closed straight away (existing ones keep
/// working) and the refusals are logged at most every ten seconds, with a count.
#[derive(Debug, Clone)]
pub struct ConnLimit {
    name: &'static str,
    sem: Arc<Semaphore>,
    max: usize,
    log: Arc<Mutex<(Instant, u64)>>,
    refused: Arc<AtomicU64>,
}

impl ConnLimit {
    pub fn new(name: &'static str, max: usize) -> Self {
        let max = max.max(1);
        Self {
            name,
            sem: Arc::new(Semaphore::new(max)),
            max,
            log: Arc::new(Mutex::new((Instant::now() - Duration::from_secs(60), 0))),
            refused: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Connections turned away so far (they never become flows, so History does not show them).
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// A permit to hold for the life of the connection, or `None` when the limit is reached.
    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        match self.sem.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                self.refused.fetch_add(1, Ordering::Relaxed);
                let mut l = self.log.lock().unwrap_or_else(|e| e.into_inner());
                l.1 += 1;
                if l.0.elapsed() >= Duration::from_secs(10) {
                    tracing::warn!(
                        listener = self.name,
                        limit = self.max,
                        refused = l.1,
                        "connection limit reached; refusing new connections"
                    );
                    *l = (Instant::now(), 0);
                }
                None
            }
        }
    }
}
