//! A byte budget shared by everything that buffers traffic: request bodies, buffered responses, the recorder
//! queue. Memory is reserved before it is allocated; when the budget is spent, new work is refused (503)
//! instead of the process being killed.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Buffering one message holds roughly this many copies at once (the body, the serialised message, and what is
/// queued for the recorder or the intercept queue). Reservations are made for the whole amount.
pub const COPY_FACTOR: usize = 2;

#[derive(Debug)]
struct Inner {
    cap: usize,
    used: AtomicUsize,
    refused: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct MemoryBudget {
    inner: Arc<Inner>,
}

/// Bytes held against the budget; released when dropped.
#[derive(Debug)]
pub struct Reservation {
    budget: Arc<Inner>,
    bytes: usize,
}

impl MemoryBudget {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                cap,
                used: AtomicUsize::new(0),
                refused: AtomicU64::new(0),
            }),
        }
    }

    /// The default: half the container's memory limit when there is one (the rest is for SQLite, the UI and the
    /// allocator's slack), otherwise 1 GiB.
    pub fn default_cap() -> usize {
        cgroup_limit().map_or(1 << 30, |l| (l / 2).max(64 << 20))
    }

    pub fn reserve(&self, bytes: usize) -> Option<Reservation> {
        let mut cur = self.inner.used.load(Ordering::Relaxed);
        loop {
            if cur.saturating_add(bytes) > self.inner.cap {
                self.inner.refused.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            match self
                .inner
                .used
                .compare_exchange_weak(cur, cur + bytes, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => {
                    return Some(Reservation {
                        budget: self.inner.clone(),
                        bytes,
                    });
                }
                Err(c) => cur = c,
            }
        }
    }

    pub fn used(&self) -> usize {
        self.inner.used.load(Ordering::Relaxed)
    }

    pub fn cap(&self) -> usize {
        self.inner.cap
    }

    /// Reservations refused so far.
    pub fn refused(&self) -> u64 {
        self.inner.refused.load(Ordering::Relaxed)
    }
}

impl Reservation {
    /// Reserve `more` additional bytes under the same reservation. False (and nothing changes) if over budget.
    pub fn grow(&mut self, more: usize, from: &MemoryBudget) -> bool {
        match from.reserve(more) {
            Some(mut extra) => {
                self.bytes += extra.bytes;
                extra.bytes = 0; // now owned by `self`
                true
            }
            None => false,
        }
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// The container's memory limit in bytes, if one is set (cgroup v2, then v1).
fn cgroup_limit() -> Option<usize> {
    for path in [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ] {
        if let Ok(s) = std::fs::read_to_string(path)
            && let Ok(n) = s.trim().parse::<u64>()
            // cgroup v1 reports "no limit" as a huge number.
            && n < (1u64 << 52)
        {
            return usize::try_from(n).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_are_released_and_over_budget_is_refused() {
        let b = MemoryBudget::new(100);
        let a = b.reserve(60).unwrap();
        assert!(b.reserve(60).is_none());
        assert_eq!(b.refused(), 1);
        let mut c = b.reserve(40).unwrap();
        assert_eq!(b.used(), 100);
        assert!(!c.grow(1, &b));
        drop(a);
        assert!(c.grow(50, &b));
        assert_eq!(c.bytes(), 90);
        assert_eq!(b.used(), 90);
        drop(c);
        assert_eq!(b.used(), 0);
    }
}
