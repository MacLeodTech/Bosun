use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use bosun_model::{Direction, FlowId, FlowSummary};
use serde::Serialize;

use crate::intercept::InterceptSummary;

/// Events the proxy publishes for front ends (sent over the API's event stream).
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProxyEvent {
    /// A flow was written to history.
    Flow {
        flow: FlowSummary,
    },
    WsMessage {
        flow_id: FlowId,
        direction: Direction,
        opcode: u8,
        len: usize,
    },
    InterceptQueued {
        item: InterceptSummary,
    },
    InterceptResolved {
        id: u64,
    },
    /// A message could not be held (queue full) and was refused.
    InterceptRefused {
        reason: String,
    },
    /// A batch of history could not be written even after a retry, and is lost.
    RecorderFailed {
        lost: u64,
        error: String,
    },
    InterceptState {
        requests: bool,
        responses: bool,
    },
    /// Another project is open now: everything a client holds (history, scope, rules, held messages) is from
    /// the old one, so it should fetch it all again. `name` is empty for the temporary project.
    ProjectSwitched {
        name: Option<String>,
        temporary: bool,
    },
    /// An Intruder attack started, moved on or ended.
    IntruderState {
        attack_id: i64,
        /// `running`, `completed`, `stopped`, `failed` or `interrupted`.
        state: String,
        total: u64,
        done: u64,
        skipped: u64,
        errors: u64,
        error: Option<String>,
    },
    /// One request of an Intruder attack finished. (The same fields as a stored result.)
    IntruderResult {
        attack_id: i64,
        index: u64,
        position: Option<u32>,
        payloads: Vec<String>,
        status: Option<u16>,
        length: u64,
        time_ms: u64,
        flow_id: Option<i64>,
        error: Option<String>,
        matches: Vec<bool>,
        extracts: Vec<Option<String>>,
        attempts: u32,
    },
}

/// An event with its place in the stream.
#[derive(Debug, Clone, Serialize)]
pub struct Sequenced {
    /// 1, 2, 3 and so on within one run of the engine.
    pub seq: u64,
    #[serde(flatten)]
    pub event: ProxyEvent,
}

pub type EventReceiver = tokio::sync::broadcast::Receiver<Sequenced>;

/// The engine's event stream: every event gets a sequence number and is also kept in a ring of recent ones, so a
/// client that was away can ask for what it missed instead of reloading everything.
#[derive(Debug, Clone)]
pub struct EventBus {
    inner: Arc<BusInner>,
}

#[derive(Debug)]
struct BusInner {
    tx: tokio::sync::broadcast::Sender<Sequenced>,
    ring: Mutex<Ring>,
}

#[derive(Debug)]
struct Ring {
    /// Names this stretch of the stream: positions from another one mean nothing here. A new one starts with
    /// each run of the engine, and again whenever its data is replaced (a project switch).
    epoch: String,
    next: u64,
    cap: usize,
    buf: VecDeque<Sequenced>,
}

/// What a client that was at `since` gets on reconnecting.
#[derive(Debug)]
pub enum Resume {
    /// These events happened since, in order; then the receiver carries on from the next one.
    Replay {
        missed: Vec<Sequenced>,
        rx: EventReceiver,
    },
    /// Too much has happened (or it is another run): reload, then carry on from the receiver.
    Reload { rx: EventReceiver },
}

impl EventBus {
    /// `capacity` is both the live channel's size and how many recent events are kept for replay.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let (tx, _) = tokio::sync::broadcast::channel(capacity);
        Self {
            inner: Arc::new(BusInner {
                tx,
                ring: Mutex::new(Ring {
                    epoch: new_epoch(),
                    next: 1,
                    cap: capacity,
                    buf: VecDeque::new(),
                }),
            }),
        }
    }

    /// A bus and a receiver on it (what tests want).
    pub fn channel(capacity: usize) -> (Self, EventReceiver) {
        let b = Self::new(capacity);
        let rx = b.subscribe();
        (b, rx)
    }

    pub fn epoch(&self) -> String {
        self.ring().epoch.clone()
    }

    /// Start a new epoch: what clients hold from before (positions, replayable events) no longer applies, so
    /// they are told to reload. Numbers carry on, so connections that are open see no gap or repeat.
    pub fn new_epoch(&self) {
        let mut ring = self.ring();
        ring.epoch = new_epoch();
        ring.buf.clear();
    }

    /// The number of the latest event, 0 before the first.
    pub fn current_seq(&self) -> u64 {
        self.ring().next - 1
    }

    fn ring(&self) -> std::sync::MutexGuard<'_, Ring> {
        self.inner.ring.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Publish an event. Returns its sequence number.
    pub fn send(&self, event: ProxyEvent) -> u64 {
        // Numbering, keeping and broadcasting happen under one lock, so the order everyone sees is the same.
        let mut ring = self.ring();
        let seq = ring.next;
        ring.next += 1;
        let ev = Sequenced { seq, event };
        if ring.buf.len() >= ring.cap {
            ring.buf.pop_front();
        }
        ring.buf.push_back(ev.clone());
        let _ = self.inner.tx.send(ev);
        seq
    }

    /// Events from now on.
    pub fn subscribe(&self) -> EventReceiver {
        let _hold = self.ring();
        self.inner.tx.subscribe()
    }

    /// Everything after `since`, then live events, with nothing missed or doubled in between. A position from
    /// another epoch is as good as too old.
    pub fn resume_in(&self, epoch: &str, since: u64) -> Resume {
        let ring = self.ring();
        if ring.epoch != epoch {
            return Resume::Reload {
                rx: self.inner.tx.subscribe(),
            };
        }
        Self::resume_locked(&ring, &self.inner.tx, since)
    }

    /// As [`EventBus::resume_in`], for a position known to be in the current epoch.
    pub fn resume(&self, since: u64) -> Resume {
        let ring = self.ring();
        Self::resume_locked(&ring, &self.inner.tx, since)
    }

    fn resume_locked(ring: &Ring, tx: &tokio::sync::broadcast::Sender<Sequenced>, since: u64) -> Resume {
        let rx = tx.subscribe();
        let latest = ring.next - 1;
        if since == latest {
            return Resume::Replay {
                missed: Vec::new(),
                rx,
            };
        }
        let oldest = ring.buf.front().map_or(ring.next, |e| e.seq);
        if since > latest || since + 1 < oldest {
            return Resume::Reload { rx };
        }
        let missed = ring.buf.iter().filter(|e| e.seq > since).cloned().collect();
        Resume::Replay { missed, rx }
    }
}

fn new_epoch() -> String {
    let mut e = [0u8; 8];
    rand::fill(&mut e);
    e.iter().map(|b| format!("{b:02x}")).collect()
}

pub type EventSender = EventBus;

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(n: u64) -> ProxyEvent {
        ProxyEvent::InterceptResolved { id: n }
    }

    fn ids(v: &[Sequenced]) -> Vec<u64> {
        v.iter().map(|e| e.seq).collect()
    }

    #[test]
    fn events_are_numbered_from_one_and_the_latest_is_known() {
        let (bus, mut rx) = EventBus::channel(8);
        assert_eq!(bus.current_seq(), 0);
        assert_eq!(bus.send(ev(10)), 1);
        assert_eq!(bus.send(ev(11)), 2);
        assert_eq!(bus.current_seq(), 2);
        assert_eq!(rx.try_recv().unwrap().seq, 1);
        assert_eq!(rx.try_recv().unwrap().seq, 2);
    }

    #[test]
    fn the_wire_form_carries_the_number_beside_the_type() {
        let e = Sequenced { seq: 7, event: ev(3) };
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"seq":7,"type":"intercept_resolved","id":3}"#
        );
    }

    #[test]
    fn a_client_that_was_away_gets_exactly_what_it_missed() {
        let bus = EventBus::new(8);
        for i in 0..5 {
            bus.send(ev(i));
        }
        let Resume::Replay { missed, mut rx } = bus.resume(2) else {
            panic!("should replay")
        };
        assert_eq!(ids(&missed), [3, 4, 5]);
        // Nothing is doubled: the next live event is the one after the replay.
        bus.send(ev(9));
        assert_eq!(rx.try_recv().unwrap().seq, 6);
        // Up to date: nothing to replay.
        let Resume::Replay { missed, .. } = bus.resume(6) else {
            panic!()
        };
        assert!(missed.is_empty());
        // From before the first event ever.
        let Resume::Replay { missed, .. } = bus.resume(0) else {
            panic!()
        };
        assert_eq!(ids(&missed), [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn too_old_or_from_the_future_means_reload() {
        let bus = EventBus::new(4);
        for i in 0..10 {
            bus.send(ev(i));
        }
        // The ring holds 7..=10.
        assert!(matches!(bus.resume(2), Resume::Reload { .. }));
        assert!(matches!(bus.resume(5), Resume::Reload { .. }));
        assert!(
            matches!(bus.resume(6), Resume::Replay { .. }),
            "7 is the next one wanted"
        );
        assert!(
            matches!(bus.resume(11), Resume::Reload { .. }),
            "from another run"
        );
    }

    #[test]
    fn nothing_is_lost_or_doubled_while_events_keep_coming() {
        let bus = EventBus::new(10_000);
        let b = bus.clone();
        let writer = std::thread::spawn(move || {
            for i in 0..5_000 {
                b.send(ev(i));
            }
        });
        // Resume at several points while the writer is running; replay then live must be gap-free.
        for _ in 0..50 {
            let since = bus.current_seq() / 2;
            let Resume::Replay { missed, mut rx } = bus.resume(since) else {
                panic!("the ring is large enough")
            };
            let mut seen = ids(&missed);
            while let Ok(e) = rx.try_recv() {
                seen.push(e.seq);
            }
            let want: Vec<u64> = (since + 1..since + 1 + seen.len() as u64).collect();
            assert_eq!(seen, want, "since {since}");
        }
        writer.join().unwrap();
    }

    #[test]
    fn each_run_has_its_own_name() {
        assert_ne!(EventBus::new(1).epoch(), EventBus::new(1).epoch());
        assert_eq!(EventBus::new(1).epoch().len(), 16);
    }
}
