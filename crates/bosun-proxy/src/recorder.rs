//! Writes finished flows to the project on a dedicated thread, in batches, so recording never blocks traffic.

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use bosun_store::{NewFlow, NewWsMessage, Project};

use crate::events::{EventSender, ProxyEvent};

const BATCH: usize = 256;
const LINGER: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub enum Record {
    Flow(Box<NewFlow>),
    Ws(NewWsMessage),
    /// Reply once everything sent before this has been written (tests, shutdown).
    Flush(mpsc::Sender<()>),
}

#[derive(Debug, Clone)]
pub struct Recorder {
    tx: mpsc::Sender<Record>,
}

impl Recorder {
    pub fn start(project: Arc<Project>, events: EventSender) -> Self {
        let (tx, rx) = mpsc::channel::<Record>();
        std::thread::Builder::new()
            .name("bosun-recorder".into())
            .spawn(move || run(project, events, rx))
            .unwrap_or_else(|e| panic!("cannot start the recorder thread: {e}"));
        Self { tx }
    }

    pub fn flow(&self, f: NewFlow) {
        let _ = self.tx.send(Record::Flow(Box::new(f)));
    }

    pub fn ws(&self, m: NewWsMessage) {
        let _ = self.tx.send(Record::Ws(m));
    }

    /// Wait until everything recorded so far is in the database.
    pub fn flush(&self) {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(Record::Flush(tx)).is_ok() {
            let _ = rx.recv_timeout(Duration::from_secs(10));
        }
    }
}

fn run(project: Arc<Project>, events: EventSender, rx: mpsc::Receiver<Record>) {
    let mut flows = Vec::new();
    let mut ws = Vec::new();
    let mut flushes = Vec::new();
    loop {
        let first = match rx.recv() {
            Ok(r) => r,
            Err(_) => return,
        };
        let mut next = Some(first);
        let deadline = std::time::Instant::now() + LINGER;
        while let Some(r) = next.take() {
            match r {
                Record::Flow(f) => flows.push(*f),
                Record::Ws(m) => ws.push(m),
                Record::Flush(t) => flushes.push(t),
            }
            if flows.len() + ws.len() >= BATCH {
                break;
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            next = rx.recv_timeout(left).ok();
        }
        // WebSocket messages refer to their handshake flow, so make sure it's written first even if the
        // handshake record and the messages arrive in different batches (it is always sent first).
        if let Err(e) = project.write_batch(&flows, &ws) {
            tracing::error!(error = %e, flows = flows.len(), "failed to write history");
        } else if events.receiver_count() > 0 {
            let ids: Vec<_> = flows.iter().map(|f| f.id).collect();
            if let Ok(sums) = project.summaries(&ids) {
                for s in sums {
                    let _ = events.send(ProxyEvent::Flow { flow: s });
                }
            }
            for m in &ws {
                let _ = events.send(ProxyEvent::WsMessage {
                    flow_id: m.flow_id,
                    direction: m.direction,
                    opcode: m.opcode,
                    len: m.payload.len(),
                });
            }
        }
        flows.clear();
        ws.clear();
        for f in flushes.drain(..) {
            let _ = f.send(());
        }
    }
}
