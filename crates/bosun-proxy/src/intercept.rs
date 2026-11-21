//! The intercept queue: requests and responses held until the user forwards, edits or drops them.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bosun_model::FlowId;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::events::{EventSender, ProxyEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Request,
    Response,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterceptSummary {
    pub id: u64,
    pub flow_id: FlowId,
    pub phase: Phase,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub queued_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterceptItem {
    #[serde(flatten)]
    pub summary: InterceptSummary,
    /// The message as HTTP/1.1-style text (base64 so binary bodies survive).
    #[serde(with = "bosun_model::b64")]
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Decision {
    /// Forward, optionally with an edited message.
    Forward {
        #[serde(default, with = "bosun_model::b64_opt")]
        raw: Option<Vec<u8>>,
    },
    Drop,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct InterceptSettings {
    pub requests: bool,
    pub responses: bool,
    /// Only hold in-scope traffic (on by default: intercepting every analytics beacon is useless).
    pub in_scope_only: bool,
}

#[derive(Debug)]
pub struct InterceptController {
    requests: AtomicBool,
    responses: AtomicBool,
    in_scope_only: AtomicBool,
    next_id: AtomicU64,
    pending: Mutex<BTreeMap<u64, (InterceptItem, oneshot::Sender<Decision>)>>,
    events: EventSender,
}

impl InterceptController {
    pub fn new(events: EventSender) -> Self {
        Self {
            requests: AtomicBool::new(false),
            responses: AtomicBool::new(false),
            in_scope_only: AtomicBool::new(true),
            next_id: AtomicU64::new(1),
            pending: Mutex::new(BTreeMap::new()),
            events,
        }
    }

    pub fn settings(&self) -> InterceptSettings {
        InterceptSettings {
            requests: self.requests.load(Ordering::SeqCst),
            responses: self.responses.load(Ordering::SeqCst),
            in_scope_only: self.in_scope_only.load(Ordering::SeqCst),
        }
    }

    /// Change what is intercepted. Turning interception off releases everything held, unedited.
    pub fn set(&self, s: InterceptSettings) {
        self.requests.store(s.requests, Ordering::SeqCst);
        self.responses.store(s.responses, Ordering::SeqCst);
        self.in_scope_only.store(s.in_scope_only, Ordering::SeqCst);
        if !s.requests || !s.responses {
            let release: Vec<u64> = self
                .lock()
                .iter()
                .filter(|(_, (item, _))| match item.summary.phase {
                    Phase::Request => !s.requests,
                    Phase::Response => !s.responses,
                })
                .map(|(id, _)| *id)
                .collect();
            for id in release {
                self.resolve(id, Decision::Forward { raw: None });
            }
        }
        let _ = self.events.send(ProxyEvent::InterceptState {
            requests: s.requests,
            responses: s.responses,
        });
    }

    pub fn should_hold(&self, phase: Phase, in_scope: bool) -> bool {
        let on = match phase {
            Phase::Request => self.requests.load(Ordering::SeqCst),
            Phase::Response => self.responses.load(Ordering::SeqCst),
        };
        on && (in_scope || !self.in_scope_only.load(Ordering::SeqCst))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, (InterceptItem, oneshot::Sender<Decision>)>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Hold a message until the user decides. If the controller goes away the message is forwarded.
    pub async fn hold(
        &self,
        flow_id: FlowId,
        phase: Phase,
        method: &str,
        url: &str,
        status: Option<u16>,
        raw: Vec<u8>,
    ) -> Decision {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let summary = InterceptSummary {
            id,
            flow_id,
            phase,
            method: method.to_string(),
            url: url.to_string(),
            status,
            queued_ms: bosun_model::now_ms(),
        };
        let (tx, rx) = oneshot::channel();
        self.lock().insert(
            id,
            (
                InterceptItem {
                    summary: summary.clone(),
                    raw,
                },
                tx,
            ),
        );
        let _ = self.events.send(ProxyEvent::InterceptQueued { item: summary });
        let guard = Cleanup { ctl: self, id };
        let d = rx.await.unwrap_or(Decision::Forward { raw: None });
        drop(guard);
        d
    }

    pub fn list(&self) -> Vec<InterceptSummary> {
        self.lock().values().map(|(i, _)| i.summary.clone()).collect()
    }

    pub fn get(&self, id: u64) -> Option<InterceptItem> {
        self.lock().get(&id).map(|(i, _)| i.clone())
    }

    pub fn resolve(&self, id: u64, d: Decision) -> bool {
        let entry = self.lock().remove(&id);
        match entry {
            Some((_, tx)) => {
                let _ = tx.send(d);
                let _ = self.events.send(ProxyEvent::InterceptResolved { id });
                true
            }
            None => false,
        }
    }

    pub fn forward_all(&self) -> usize {
        let ids: Vec<u64> = self.lock().keys().copied().collect();
        ids.into_iter()
            .filter(|id| self.resolve(*id, Decision::Forward { raw: None }))
            .count()
    }
}

/// Removes the queue entry if the waiting connection goes away (client disconnected) before a decision.
struct Cleanup<'a> {
    ctl: &'a InterceptController,
    id: u64,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if self.ctl.lock().remove(&self.id).is_some() {
            let _ = self
                .ctl
                .events
                .send(ProxyEvent::InterceptResolved { id: self.id });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn hold_resolve_and_release_on_disable() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let ctl = Arc::new(InterceptController::new(tx));
        ctl.set(InterceptSettings {
            requests: true,
            responses: false,
            in_scope_only: true,
        });
        assert!(ctl.should_hold(Phase::Request, true));
        assert!(!ctl.should_hold(Phase::Request, false));
        assert!(!ctl.should_hold(Phase::Response, true));

        let c = ctl.clone();
        let h = tokio::spawn(async move {
            c.hold(1, Phase::Request, "GET", "http://a/", None, b"x".to_vec())
                .await
        });
        while ctl.list().is_empty() {
            tokio::task::yield_now().await;
        }
        let id = ctl.list()[0].id;
        assert!(ctl.resolve(
            id,
            Decision::Forward {
                raw: Some(b"y".to_vec())
            }
        ));
        assert_eq!(
            h.await.unwrap(),
            Decision::Forward {
                raw: Some(b"y".to_vec())
            }
        );
        assert!(!ctl.resolve(id, Decision::Drop), "already resolved");

        let c = ctl.clone();
        let h =
            tokio::spawn(async move { c.hold(2, Phase::Request, "GET", "http://a/", None, vec![]).await });
        while ctl.list().is_empty() {
            tokio::task::yield_now().await;
        }
        ctl.set(InterceptSettings::default());
        assert_eq!(h.await.unwrap(), Decision::Forward { raw: None });
        assert!(ctl.list().is_empty());
    }

    #[tokio::test]
    async fn abandoned_holds_leave_the_queue() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let ctl = Arc::new(InterceptController::new(tx));
        let c = ctl.clone();
        let h = tokio::spawn(async move { c.hold(1, Phase::Request, "GET", "u", None, vec![]).await });
        while ctl.list().is_empty() {
            tokio::task::yield_now().await;
        }
        h.abort();
        let _ = h.await;
        assert!(ctl.list().is_empty());
    }

    #[test]
    fn decisions_parse_from_json() {
        let d: Decision = serde_json::from_str(r#"{"action":"forward","raw":"eA=="}"#).unwrap();
        assert_eq!(
            d,
            Decision::Forward {
                raw: Some(b"x".to_vec())
            }
        );
        let d: Decision = serde_json::from_str(r#"{"action":"forward"}"#).unwrap();
        assert_eq!(d, Decision::Forward { raw: None });
        let d: Decision = serde_json::from_str(r#"{"action":"drop"}"#).unwrap();
        assert_eq!(d, Decision::Drop);
    }
}
