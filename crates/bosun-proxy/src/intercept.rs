//! The intercept queue: requests and responses held until the user forwards, edits or drops them.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use bosun_model::FlowId;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::events::{EventSender, ProxyEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Request,
    Response,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct InterceptSummary {
    pub id: u64,
    pub flow_id: FlowId,
    pub phase: Phase,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub queued_ms: i64,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct InterceptItem {
    #[serde(flatten)]
    pub summary: InterceptSummary,
    /// The message as HTTP/1.1-style text (base64 so binary bodies survive).
    #[serde(with = "bosun_model::b64")]
    #[schema(value_type = String, format = Byte)]
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, utoipa::ToSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Decision {
    /// Forward, optionally with an edited message.
    Forward {
        #[serde(default, with = "bosun_model::b64_opt")]
        #[schema(value_type = Option<String>, format = Byte)]
        raw: Option<Vec<u8>>,
    },
    Drop,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct InterceptSettings {
    pub requests: bool,
    pub responses: bool,
    /// Only hold in-scope traffic (on by default: intercepting every analytics beacon is useless).
    pub in_scope_only: bool,
    /// Forward a held message, unedited, after this many seconds (none: hold until decided).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Which responses are held when response interception is on. Every condition that is set must match; an empty
/// filter holds every response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ResponseFilter {
    /// Status codes or classes, such as `404`, `5xx` (any one may match). Empty: any status.
    #[serde(default)]
    pub statuses: Vec<String>,
    /// Substrings of the `Content-Type` (any one may match, case-insensitive). Empty: any type.
    #[serde(default)]
    pub mime_contains: Vec<String>,
    /// A substring that must appear in the response's header lines (case-insensitive).
    #[serde(default)]
    pub header_contains: Option<String>,
    /// A substring that must appear in the response body (the body is buffered to check it).
    #[serde(default)]
    pub body_contains: Option<String>,
    /// Hold only responses whose request was held too.
    #[serde(default)]
    pub only_if_request_held: bool,
}

impl ResponseFilter {
    /// Statuses must be `NNN` or `Nxx`; a filter with a bad entry is refused.
    pub fn validate(&self) -> Result<(), String> {
        for s in &self.statuses {
            let b = s.trim().as_bytes();
            let ok = b.len() == 3
                && b[0].is_ascii_digit()
                && (b[1..].iter().all(u8::is_ascii_digit) || b[1..].eq_ignore_ascii_case(b"xx"));
            if !ok {
                return Err(format!("status {s:?} is not a code (404) or a class (5xx)"));
            }
        }
        for s in self
            .mime_contains
            .iter()
            .chain(&self.header_contains)
            .chain(&self.body_contains)
        {
            if s.len() > 1024 {
                return Err("a filter value is longer than 1024 bytes".into());
            }
        }
        if self.statuses.len() > 64 || self.mime_contains.len() > 64 {
            return Err("too many filter entries (64 at most)".into());
        }
        Ok(())
    }

    fn head_matches(&self, request_held: bool, status: u16, head: &str) -> bool {
        if self.only_if_request_held && !request_held {
            return false;
        }
        if !self.statuses.is_empty() {
            let code = format!("{status:03}");
            let ok = self.statuses.iter().any(|s| {
                let s = s.trim();
                s.len() == 3 && (s == code || s[1..].eq_ignore_ascii_case("xx") && s[..1] == code[..1])
            });
            if !ok {
                return false;
            }
        }
        let lower = head.to_ascii_lowercase();
        if !self.mime_contains.is_empty() {
            let ct = lower
                .lines()
                .find_map(|l| l.strip_prefix("content-type:"))
                .unwrap_or("");
            if !self
                .mime_contains
                .iter()
                .any(|m| ct.contains(&m.to_ascii_lowercase()))
            {
                return false;
            }
        }
        self.header_contains
            .as_ref()
            .is_none_or(|h| lower.contains(&h.to_ascii_lowercase()))
    }
}

/// What the filter says about a response before its body is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RespHold {
    No,
    Yes,
    /// Hold only if the body matches (see [`InterceptController::body_matches`]).
    IfBody,
}

/// The queue is full; the message was not held (and must not be forwarded as if it had been).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

#[derive(Debug)]
pub struct InterceptController {
    timeout_secs: AtomicU64,
    max_items: usize,
    max_bytes: usize,
    queued_bytes: AtomicUsize,
    refused: AtomicU64,
    requests: AtomicBool,
    responses: AtomicBool,
    in_scope_only: AtomicBool,
    filter: std::sync::RwLock<ResponseFilter>,
    next_id: AtomicU64,
    pending: Mutex<BTreeMap<u64, (InterceptItem, oneshot::Sender<Decision>)>>,
    events: EventSender,
}

impl InterceptController {
    pub fn new(events: EventSender) -> Self {
        Self::with_limits(events, 256, 128 * 1024 * 1024)
    }

    pub fn with_limits(events: EventSender, max_items: usize, max_bytes: usize) -> Self {
        Self {
            timeout_secs: AtomicU64::new(0),
            max_items,
            max_bytes,
            queued_bytes: AtomicUsize::new(0),
            refused: AtomicU64::new(0),
            requests: AtomicBool::new(false),
            responses: AtomicBool::new(false),
            in_scope_only: AtomicBool::new(true),
            filter: Default::default(),
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
            timeout_secs: Some(self.timeout_secs.load(Ordering::SeqCst)).filter(|t| *t > 0),
        }
    }

    /// Messages refused because the queue was full.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Bytes currently held.
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes.load(Ordering::Relaxed)
    }

    /// Change what is intercepted. Turning interception off releases everything held, unedited.
    pub fn set(&self, s: InterceptSettings) {
        self.requests.store(s.requests, Ordering::SeqCst);
        self.responses.store(s.responses, Ordering::SeqCst);
        self.in_scope_only.store(s.in_scope_only, Ordering::SeqCst);
        self.timeout_secs
            .store(s.timeout_secs.unwrap_or(0), Ordering::SeqCst);
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

    pub fn response_filter(&self) -> ResponseFilter {
        self.filter.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_response_filter(&self, f: ResponseFilter) {
        *self.filter.write().unwrap_or_else(|e| e.into_inner()) = f;
    }

    /// Whether to hold a response, judged from its head (`head` is the status line and headers as text).
    pub fn response_hold(&self, in_scope: bool, request_held: bool, status: u16, head: &str) -> RespHold {
        if !self.should_hold(Phase::Response, in_scope) {
            return RespHold::No;
        }
        let f = self.filter.read().unwrap_or_else(|e| e.into_inner());
        if !f.head_matches(request_held, status, head) {
            RespHold::No
        } else if f.body_contains.is_some() {
            RespHold::IfBody
        } else {
            RespHold::Yes
        }
    }

    pub fn body_matches(&self, body: &[u8]) -> bool {
        match &self
            .filter
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .body_contains
        {
            Some(n) if !n.is_empty() => body
                .windows(n.len())
                .any(|w| w.eq_ignore_ascii_case(n.as_bytes())),
            _ => true,
        }
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

    /// Hold a message until the user decides (or the timeout passes, which forwards it unedited). If the
    /// controller goes away the message is forwarded. `Err(QueueFull)` when the item or byte cap would be
    /// exceeded: the caller must refuse the message, not forward it.
    pub async fn hold(
        &self,
        flow_id: FlowId,
        phase: Phase,
        method: &str,
        url: &str,
        status: Option<u16>,
        raw: Vec<u8>,
    ) -> Result<Decision, QueueFull> {
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
        let size = raw.len();
        {
            let mut q = self.lock();
            if q.len() >= self.max_items || self.queued_bytes.load(Ordering::SeqCst) + size > self.max_bytes {
                drop(q);
                self.refused.fetch_add(1, Ordering::Relaxed);
                let _ = self.events.send(ProxyEvent::InterceptRefused {
                    reason: "the intercept queue is full; the message was refused (503)".into(),
                });
                return Err(QueueFull);
            }
            self.queued_bytes.fetch_add(size, Ordering::SeqCst);
            q.insert(
                id,
                (
                    InterceptItem {
                        summary: summary.clone(),
                        raw,
                    },
                    tx,
                ),
            );
        }
        let _ = self.events.send(ProxyEvent::InterceptQueued { item: summary });
        let guard = Cleanup { ctl: self, id };
        let timeout = self.timeout_secs.load(Ordering::SeqCst);
        let d = if timeout > 0 {
            tokio::time::timeout(std::time::Duration::from_secs(timeout), rx)
                .await
                .map_or(Decision::Forward { raw: None }, |r| {
                    r.unwrap_or(Decision::Forward { raw: None })
                })
        } else {
            rx.await.unwrap_or(Decision::Forward { raw: None })
        };
        drop(guard);
        Ok(d)
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
            Some((item, tx)) => {
                self.queued_bytes.fetch_sub(item.raw.len(), Ordering::SeqCst);
                let _ = tx.send(d);
                let _ = self.events.send(ProxyEvent::InterceptResolved { id });
                true
            }
            None => false,
        }
    }

    /// Drop everything held (a project switch: those messages belong to the old project's session and nobody
    /// approved forwarding them).
    pub fn drop_all(&self) -> usize {
        let ids: Vec<u64> = self.lock().keys().copied().collect();
        ids.into_iter()
            .filter(|id| self.resolve(*id, Decision::Drop))
            .count()
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
        let removed = self.ctl.lock().remove(&self.id);
        if let Some((item, _)) = removed {
            self.ctl.queued_bytes.fetch_sub(item.raw.len(), Ordering::SeqCst);
            let _ = self
                .ctl
                .events
                .send(ProxyEvent::InterceptResolved { id: self.id });
        }
    }
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    #[test]
    fn filter_matches_status_mime_header() {
        let f = ResponseFilter {
            statuses: vec!["5xx".into(), "404".into()],
            mime_contains: vec!["JSON".into()],
            header_contains: Some("x-debug".into()),
            ..Default::default()
        };
        let head = "HTTP/1.1 500 X\r\nContent-Type: application/json\r\nX-Debug: 1\r\n\r\n";
        assert!(f.head_matches(false, 500, head));
        assert!(f.head_matches(false, 404, head));
        assert!(!f.head_matches(false, 200, head));
        assert!(!f.head_matches(false, 500, &head.replace("json", "html")));
        assert!(!f.head_matches(false, 500, &head.replace("X-Debug", "X-Other")));
        let g = ResponseFilter {
            only_if_request_held: true,
            ..Default::default()
        };
        assert!(!g.head_matches(false, 200, head) && g.head_matches(true, 200, head));
        assert!(
            ResponseFilter {
                statuses: vec!["50".into()],
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(f.validate().is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn drop_all_drops_what_is_held() {
        let (tx, _rx) = crate::events::EventBus::channel(16);
        let ctl = Arc::new(InterceptController::new(tx));
        ctl.set(InterceptSettings {
            requests: true,
            responses: false,
            in_scope_only: false,
            timeout_secs: None,
        });
        let mut held = Vec::new();
        for n in 0..3 {
            let c = ctl.clone();
            held.push(tokio::spawn(async move {
                c.hold(n, Phase::Request, "GET", "http://a/", None, b"x".to_vec())
                    .await
            }));
        }
        while ctl.list().len() < 3 {
            tokio::task::yield_now().await;
        }
        assert_eq!(ctl.drop_all(), 3);
        for h in held {
            assert_eq!(h.await.unwrap().unwrap(), Decision::Drop);
        }
        assert!(ctl.list().is_empty());
        assert_eq!(ctl.drop_all(), 0);
    }

    #[tokio::test]
    async fn hold_resolve_and_release_on_disable() {
        let (tx, _rx) = crate::events::EventBus::channel(16);
        let ctl = Arc::new(InterceptController::new(tx));
        ctl.set(InterceptSettings {
            requests: true,
            responses: false,
            in_scope_only: true,
            timeout_secs: None,
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
            h.await.unwrap().unwrap(),
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
        assert_eq!(h.await.unwrap().unwrap(), Decision::Forward { raw: None });
        assert!(ctl.list().is_empty());
    }

    #[tokio::test]
    async fn abandoned_holds_leave_the_queue() {
        let (tx, _rx) = crate::events::EventBus::channel(16);
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

    #[tokio::test]
    async fn the_queue_has_an_item_cap_a_byte_cap_and_a_timeout() {
        let (tx, _rx) = crate::events::EventBus::channel(16);
        let ctl = Arc::new(InterceptController::with_limits(tx, 2, 10));
        let hold = |ctl: Arc<InterceptController>, n: usize| {
            tokio::spawn(async move { ctl.hold(1, Phase::Request, "GET", "u", None, vec![0; n]).await })
        };
        let a = hold(ctl.clone(), 4);
        let b = hold(ctl.clone(), 4);
        while ctl.list().len() < 2 {
            tokio::task::yield_now().await;
        }
        // Item cap.
        assert_eq!(
            ctl.hold(1, Phase::Request, "GET", "u", None, vec![]).await,
            Err(QueueFull)
        );
        ctl.forward_all();
        let _ = (a.await, b.await);
        assert_eq!(ctl.queued_bytes(), 0);
        // Byte cap.
        assert_eq!(
            ctl.hold(1, Phase::Request, "GET", "u", None, vec![0; 11]).await,
            Err(QueueFull)
        );
        assert_eq!(ctl.refused(), 2);
        // Timeout: forwarded unedited, queue empty again.
        ctl.set(InterceptSettings {
            requests: true,
            timeout_secs: Some(1),
            ..Default::default()
        });
        let d = ctl
            .hold(1, Phase::Request, "GET", "u", None, vec![0; 3])
            .await
            .unwrap();
        assert_eq!(d, Decision::Forward { raw: None });
        assert!(ctl.list().is_empty());
        assert_eq!(ctl.queued_bytes(), 0);
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
