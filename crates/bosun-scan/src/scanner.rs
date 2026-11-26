//! The thread that feeds recorded flows to the rules.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bosun_model::now_ms;
use bosun_store::Project;

use crate::rules::scan_flow_with;
use bosun_checks::Compiled;

/// Flows read per transaction.
const BATCH: usize = 32;
/// How long to wait when there is nothing to read.
const IDLE: Duration = Duration::from_millis(500);
/// The pause after a batch, so the recorder's writes and the API's reads get their turn.
const BREATHER: Duration = Duration::from_millis(15);

/// A running scanner. Dropping it stops the thread (after the batch in hand).
#[derive(Debug)]
pub struct Scanner {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Scanner {
    /// Start reading `project`'s unread flows. The thread holds the project only while it works on a batch, so it
    /// never keeps a closed project open.
    pub fn start(project: &Arc<Project>) -> Self {
        Self::start_notify(project, || {})
    }

    /// As [`Scanner::start`], and `changed` is called (on the scanner's thread, so keep it quick) after a batch
    /// that found something, and once when the scanner runs dry after working, so a front end can look again.
    pub fn start_notify(project: &Arc<Project>, changed: impl Fn() + Send + 'static) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let weak = Arc::downgrade(project);
        let s = stop.clone();
        let thread = thread::Builder::new()
            .name("bosun-scanner".into())
            .spawn(move || run(&weak, &s, &changed))
            .map_err(|e| tracing::error!(error = %e, "cannot start the passive scanner"))
            .ok();
        Self { stop, thread }
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = &self.thread {
            t.thread().unpark();
        }
    }
}

/// The project's enabled custom checks, compiled once and rebuilt when any of them changes. A check that no
/// longer compiles is skipped (the API validates before storing, so this is a file edited by hand).
#[derive(Default)]
struct Custom {
    stamp: Option<(i64, i64, i64)>,
    checks: Vec<Compiled>,
}

impl Custom {
    fn get(&mut self, p: &Project) -> &[Compiled] {
        match p.checks_stamp() {
            Ok(s) if self.stamp != Some(s) => {
                match p.checks_enabled() {
                    Ok(rows) => {
                        self.checks = rows
                        .iter()
                        .filter_map(|(id, yaml)| {
                            bosun_checks::lang::parse(yaml)
                                .map_err(|e| tracing::warn!(check = %id, error = %e.0, "skipping a custom check"))
                                .ok()
                                .filter(Compiled::is_passive)
                        })
                        .collect();
                        self.stamp = Some(s);
                    }
                    Err(e) => tracing::warn!(error = %e, "cannot read the custom checks"),
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "cannot read the custom checks"),
        }
        &self.checks
    }
}

fn run(project: &Weak<Project>, stop: &AtomicBool, changed: &dyn Fn()) {
    let mut custom = Custom::default();
    let mut worked = false;
    while !stop.load(Ordering::Relaxed) {
        let Some(p) = project.upgrade() else { return };
        match step(&p, &mut custom) {
            Ok((0, _)) => {
                drop(p);
                if std::mem::take(&mut worked) {
                    changed();
                }
                thread::park_timeout(IDLE);
            }
            Ok((_, found)) => {
                drop(p);
                worked = true;
                if found {
                    changed();
                }
                thread::sleep(BREATHER);
            }
            Err(e) => {
                tracing::warn!(error = %e, "passive scan failed; trying again shortly");
                drop(p);
                thread::park_timeout(IDLE * 4);
            }
        }
    }
}

/// Read one batch. Returns how many flows it covered and whether any issue was found in them.
fn step(p: &Project, custom: &mut Custom) -> Result<(usize, bool), bosun_store::StoreError> {
    let ids = p.scan_pending(BATCH)?;
    let now = now_ms();
    let custom = custom.get(p);
    let mut found = Vec::new();
    for id in &ids {
        // A flow that cannot be read (deleted meanwhile, damaged) or that trips a rule is skipped, not retried
        // forever.
        match p.get_flow(*id) {
            Ok(Some(f)) => {
                match std::panic::catch_unwind(AssertUnwindSafe(|| scan_flow_with(&f, now, custom))) {
                    Ok(v) => found.extend(v),
                    Err(_) => tracing::error!(flow = id, "a passive rule panicked"),
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(flow = id, error = %e, "cannot read a flow to scan it"),
        }
    }
    if !ids.is_empty() {
        p.scan_commit(&ids, &found)?;
    }
    Ok((ids.len(), !found.is_empty()))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use bosun_model::{FlowSource, Scheme};
    use bosun_store::{IssueFilter, NewFlow};

    use super::*;

    fn flow(p: &Project, host: &str, path: &str) -> NewFlow {
        let body = "x";
        NewFlow {
            id: p.next_flow_id(),
            source: FlowSource::Proxy,
            started_ms: 1,
            duration_ms: Some(1),
            ttfb_ms: None,
            scheme: Scheme::Https,
            host: host.into(),
            port: 443,
            method: "GET".into(),
            path: path.into(),
            http_version: "HTTP/1.1".into(),
            status: Some(200),
            in_scope: true,
            edited: false,
            error: None,
            request: format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes(),
            original_request: None,
            response: Some(
                format!(
                    "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\n{body}"
                )
                .into_bytes(),
            ),
            original_response: None,
            response_truncated: false,
        }
    }

    fn wait_until_read(p: &Project) {
        let t = Instant::now();
        while p.scan_backlog().unwrap() > 0 {
            assert!(
                t.elapsed() < Duration::from_secs(30),
                "the scanner did not catch up"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_backlog_is_scanned_deduplicated_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.bosun");
        {
            let p = Arc::new(Project::open(&path).unwrap());
            // Flows recorded before any scanner ran: a backlog.
            let flows: Vec<_> = (0..600).map(|i| flow(&p, "a.test", &format!("/p{i}"))).collect();
            p.write_batch(&flows, &[]).unwrap();
            assert_eq!(p.scan_backlog().unwrap(), 600);
            let _s = Scanner::start(&p);
            wait_until_read(&p);
            let issues = p.issues(&IssueFilter::default()).unwrap();
            // Hundreds of identical sightings are one issue per rule and origin.
            let rules: Vec<_> = issues.iter().map(|i| i.rule.as_str()).collect();
            assert_eq!(rules.len(), 3, "{rules:?}");
            assert!(issues.iter().all(|i| i.count == 600 && i.flow_id.is_some()));
            // New traffic is picked up too, and a status set by the user is kept.
            let id = issues[0].id;
            assert!(
                p.issue_set_status(id, bosun_store::IssueStatus::FalsePositive)
                    .unwrap()
            );
            p.write_batch(&[flow(&p, "b.test", "/x")], &[]).unwrap();
            wait_until_read(&p);
            assert_eq!(p.issues(&IssueFilter::default()).unwrap().len(), 6);
            p.write_batch(&[flow(&p, "a.test", "/again")], &[]).unwrap();
            wait_until_read(&p);
        }
        let p = Arc::new(Project::open(&path).unwrap());
        let _s = Scanner::start(&p);
        let issues = p.issues(&IssueFilter::default()).unwrap();
        assert_eq!(issues.len(), 6);
        assert!(
            issues
                .iter()
                .filter(|i| i.host == "a.test")
                .all(|i| i.count == 601)
        );
        assert!(
            issues
                .iter()
                .any(|i| i.status == bosun_store::IssueStatus::FalsePositive)
        );
        assert_eq!(p.scan_backlog().unwrap(), 0);
    }

    #[test]
    fn the_scanner_says_when_it_found_something() {
        let p = Arc::new(Project::open_in_memory().unwrap());
        p.write_batch(&[flow(&p, "a.test", "/x")], &[]).unwrap();
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n2 = n.clone();
        let _s = Scanner::start_notify(&p, move || {
            n2.fetch_add(1, Ordering::Relaxed);
        });
        wait_until_read(&p);
        let t = Instant::now();
        while n.load(Ordering::Relaxed) == 0 && t.elapsed() < Duration::from_secs(10) {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(n.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn custom_checks_run_and_follow_edits() {
        let yaml = |word: &str| {
            format!(
                "version: 1\nid: mine\ninfo:\n  name: Mine\n  severity: low\npassive:\n  matchers:\n    - type: word\n      part: body\n      words: [\"{word}\"]\n"
            )
        };
        let p = Arc::new(Project::open_in_memory().unwrap());
        p.write_batch(&[flow(&p, "a.test", "/x")], &[]).unwrap(); // the body is "x"
        let _s = Scanner::start(&p);
        wait_until_read(&p);
        assert!(
            p.issues(&IssueFilter::default())
                .unwrap()
                .iter()
                .all(|i| i.rule != "mine")
        );
        let id = p.check_add("mine", &yaml("x"), 1).unwrap();
        p.write_batch(&[flow(&p, "b.test", "/x")], &[]).unwrap();
        wait_until_read(&p);
        let found = |p: &Project| {
            p.issues(&IssueFilter::default())
                .unwrap()
                .iter()
                .filter(|i| i.rule == "mine")
                .map(|i| i.host.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(found(&p), ["b.test"]);
        // Edited so it no longer matches, then switched off: nothing new either way.
        assert!(p.check_update(id, "mine", &yaml("nothing like it"), 2).unwrap());
        p.write_batch(&[flow(&p, "c.test", "/x")], &[]).unwrap();
        wait_until_read(&p);
        assert_eq!(found(&p), ["b.test"]);
        assert!(p.check_update(id, "mine", &yaml("x"), 3).unwrap());
        assert!(p.check_set_enabled(id, false, 4).unwrap());
        p.write_batch(&[flow(&p, "d.test", "/x")], &[]).unwrap();
        wait_until_read(&p);
        assert_eq!(found(&p), ["b.test"]);
    }

    #[test]
    fn deleting_the_evidence_flow_keeps_the_issue() {
        let p = Arc::new(Project::open_in_memory().unwrap());
        let f = flow(&p, "a.test", "/x");
        let id = f.id;
        p.write_batch(&[f], &[]).unwrap();
        let _s = Scanner::start(&p);
        wait_until_read(&p);
        p.delete_flows(&[id]).unwrap();
        let issues = p.issues(&IssueFilter::default()).unwrap();
        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .all(|i| i.flow_id.is_none() && i.evidence.is_empty())
        );
    }

    #[test]
    fn a_rescan_reads_everything_again_and_recounts() {
        let p = Arc::new(Project::open_in_memory().unwrap());
        p.write_batch(&[flow(&p, "a.test", "/x"), flow(&p, "a.test", "/y")], &[])
            .unwrap();
        let _s = Scanner::start(&p);
        wait_until_read(&p);
        p.scan_restart().unwrap();
        wait_until_read(&p);
        let issues = p.issues(&IssueFilter::default()).unwrap();
        assert!(issues.iter().all(|i| i.count == 2));
    }

    #[test]
    fn the_scanner_stops_with_its_handle_and_does_not_hold_the_project() {
        let p = Arc::new(Project::open_in_memory().unwrap());
        let s = Scanner::start(&p);
        drop(s);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(Arc::strong_count(&p), 1);
    }
}
