//! History queries typed by the user: parsing must be total, the spans must be valid, and whatever parses must
//! compile to SQL that SQLite accepts and runs (no syntax errors, no panics), against a real project.
#![no_main]
use std::sync::{Mutex, OnceLock};

use bosun_model::{FlowSource, Scheme};
use bosun_store::project::{FlowFilter, NewFlow, Project};
use bosun_store::query;
use libfuzzer_sys::fuzz_target;

fn project() -> &'static Mutex<Project> {
    static P: OnceLock<Mutex<Project>> = OnceLock::new();
    P.get_or_init(|| {
        let p = Project::open_in_memory().expect("in-memory project");
        let mk = |path: &str, status| NewFlow {
            id: p.next_flow_id(),
            source: FlowSource::Proxy,
            started_ms: 1,
            duration_ms: Some(1),
            ttfb_ms: None,
            scheme: Scheme::Https,
            host: "a.test".into(),
            port: 443,
            method: "GET".into(),
            path: path.into(),
            http_version: "HTTP/1.1".into(),
            status,
            in_scope: true,
            edited: false,
            error: None,
            request: format!("GET {path} HTTP/1.1\r\nHost: a.test\r\nX-A: b\r\n\r\n").into_bytes(),
            original_request: None,
            response: Some(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi".to_vec()),
            original_response: None,
            response_truncated: false,
        };
        p.write_batch(&[mk("/a.css", Some(200)), mk("/login", None)], &[]).expect("seed");
        Mutex::new(p)
    })
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let parsed = query::parse(&text);
    for t in &parsed.terms {
        assert!(t.start <= t.end && t.end <= text.len());
        assert!(text.is_char_boundary(t.start) && text.is_char_boundary(t.end));
    }
    if let Some(e) = &parsed.expr {
        let (sql, args) = query::compile(e, 1_000_000);
        assert_eq!(sql.matches('?').count(), args.len());
    }
    let p = project().lock().unwrap_or_else(|e| e.into_inner());
    let r = p.list_flows(&FlowFilter { query: parsed.expr, ..Default::default() });
    // The only acceptable failure is the time limit.
    if let Err(e) = r {
        assert!(e.to_string().contains("longer than"), "{e}");
    }
});
