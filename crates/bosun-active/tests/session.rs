#![allow(clippy::unwrap_used)]
//! WP-56: a scan of the testbed's logged-in area stays logged in, even when the session ends mid-scan.

use std::sync::{Arc, Mutex};

use bosun_active::{Control, Options, Sink, Target, scan_with_session};
use bosun_auth::{Capture, Expiry, LoginMacro, Session};
use bosun_http::{Engine, Exchange, SendOptions};
use bosun_model::{Scheme, Target as Origin};
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, RuleSpec, Scope, ScopeSpec};

#[derive(Default)]
struct Statuses(Mutex<Vec<(String, u16)>>);

impl Sink for Statuses {
    fn exchange(&self, ex: &Exchange) -> i64 {
        let line = String::from_utf8_lossy(&ex.request);
        let path = line.split(' ').nth(1).unwrap_or("").to_string();
        self.0.lock().unwrap().push((path, ex.status.unwrap_or(0)));
        0
    }
}

fn engine(port: u16) -> Engine {
    let scope = Scope::compile(ScopeSpec {
        include: vec![RuleSpec {
            scheme: None,
            host: "127.0.0.1".into(),
            port: Some(port),
            path: None,
            allow_private: true,
        }],
        exclude: vec![],
    })
    .unwrap();
    Engine::new(Gate::new(scope), MemoryBudget::new(64 << 20))
}

fn login(port: u16, user: &str, pass: &str) -> LoginMacro {
    let body = format!("user={user}&pass={pass}");
    LoginMacro {
        target: Origin::new(Scheme::Http, "127.0.0.1", port),
        request: format!(
            "POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
        capture: Capture::Cookies,
    }
}

fn targets(port: u16) -> Vec<Target> {
    [
        "/app/orders/1?q=a",
        "/app/orders/2?q=a",
        "/app/orders/3?q=a",
        "/app?q=a",
    ]
    .iter()
    .map(|p| Target {
        method: None,
        url: format!("http://127.0.0.1:{port}{p}"),
        headers: vec![],
        body: None,
        content_type: None,
    })
    .collect()
}

#[tokio::test]
async fn a_scan_stays_logged_in_and_signs_in_again_when_the_session_ends() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let port = tb.addr.port();
    let e = engine(port);
    let session = Arc::new(Session::new(
        e.clone(),
        login(port, "alice", "alicepw"),
        Expiry::default(),
    ));
    // Sign in, then end every session behind the scan's back.
    session.headers().await.unwrap();
    let expire = b"POST /auth/expire HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
    e.send(
        &Origin::new(Scheme::Http, "127.0.0.1", port),
        expire,
        &SendOptions::default(),
    )
    .await
    .unwrap();

    let seen = Arc::new(Statuses::default());
    let opts = Options {
        checks: vec!["active-xss-reflected".into()],
        concurrency: 4,
        ..Options::default()
    };
    let r = scan_with_session(
        &e,
        &opts,
        &targets(port),
        seen.clone(),
        &Control::new(),
        Some(session),
    )
    .await
    .unwrap();
    assert_eq!(r.session_error, None);
    assert_eq!(
        r.sign_ins, 2,
        "one sign-in at the start, one when the session ended"
    );
    let got = seen.0.lock().unwrap().clone();
    let bounced: Vec<_> = got.iter().filter(|(_, s)| *s == 302).collect();
    // Concurrent units may each hit the dead session once before the refresh lands; none after.
    assert!(!bounced.is_empty() && bounced.len() <= 4, "{got:?}");
    assert!(got.iter().filter(|(_, s)| *s == 200).count() >= 4, "{got:?}");

    // Without a session the same scan is bounced everywhere.
    let seen = Arc::new(Statuses::default());
    scan_with_session(&e, &opts, &targets(port), seen.clone(), &Control::new(), None)
        .await
        .unwrap();
    assert!(seen.0.lock().unwrap().iter().all(|(_, s)| *s == 302));
}

#[tokio::test]
async fn bad_credentials_stop_the_scan_with_a_reason() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let port = tb.addr.port();
    let e = engine(port);
    let session = Arc::new(Session::new(
        e.clone(),
        login(port, "alice", "wrong"),
        Expiry::default(),
    ));
    let r = scan_with_session(
        &e,
        &Options::default(),
        &targets(port),
        Arc::new(()),
        &Control::new(),
        Some(session),
    )
    .await
    .unwrap();
    let why = r.session_error.unwrap();
    assert!(why.contains("did not give a session"), "{why}");
    assert!(r.stopped);
}
