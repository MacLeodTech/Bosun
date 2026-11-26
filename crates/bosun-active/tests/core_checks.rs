#![allow(clippy::unwrap_used)]
//! WP-55: the core active checks, each against a planted testbed endpoint and its safe twin (no false positive).

use std::sync::Arc;

use bosun_active::{Control, Options, Report, Strength, Target, scan};
use bosun_http::Engine;
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, RuleSpec, Scope, ScopeSpec};

type Found = Vec<(String, String, String)>;

fn engine(port: u16) -> Engine {
    let rule = RuleSpec {
        scheme: None,
        host: "127.0.0.1".into(),
        port: Some(port),
        path: None,
        allow_private: true,
    };
    let scope = Scope::compile(ScopeSpec {
        include: vec![rule],
        exclude: vec![],
    })
    .unwrap();
    Engine::new(Gate::new(scope), MemoryBudget::new(64 << 20))
}

fn get(url: String) -> Target {
    Target {
        method: None,
        url,
        headers: vec![],
        body: None,
        content_type: None,
    }
}

/// Scan `paths` (GET, or `POST /path body`) with the given checks (none: the defaults). The findings as
/// `(check, path, point)`, sorted.
async fn found(
    checks: &[&str],
    strength: Strength,
    paths: &[&str],
) -> (Found, Report, bosun_testbed::Testbed) {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let base = format!("http://127.0.0.1:{}", tb.addr.port());
    let t: Vec<Target> = paths
        .iter()
        .map(|p| match p.strip_prefix("POST ") {
            Some(r) => {
                let (path, body) = r.split_once(' ').unwrap();
                Target {
                    method: Some("POST".into()),
                    body: Some(body.into()),
                    ..get(format!("{base}{path}"))
                }
            }
            None => get(format!("{base}{p}")),
        })
        .collect();
    let opts = Options {
        checks: checks.iter().map(|c| (*c).to_string()).collect(),
        strength,
        concurrency: 8,
        ..Options::default()
    };
    let r = scan(&engine(tb.addr.port()), &opts, &t, Arc::new(()), &Control::new())
        .await
        .unwrap();
    let mut got: Found = r
        .findings
        .iter()
        .map(|f| {
            (
                f.check.clone(),
                f.url.strip_prefix(&base).unwrap().to_string(),
                f.point.clone(),
            )
        })
        .collect();
    got.sort();
    (got, r, tb)
}

fn want(check: &str, path: &str, point: &str) -> Found {
    vec![(check.into(), path.into(), point.into())]
}

#[tokio::test]
async fn boolean_blind_sqli_is_found_and_not_in_the_twins() {
    let (got, ..) = found(
        &["active-sqli-boolean"],
        Strength::Medium,
        &[
            "/user?id=1",
            "/user-safe?id=1",
            "/item?id=1",
            "/safe?id=1",
            "/search?q=boat",
            "/about",
        ],
    )
    .await;
    assert_eq!(got, want("active-sqli-boolean", "/user", "query:id"));
}

#[tokio::test]
async fn time_based_sqli_is_found_and_not_in_the_twins() {
    let (got, ..) = found(
        &["active-sqli-time"],
        Strength::Low,
        &["/report?id=1", "/report-safe?id=1", "/user?id=1"],
    )
    .await;
    assert_eq!(got, want("active-sqli-time", "/report", "query:id"));
}

#[tokio::test]
async fn stored_xss_is_destructive_off_by_default_and_found_when_named() {
    let t = ["POST /guestbook msg=hi", "POST /notes msg=hi"];
    // Named: found in the guest book, not in the escaping twin.
    let (got, _, tb) = found(&["active-xss-stored"], Strength::Medium, &t).await;
    assert_eq!(got, want("active-xss-stored", "/guestbook", "form:msg"));
    assert!(tb.hits().iter().any(|h| h.starts_with("POST /guestbook")));
    // Not named: the defaults never save data, so no request is sent to the guest book or the notes.
    let (got, r, tb) = found(&[], Strength::Medium, &t).await;
    assert!(got.is_empty(), "{got:?}");
    assert!(r.requests > 0);
    assert!(
        !tb.hits().iter().any(|h| h.starts_with("GET")),
        "the defaults read the page back: {:?}",
        tb.hits()
    );
    assert!(bosun_active::is_destructive("active-xss-stored"));
    assert!(
        bosun_active::DESTRUCTIVE
            .iter()
            .all(|d| bosun_active::CHECKS.iter().any(|(id, _)| id == d))
    );
}

#[tokio::test]
async fn template_injection_is_found_and_not_in_the_twins() {
    let (got, ..) = found(
        &["active-ssti"],
        Strength::Medium,
        &[
            "/render?name=sam",
            "/render-safe?name=sam",
            "/greet?name=sam",
            "/search?q=boat",
        ],
    )
    .await;
    assert_eq!(got, want("active-ssti", "/render", "query:name"));
}

#[tokio::test]
async fn command_injection_is_found_by_echo_and_by_time_and_not_in_the_twin() {
    let (got, r, _) = found(
        &["active-cmd-injection"],
        Strength::Medium,
        &[
            "/ping?host=localhost",
            "/ping-safe?host=localhost",
            "/search?q=boat",
        ],
    )
    .await;
    assert_eq!(got, want("active-cmd-injection", "/ping", "query:host"));
    assert_eq!(r.findings[0].title, "OS command injection");
    // Blind: nothing printed, only the delay.
    let (got, r, _) = found(
        &["active-cmd-injection"],
        Strength::Low,
        &["/ping-blind?host=localhost"],
    )
    .await;
    assert_eq!(got, want("active-cmd-injection", "/ping-blind", "query:host"));
    assert!(r.findings[0].title.contains("time based"));
}

#[tokio::test]
async fn path_traversal_is_found_and_not_in_the_twins() {
    let (got, ..) = found(
        &["active-path-traversal"],
        Strength::Medium,
        &[
            "/download?file=report.txt",
            "/download-safe?file=report.txt",
            "/files/readme.txt",
            "/search?q=boat",
        ],
    )
    .await;
    assert_eq!(got, want("active-path-traversal", "/download", "query:file"));
}

#[tokio::test]
async fn open_redirect_is_found_and_not_in_the_twin() {
    let (got, ..) = found(
        &["active-open-redirect"],
        Strength::Medium,
        &["/go?url=/home", "/go-safe?url=/home", "/search?q=boat"],
    )
    .await;
    assert_eq!(got, want("active-open-redirect", "/go", "query:url"));
}

#[tokio::test]
async fn crlf_injection_is_found_and_not_in_the_twin() {
    let (got, ..) = found(
        &["active-crlf-injection"],
        Strength::Medium,
        &["/lang?set=en", "/lang-safe?set=en", "/search?q=boat"],
    )
    .await;
    assert_eq!(got, want("active-crlf-injection", "/lang", "query:set"));
}

#[tokio::test]
async fn cors_misconfiguration_is_found_and_not_in_the_safe_endpoints() {
    let (got, ..) = found(
        &["active-cors"],
        Strength::Medium,
        &[
            "/api/profile",
            "/api/profile-safe",
            "/api/public",
            "/search?q=boat",
        ],
    )
    .await;
    assert_eq!(got, want("active-cors", "/api/profile", "request"));
}

#[tokio::test]
async fn host_header_attack_is_found_and_not_in_the_twin() {
    let (got, ..) = found(
        &["active-host-header"],
        Strength::Medium,
        &["/reset", "/reset-safe", "/search?q=boat"],
    )
    .await;
    assert_eq!(got, want("active-host-header", "/reset", "request"));
}

#[tokio::test]
async fn a_default_scan_of_every_endpoint_finds_exactly_the_planted_issues() {
    let all = [
        "/user?id=1",
        "/user-safe?id=1",
        "/report?id=1",
        "/report-safe?id=1",
        "/render?name=sam",
        "/render-safe?name=sam",
        "/ping?host=localhost",
        "/ping-safe?host=localhost",
        "/download?file=report.txt",
        "/download-safe?file=report.txt",
        "/go?url=/home",
        "/go-safe?url=/home",
        "/lang?set=en",
        "/lang-safe?set=en",
        "/api/profile",
        "/api/profile-safe",
        "/api/public",
        "/reset",
        "/reset-safe",
        "POST /guestbook msg=hi",
        "POST /notes msg=hi",
    ];
    let (got, r, tb) = found(&[], Strength::Medium, &all).await;
    let mut w: Found = [
        ("active-sqli-boolean", "/user", "query:id"),
        ("active-sqli-time", "/report", "query:id"),
        ("active-ssti", "/render", "query:name"),
        ("active-cmd-injection", "/ping", "query:host"),
        ("active-path-traversal", "/download", "query:file"),
        ("active-open-redirect", "/go", "query:url"),
        ("active-crlf-injection", "/lang", "query:set"),
        ("active-cors", "/api/profile", "request"),
        ("active-host-header", "/reset", "request"),
    ]
    .iter()
    .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
    .collect();
    w.sort();
    assert_eq!(got, w);
    assert!(r.units_done == r.units_total && !r.truncated);
    assert!(r.requests > 0 && tb.hits().len() as u64 == r.requests);
}

#[tokio::test]
async fn the_new_checks_respect_the_request_cap_and_the_scope() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let outside = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let base = format!("http://127.0.0.1:{}", tb.addr.port());
    let t = vec![
        get(format!("http://127.0.0.1:{}/reset", outside.addr.port())),
        get(format!("{base}/user?id=1")),
        get(format!("{base}/api/profile")),
    ];
    let opts = Options {
        max_requests: 7,
        concurrency: 1,
        strength: Strength::High,
        ..Options::default()
    };
    let r = scan(&engine(tb.addr.port()), &opts, &t, Arc::new(()), &Control::new())
        .await
        .unwrap();
    assert!(outside.hits().is_empty());
    assert_eq!(r.refused.len(), 1);
    assert!(r.truncated && r.requests == 7 && tb.hits().len() == 7);
}
