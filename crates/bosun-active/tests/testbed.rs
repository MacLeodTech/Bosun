#![allow(clippy::unwrap_used)]
//! The active engine against the testbed: the planted issues are found and the safe twins stay quiet, the scan
//! pauses and resumes, honours the request cap and the stop switch, and never leaves the scope. The crawler runs
//! against the same testbed first (WP-52): it finds every linked page and does not leave the scope either.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bosun_active::{Control, Options, Strength, Target, scan};
use bosun_http::Engine;
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, RuleSpec, Scope, ScopeSpec};

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

fn targets(base: &str) -> Vec<Target> {
    let mut t: Vec<Target> = [
        "/search?q=boat",
        "/item?id=1",
        "/greet?name=sam",
        "/safe?id=1",
        "/files/readme.txt",
    ]
    .iter()
    .map(|p| get(format!("{base}{p}")))
    .collect();
    t.push(Target {
        headers: vec![("Cookie".into(), "theme=dark; session=abc".into())],
        ..get(format!("{base}/prefs"))
    });
    t.push(Target {
        method: Some("POST".into()),
        body: Some("text=hi".into()),
        ..get(format!("{base}/comment"))
    });
    t.push(Target {
        method: Some("POST".into()),
        body: Some(r#"{"name":"sam","n":3}"#.into()),
        content_type: Some("application/json".into()),
        ..get(format!("{base}/api/echo"))
    });
    t
}

#[tokio::test]
async fn crawler_finds_every_linked_page_of_the_testbed_and_stays_in_scope() {
    let outside = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let tb = bosun_testbed::start(
        "127.0.0.1:0",
        Some(format!("http://127.0.0.1:{}", outside.addr.port())),
    )
    .await
    .unwrap();
    let opts = bosun_crawl::Options {
        start: vec![format!("http://127.0.0.1:{}/", tb.addr.port())],
        ..bosun_crawl::Options::default()
    };
    let r = bosun_crawl::crawl(&engine(tb.addr.port()), &opts, &(), &bosun_crawl::Stop::new())
        .await
        .unwrap();
    let paths: Vec<String> = r
        .pages
        .iter()
        .map(|p| {
            p.url
                .split_once(&tb.addr.port().to_string())
                .map_or(p.url.clone(), |x| x.1.to_string())
        })
        .collect();
    for want in [
        "/",
        "/search?q=boat",
        "/item?id=1",
        "/greet?name=sam",
        "/safe?id=1",
        "/prefs",
        "/files/readme.txt",
        "/about",
        "/about/team",
    ] {
        assert!(paths.iter().any(|p| p == want), "missing {want} in {paths:?}");
    }
    assert_eq!(r.forms.len(), 1);
    assert!(
        r.out_of_scope.iter().any(|u| u.ends_with("/outside")),
        "{:?}",
        r.out_of_scope
    );
    assert!(
        outside.hits().is_empty(),
        "the crawl left the scope: {:?}",
        outside.hits()
    );
}

#[tokio::test]
async fn finds_the_planted_issues_and_nothing_in_the_safe_twins() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let base = format!("http://127.0.0.1:{}", tb.addr.port());
    let opts = Options {
        strength: Strength::Medium,
        ..Options::default()
    };
    let r = scan(
        &engine(tb.addr.port()),
        &opts,
        &targets(&base),
        Arc::new(()),
        &Control::new(),
    )
    .await
    .unwrap();
    let mut got: Vec<(String, String, String)> = r
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
    let want = [
        ("active-sqli-error", "/item", "query:id"),
        ("active-xss-reflected", "/api/echo", "json:/name"),
        ("active-xss-reflected", "/comment", "form:text"),
        ("active-xss-reflected", "/files/readme.txt", "path:last-segment"),
        ("active-xss-reflected", "/prefs", "cookie:theme"),
        ("active-xss-reflected", "/search", "query:q"),
    ];
    let want: Vec<(String, String, String)> = want
        .iter()
        .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
        .collect();
    assert_eq!(got, want);
    assert!(r.refused.is_empty() && !r.truncated && !r.stopped);
    assert_eq!(r.units_done, r.units_total);
    // Nothing was sent to the safe twins' points beyond probes, and every request is the scanner's.
    assert!(r.requests > 0 && tb.hits().len() as u64 == r.requests);
}

#[tokio::test]
async fn a_target_outside_the_scope_is_refused_and_never_contacted() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let outside = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let t = vec![
        get(format!("http://127.0.0.1:{}/search?q=a", outside.addr.port())),
        get(format!("http://127.0.0.1:{}/search?q=a", tb.addr.port())),
    ];
    let r = scan(
        &engine(tb.addr.port()),
        &Options::default(),
        &t,
        Arc::new(()),
        &Control::new(),
    )
    .await
    .unwrap();
    assert!(outside.hits().is_empty());
    assert_eq!(r.refused.len(), 1);
    assert_eq!(r.findings.len(), 1);
}

#[tokio::test]
async fn pause_holds_every_request_and_resume_finishes_the_scan() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let base = format!("http://127.0.0.1:{}", tb.addr.port());
    let eng = engine(tb.addr.port());
    let ctl = Control::new();
    ctl.pause();
    let (c2, t) = (ctl.clone(), targets(&base));
    let job = tokio::spawn(async move {
        scan(&eng, &Options::default(), &t, Arc::new(()), &c2)
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(tb.hits().is_empty(), "requests went out while paused");
    assert!(!job.is_finished());
    ctl.resume();
    let r = tokio::time::timeout(Duration::from_secs(30), job)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.units_done, r.units_total);
    assert_eq!(r.findings.len(), 6);
}

#[tokio::test]
async fn the_request_cap_and_the_stop_switch_end_a_scan() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let base = format!("http://127.0.0.1:{}", tb.addr.port());
    let opts = Options {
        max_requests: 5,
        concurrency: 1,
        ..Options::default()
    };
    let r = scan(
        &engine(tb.addr.port()),
        &opts,
        &targets(&base),
        Arc::new(()),
        &Control::new(),
    )
    .await
    .unwrap();
    assert!(r.truncated && r.requests == 5 && tb.hits().len() == 5);

    struct Stopper(Control, AtomicU64);
    impl bosun_active::Sink for Stopper {
        fn progress(&self, done: usize, _t: usize, _r: u64) {
            self.1.store(done as u64, Ordering::SeqCst);
            self.0.stop();
        }
    }
    let ctl = Control::new();
    let sink = Arc::new(Stopper(ctl.clone(), AtomicU64::new(0)));
    let opts = Options {
        concurrency: 1,
        ..Options::default()
    };
    let r = scan(&engine(tb.addr.port()), &opts, &targets(&base), sink, &ctl)
        .await
        .unwrap();
    assert!(r.stopped && r.units_done < r.units_total);
}

#[test]
fn options_are_validated() {
    assert!(
        Options {
            concurrency: 0,
            ..Options::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Options {
            checks: vec!["nope".into()],
            ..Options::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Options {
            headers: vec![("A".into(), "b\r\nX: y".into())],
            ..Options::default()
        }
        .validate()
        .is_err()
    );
}
