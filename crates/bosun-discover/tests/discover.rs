#![allow(clippy::unwrap_used)]
//! Discovery against the testbed: planted hidden paths and parameters are found, recursion goes into directories,
//! a soft-404 area gives only its real page, and the gate and the request limit hold.

use bosun_crawl::Stop;
use bosun_discover::{Mode, Options, Report, discover};
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

fn urls(r: &Report) -> Vec<String> {
    r.hits
        .iter()
        .map(|h| {
            h.url
                .rsplit_once(':')
                .unwrap()
                .1
                .split_once('/')
                .unwrap()
                .1
                .to_string()
        })
        .collect()
}

#[tokio::test]
async fn finds_planted_paths_recurses_and_ignores_soft_404s() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let port = tb.addr.port();
    let e = engine(port);
    let o = Options {
        base: format!("http://127.0.0.1:{port}/"),
        words: [
            "admin",
            "ghost",
            "backup.zip",
            ".git/HEAD",
            "nothing-here",
            "config",
            "backup.sql",
            "real",
        ]
        .map(String::from)
        .to_vec(),
        max_depth: 2,
        ..Options::default()
    };
    let r = discover(&e, &o, &(), &Stop::new()).await.unwrap();
    let found = urls(&r);
    for want in [
        "admin",
        "backup.zip",
        ".git/HEAD",
        "ghost",
        "admin/config",
        "admin/backup.sql",
        "ghost/real",
    ] {
        assert!(
            found.iter().any(|u| u.trim_end_matches('/') == want),
            "{want} missing from {found:?}"
        );
    }
    // Names that do not exist, and the soft-404 area's made-up names, are not hits.
    assert!(!found.iter().any(|u| u.contains("nothing-here")), "{found:?}");
    assert!(
        !found.iter().any(|u| u == "ghost/config" || u == "ghost/admin"),
        "{found:?}"
    );
    let admin = r.hits.iter().find(|h| h.url.ends_with("/admin")).unwrap();
    assert_eq!(admin.status, 301);
    assert_eq!(admin.note.as_deref(), Some("directory"));
    assert!(r.directories.len() >= 3, "{:?}", r.directories);
    assert!(!r.truncated && !r.stopped && r.error.is_none());
}

#[tokio::test]
async fn finds_a_hidden_parameter_and_extensions() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let port = tb.addr.port();
    let e = engine(port);
    let o = Options {
        base: format!("http://127.0.0.1:{port}/tool"),
        mode: Mode::Params,
        words: ["q", "debug", "page", "x"].map(String::from).to_vec(),
        ..Options::default()
    };
    let r = discover(&e, &o, &(), &Stop::new()).await.unwrap();
    let names: Vec<_> = r.hits.iter().map(|h| h.word.as_str()).collect();
    assert_eq!(names, ["debug"], "{:?}", r.hits);

    let o = Options {
        base: format!("http://127.0.0.1:{port}/"),
        words: vec!["backup".into()],
        extensions: vec!["zip".into(), "sql".into()],
        max_depth: 0,
        ..Options::default()
    };
    let r = discover(&e, &o, &(), &Stop::new()).await.unwrap();
    let found = urls(&r);
    assert!(found.iter().any(|u| u == "backup.zip"), "{found:?}");
    // `backup.sql` is not at the root (it is under /admin/).
    assert!(!found.iter().any(|u| u == "backup.sql"), "{found:?}");
}

#[tokio::test]
async fn the_gate_the_limit_and_the_stop_switch_hold() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let port = tb.addr.port();
    // Out of scope: refused, nothing is sent.
    let e = engine(port + 1);
    let o = Options {
        base: format!("http://127.0.0.1:{port}/"),
        ..Options::default()
    };
    let r = discover(&e, &o, &(), &Stop::new()).await.unwrap();
    assert!(
        r.error.as_deref().is_some_and(|m| m.contains("refused")),
        "{:?}",
        r.error
    );
    assert!(tb.hits().is_empty());
    // The request limit ends the run and says so.
    let e = engine(port);
    let o = Options {
        base: format!("http://127.0.0.1:{port}/"),
        max_requests: 12,
        ..Options::default()
    };
    let r = discover(&e, &o, &(), &Stop::new()).await.unwrap();
    assert!(r.truncated && r.requests <= 12, "{} {}", r.truncated, r.requests);
    // Stopped before it starts.
    let stop = Stop::new();
    stop.stop();
    let r = discover(&e, &o, &(), &stop).await.unwrap();
    assert!(r.stopped || r.hits.is_empty());
    // Bad input.
    let bad = Options {
        base: "nonsense".into(),
        ..Options::default()
    };
    assert!(discover(&e, &bad, &(), &Stop::new()).await.is_err());
}
