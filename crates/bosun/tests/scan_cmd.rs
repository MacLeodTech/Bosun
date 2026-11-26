//! `bosun scan` the way a CI job runs it: against the testbed, with the exit code set by `--fail-on`.

#![allow(clippy::unwrap_used)]

use std::process::{Command, Output};

fn scan(url: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bosun"))
        .args(["scan", url, "--allow-private", "--quiet"])
        .args(extra)
        .env("BOSUN_KEYCHAIN", "off")
        .env_remove("BOSUN_SERVER")
        .env_remove("BOSUN_TOKEN")
        .output()
        .unwrap()
}

fn run(url: String, extra: Vec<String>) -> Output {
    // The command blocks, so keep it off the runtime's thread.
    let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
    scan(&url, &extra)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ci_scan_of_the_testbed_fails_on_its_high_severity_issue_and_passes_a_higher_threshold() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let base = format!("http://127.0.0.1:{}", tb.addr.port());
    let dir = tempfile::tempdir().unwrap();
    let sarif = dir.path().join("out.sarif");

    // The whole site, crawled: the planted SQL injection is high severity.
    let (b, s) = (base.clone(), sarif.to_str().unwrap().to_string());
    let o = tokio::task::spawn_blocking(move || run(b, vec!["--sarif".into(), s, "--fail-on".into(), "high".into()]))
        .await
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert_eq!(o.status.code(), Some(2), "{out}\n{}", String::from_utf8_lossy(&o.stderr));
    assert!(out.contains("active-sqli-error"), "{out}");
    assert!(out.contains("active-xss-reflected"), "{out}");
    // SARIF holds the findings.
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&sarif).unwrap()).unwrap();
    assert_eq!(v["version"], "2.1.0");
    assert!(v.to_string().contains("active-sqli-error"), "{v}");

    // Only the medium-severity reflected XSS: a high threshold passes, a medium one fails, `none` never fails.
    let xss = format!("{base}/search?q=boat");
    for (fail_on, code) in [("high", 0), ("medium", 2), ("none", 0)] {
        let (u, f) = (xss.clone(), fail_on.to_string());
        let o = tokio::task::spawn_blocking(move || {
            run(u, vec!["--no-crawl".into(), "--fail-on".into(), f])
        })
        .await
        .unwrap();
        assert_eq!(
            o.status.code(),
            Some(code),
            "--fail-on {fail_on}: {}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scan_stays_on_the_target_host_and_an_import_gives_its_requests() {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let base = format!("http://127.0.0.1:{}", tb.addr.port());
    let dir = tempfile::tempdir().unwrap();
    let urls = dir.path().join("urls.txt");
    // One URL on the target, one on a host that is not in the scope.
    std::fs::write(&urls, format!("{base}/item?id=1\nhttp://localhost:9/outside?q=1\n")).unwrap();
    let (b, f) = (base.clone(), urls.to_str().unwrap().to_string());
    let o = tokio::task::spawn_blocking(move || {
        run(
            b,
            vec!["--import".into(), f, "--import-format".into(), "urls".into(), "--fail-on".into(), "high".into()],
        )
    })
    .await
    .unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(String::from_utf8_lossy(&o.stdout).contains("active-sqli-error"));
    assert!(err.contains("outside the scope"), "{err}");
    assert!(tb.hits().iter().all(|h| !h.contains("outside")), "{:?}", tb.hits());
}
