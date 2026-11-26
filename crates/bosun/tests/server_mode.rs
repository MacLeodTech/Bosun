//! Server mode: non-interactive setup from secret files, `bosun healthcheck`, `/healthz`, `/metrics` and JSON logs.

#![allow(clippy::unwrap_used)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn setup_from_files_health_metrics_and_json_logs() {
    let dir = tempfile::tempdir().unwrap();
    let (api, proxy, metrics) = (free_port(), free_port(), free_port());
    let pw = dir.path().join("pw");
    let tok = dir.path().join("tok");
    std::fs::write(&pw, "a long enough password\n").unwrap();
    let token = "bootstrap_token_0123456789abcdefghijklmnop";
    std::fs::write(&tok, format!("{token}\n")).unwrap();
    let cfg = dir.path().join("bosun.toml");
    std::fs::write(
        &cfg,
        format!(
            "metrics_listen = \"127.0.0.1:{metrics}\"\n[proxy]\nlisten = \"127.0.0.1:{proxy}\"\n[api]\nlisten = \"127.0.0.1:{api}\"\n"
        ),
    )
    .unwrap();
    let data = dir.path().join("data");
    let bosun = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_bosun"));
        c.args([
            "--config",
            cfg.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
        ])
        .args(args)
        .env("BOSUN_LOG_FORMAT", "json")
        .env("BOSUN_ADMIN_USER", "root")
        .env("BOSUN_ADMIN_PASSWORD_FILE", &pw)
        .env("BOSUN_BOOTSTRAP_TOKEN_FILE", &tok);
        c
    };
    assert!(
        !bosun(&["healthcheck"]).output().unwrap().status.success(),
        "nothing is listening yet"
    );
    let mut child = bosun(&["serve"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| unreachable!());
    let end = Instant::now() + Duration::from_secs(20);
    while !bosun(&["healthcheck"]).output().unwrap().status.success() {
        assert!(Instant::now() < end, "never became healthy");
        std::thread::sleep(Duration::from_millis(100));
    }
    let http = reqwest::Client::new();
    let h = http
        .get(format!("http://127.0.0.1:{api}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(h.status(), 200);
    assert_eq!(h.text().await.unwrap(), "ok");
    let me: serde_json::Value = http
        .get(format!("http://127.0.0.1:{api}/api/v1/auth/me"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["user"]["username"], "root");
    assert_eq!(me["user"]["role"], "admin");
    let m = http
        .get(format!("http://127.0.0.1:{metrics}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(m.contains("# TYPE bosun_memory_budget_bytes gauge"), "{m}");
    assert_eq!(
        http.get(format!("http://127.0.0.1:{metrics}/other"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    child.kill().unwrap();
    let out = child.wait_with_output().unwrap();
    let log = String::from_utf8_lossy(&out.stderr);
    let first = log.lines().find(|l| l.starts_with('{')).expect("a JSON log line");
    serde_json::from_str::<serde_json::Value>(first).unwrap();
    assert!(!log.contains("a long enough password") && !log.contains(token));
}
