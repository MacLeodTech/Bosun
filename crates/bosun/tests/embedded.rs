//! `bosun serve --embedded`, the way a desktop app runs the engine: as a child process that prints a handshake
//! line, signs its parent in with a one-time ticket, and exits when its stdin closes.

#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use bosun_client::{Client, Role};

fn spawn(data: &std::path::Path, extra: &[&str]) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_bosun"))
        .args(["--data-dir", data.to_str().unwrap(), "serve", "--embedded"])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn handshake(child: &mut std::process::Child) -> serde_json::Value {
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("not a JSON handshake ({e}): {line:?}"))
}

fn wait_exit(child: &mut std::process::Child, within: Duration) -> Option<std::process::ExitStatus> {
    let end = Instant::now() + within;
    while Instant::now() < end {
        if let Some(s) = child.try_wait().unwrap() {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[tokio::test]
async fn the_parent_gets_a_handshake_signs_in_once_and_the_engine_ends_with_its_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = spawn(dir.path(), &[]);
    let hs = handshake(&mut child);

    let api = hs["api_url"].as_str().unwrap().to_string();
    assert!(api.starts_with("http://127.0.0.1:"), "{api}");
    assert!(
        hs["proxy_addr"].as_str().unwrap().starts_with("127.0.0.1:"),
        "{hs}"
    );
    assert_eq!(
        hs["ca_spki"].as_str().unwrap().len(),
        44,
        "a base64 SHA-256: {hs}"
    );
    assert!(!hs["version"].as_str().unwrap().is_empty());
    let ticket = hs["login_ticket"].as_str().unwrap().to_string();
    assert_ne!(api, hs["proxy_addr"], "separate listeners");

    let c = Client::new(&api).unwrap();
    assert!(c.status().await.unwrap().setup_required);
    let me = c.login_ticket(&ticket).await.unwrap();
    assert_eq!(me.user.role, Role::Admin);
    assert!(c.users().await.is_ok());
    // The CA the parent was told about is the one the engine serves.
    assert_eq!(
        c.ca_info().await.unwrap().spki_sha256,
        hs["ca_spki"].as_str().unwrap()
    );
    // The proxy is up on the address it announced.
    assert_eq!(
        c.proxy_info().await.unwrap().listen,
        hs["proxy_addr"].as_str().unwrap()
    );

    // The ticket was single-use.
    let other = Client::new(&api).unwrap();
    assert!(other.login_ticket(&ticket).await.unwrap_err().is_unauthorized());
    let audit = c.audit(None, None).await.unwrap();
    assert!(
        audit.iter().any(|e| e.action == "login.ticket"),
        "the exchange is audited"
    );

    // Closing stdin (the parent going away) ends the engine, cleanly.
    drop(child.stdin.take());
    let status = wait_exit(&mut child, Duration::from_secs(15)).unwrap_or_else(|| {
        child.kill().ok();
        panic!("the engine kept running after its stdin closed")
    });
    assert!(status.success(), "{status:?}");
}

#[test]
fn embedded_mode_only_listens_on_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bosun"))
        .args([
            "--data-dir",
            dir.path().to_str().unwrap(),
            "serve",
            "--embedded",
            "--listen",
            "0.0.0.0:0",
        ])
        .stdin(Stdio::piped())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("loopback"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "no handshake on a refusal");
}

#[test]
fn an_engine_whose_stdin_is_already_closed_exits_instead_of_lingering() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_bosun"))
        .args(["--data-dir", dir.path().to_str().unwrap(), "serve", "--embedded"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = wait_exit(&mut child, Duration::from_secs(15)).unwrap_or_else(|| {
        child.kill().ok();
        panic!("an orphaned engine kept running")
    });
    assert!(status.success());
}
