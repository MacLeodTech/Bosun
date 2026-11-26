//! `bosun login`, `status` and `repeater send` against an engine started in the test.

#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

fn bosun(data: &std::path::Path, client_dir: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bosun"));
    c.args(["--data-dir", data.to_str().unwrap()])
        .env("BOSUN_CLIENT_DIR", client_dir)
        .env("BOSUN_KEYCHAIN", "off")
        .env_remove("BOSUN_SERVER")
        .env_remove("BOSUN_TOKEN");
    c
}

fn run_with_stdin(mut c: Command, input: &str) -> std::process::Output {
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

/// A one-shot HTTP server: answers whatever arrives with a fixed body and reports the request it got.
fn target() -> (u16, std::thread::JoinHandle<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\nconnection: close\r\n\r\nhello!\n")
            .unwrap();
        String::from_utf8_lossy(&got).into_owned()
    });
    (port, h)
}

#[test]
fn login_status_and_repeater_send_work_against_a_running_engine() {
    let data = tempfile::tempdir().unwrap();
    let cdir = tempfile::tempdir().unwrap();

    let add = run_with_stdin(
        {
            let mut c = bosun(data.path(), cdir.path());
            c.args(["user", "add", "alice", "--role", "admin"]);
            c
        },
        "correct horse battery staple\n",
    );
    assert!(add.status.success(), "{}", String::from_utf8_lossy(&add.stderr));

    let mut engine = bosun(data.path(), cdir.path())
        .args(["serve", "--embedded"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(engine.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    let hs: serde_json::Value = serde_json::from_str(&line).unwrap();
    let api = hs["api_url"].as_str().unwrap().to_string();

    // Nothing signed in yet: a clear error, not a panic.
    let none = bosun(data.path(), cdir.path()).arg("status").output().unwrap();
    assert!(!none.status.success());
    assert!(String::from_utf8_lossy(&none.stderr).contains("bosun login"));

    let login = run_with_stdin(
        {
            let mut c = bosun(data.path(), cdir.path());
            c.args(["login", "--server", &api, "--username", "alice"]);
            c
        },
        "correct horse battery staple\n",
    );
    assert!(
        login.status.success(),
        "{}",
        String::from_utf8_lossy(&login.stderr)
    );
    let profiles = cdir.path().join("profiles.json");
    assert!(profiles.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&profiles).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let st = bosun(data.path(), cdir.path())
        .args(["status", "--json"])
        .output()
        .unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    let v: serde_json::Value = serde_json::from_slice(&st.stdout).unwrap();
    assert_eq!(v["user"], "alice");

    let (port, srv) = target();
    let req = cdir.path().join("req.txt");
    std::fs::write(
        &req,
        format!("GET /x HTTP/1.1\nHost: 127.0.0.1:{port}\nConnection: close\n\n"),
    )
    .unwrap();
    let url = format!("http://127.0.0.1:{port}");
    let send = |extra: &[&str]| {
        bosun(data.path(), cdir.path())
            .args(["repeater", "send", &url, req.to_str().unwrap()])
            .args(extra)
            .output()
            .unwrap()
    };

    // Out of scope by default: refused, and the exit code says so.
    let refused = send(&[]);
    assert_eq!(
        refused.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("out of scope"));

    // With the target in scope (loopback needs allow_private), a request file with LF endings goes out with CRLF and the body
    // comes back on stdout, the status line on stderr.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let c = bosun_client::Client::builder(&api)
            .token(
                serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(&profiles).unwrap())
                    .unwrap()["profiles"]["default"]["token"]
                    .as_str()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let mut rule = bosun_client::ScopeRule::host("127.0.0.1");
        rule.allow_private = true;
        c.put_scope(&bosun_client::ScopeSpec {
            include: vec![rule],
            exclude: vec![],
        })
        .await
        .unwrap();
    });
    let ok = send(&[]);
    let err = String::from_utf8_lossy(&ok.stderr);
    assert_eq!(ok.status.code(), Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&ok.stdout), "hello!\n".to_string() + "");
    assert!(err.contains("200"), "{err}");
    let got = srv.join().unwrap();
    assert!(got.starts_with("GET /x HTTP/1.1\r\nHost:"), "{got:?}");

    // `intruder run`: a one-request attack from a plan file, results as CSV.
    let (iport, isrv) = target();
    std::fs::write(
        cdir.path().join("ireq.txt"),
        format!("GET /\u{a7}a\u{a7} HTTP/1.1\nHost: 127.0.0.1:{iport}\nConnection: close\n\n"),
    )
    .unwrap();
    let plan = cdir.path().join("plan.json");
    std::fs::write(
        &plan,
        format!(
            r#"{{"scheme":"http","host":"127.0.0.1","port":{iport},"request_file":"ireq.txt",
            "attack_type":"sniper","payload_sets":[{{"source":{{"type":"list","items":["one"]}}}}]}}"#
        ),
    )
    .unwrap();
    let run = bosun(data.path(), cdir.path())
        .args(["intruder", "run", plan.to_str().unwrap()])
        .output()
        .unwrap();
    let ierr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(0), "{ierr}");
    let csv = String::from_utf8_lossy(&run.stdout);
    assert!(csv.starts_with("index,payloads,status"), "{csv}");
    assert!(csv.lines().nth(1).unwrap().starts_with("0,one,200,"), "{csv}");
    assert!(isrv.join().unwrap().starts_with("GET /one HTTP/1.1"));

    drop(engine.stdin.take());
    let _ = engine.wait();
}

#[test]
fn history_scope_rules_intercept_ca_and_events_work_against_a_running_engine() {
    let data = tempfile::tempdir().unwrap();
    let cdir = tempfile::tempdir().unwrap();
    let mut add = bosun(data.path(), cdir.path());
    add.args(["user", "add", "alice", "--role", "admin"]);
    assert!(
        run_with_stdin(add, "correct horse battery staple\n")
            .status
            .success()
    );
    let mut engine = bosun(data.path(), cdir.path())
        .args(["serve", "--embedded"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(engine.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    let hs: serde_json::Value = serde_json::from_str(&line).unwrap();
    let api = hs["api_url"].as_str().unwrap().to_string();
    let mut login = bosun(data.path(), cdir.path());
    login.args(["login", "--server", &api, "--username", "alice"]);
    assert!(
        run_with_stdin(login, "correct horse battery staple\n")
            .status
            .success()
    );
    let ok = |args: &[&str]| {
        let o = bosun(data.path(), cdir.path()).args(args).output().unwrap();
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    let json = |args: &[&str]| serde_json::from_str::<serde_json::Value>(&ok(args)).unwrap();
    let write = |name: &str, text: &str| {
        let p = cdir.path().join(name);
        std::fs::write(&p, text).unwrap();
        p.to_str().unwrap().to_string()
    };

    // Scope: add, get (table and JSON), exclude, replace from a file.
    ok(&["scope", "add", "127.0.0.1", "--allow-private"]);
    assert!(ok(&["scope", "get"]).contains("include  127.0.0.1"));
    ok(&["scope", "add", "skip.test", "--exclude"]);
    assert_eq!(
        json(&["scope", "get", "--json"])["exclude"][0]["host"],
        "skip.test"
    );
    let f = write(
        "scope.json",
        r#"{"include":[{"host":"127.0.0.1","allow_private":true}],"exclude":[]}"#,
    );
    ok(&["scope", "set", &f]);
    assert_eq!(
        json(&["scope", "get", "--json"])["exclude"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // Rules: set replaces, import appends.
    let f = write(
        "rules.json",
        r#"[{"target":"request_header","match":"X-A: 1","replace":"X-A: 2"}]"#,
    );
    ok(&["rules", "set", &f]);
    ok(&["rules", "import", &f]);
    assert_eq!(json(&["rules", "get", "--json"]).as_array().unwrap().len(), 2);
    assert!(ok(&["rules", "get"]).contains("X-A: 1"));
    ok(&["rules", "set", &write("none.json", "[]")]);
    assert!(json(&["rules", "get", "--json"]).as_array().unwrap().is_empty());

    // Intercept: on, status, an empty queue, off.
    ok(&["intercept", "on", "--responses"]);
    let st = json(&["intercept", "status", "--json"]);
    assert_eq!(
        (st["requests"].clone(), st["responses"].clone()),
        (true.into(), true.into())
    );
    assert!(ok(&["intercept", "queue", "--quiet"]).is_empty());
    ok(&["intercept", "forward"]);
    ok(&["intercept", "off"]);
    assert_eq!(json(&["intercept", "status", "--json"])["requests"], false);

    // Make one flow through the Repeater, then read it back.
    let (port, srv) = target();
    let req = write(
        "req.txt",
        &format!("GET /x?a=1 HTTP/1.1\nHost: 127.0.0.1:{port}\nConnection: close\n\n"),
    );
    ok(&["repeater", "send", &format!("http://127.0.0.1:{port}"), &req]);
    srv.join().unwrap();
    let mut list = json(&["history", "list", "--json"]);
    for _ in 0..50 {
        if !list.as_array().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        list = json(&["history", "list", "--json"]);
    }
    let id = list[0]["id"].as_i64().unwrap();
    assert_eq!(list[0]["status"], 200);
    assert!(ok(&["history", "list"]).starts_with("ID"));
    assert!(!ok(&["history", "list", "-q"]).starts_with("ID"));
    assert_eq!(
        ok(&["history", "search", "status:200", "--ndjson"])
            .lines()
            .count(),
        1
    );
    let none = bosun(data.path(), cdir.path())
        .args(["history", "search", "status:404"])
        .output()
        .unwrap();
    assert_eq!(none.status.code(), Some(4));
    let shown = ok(&["history", "show", &id.to_string()]);
    assert!(shown.contains("GET /x?a=1") && shown.contains("200"), "{shown}");
    assert_eq!(
        ok(&[
            "history",
            "show",
            &id.to_string(),
            "--part",
            "response",
            "--body-only"
        ]),
        "hello!\n"
    );

    // Export: HAR and ndjson.
    let har = json(&["history", "export"]);
    assert_eq!(har["log"]["version"], "1.2");
    let e = &har["log"]["entries"][0];
    assert_eq!(e["request"]["method"], "GET");
    assert_eq!(e["request"]["queryString"][0]["name"], "a");
    assert_eq!(e["response"]["status"], 200);
    assert_eq!(e["response"]["content"]["text"], "hello!\n");
    let nd = ok(&["history", "export", "--format", "ndjson"]);
    let first: serde_json::Value = serde_json::from_str(nd.lines().next().unwrap()).unwrap();
    assert_eq!(first["id"], id);
    assert!(
        first["response_head"]
            .as_str()
            .unwrap()
            .starts_with("HTTP/1.1 200")
    );

    // CA from the engine, and the event stream's hello.
    assert!(ok(&["ca", "export", "--profile", "default"]).starts_with("-----BEGIN CERTIFICATE"));
    let ev = ok(&["events", "--count", "1"]);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&ev).unwrap()["type"],
        "hello"
    );

    drop(engine.stdin.take());
    let _ = engine.wait();
}

#[test]
fn a_bad_target_is_refused_before_anything_is_sent() {
    let cdir = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let out = run_with_stdin(
        {
            let mut c = bosun(data.path(), cdir.path());
            c.args(["repeater", "send", "ftp://x", "--server", "http://127.0.0.1:1"]);
            c
        },
        "GET / HTTP/1.1\n\n",
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("http or https"));
}

#[test]
fn report_renders_issues_offline_and_redacts() {
    let d = tempfile::tempdir().unwrap();
    let issues = r#"[{"id":1,"issue_type":"x","title":"T <b>","severity":"high","confidence":"firm","status":"new",
        "method":"GET","url":"https://h.example/?token=s3cret"}]"#;
    let mut c = bosun(d.path(), d.path());
    c.args(["report", "--input", "-", "--format", "sarif"]);
    let out = run_with_stdin(c, issues);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("\"version\": \"2.1.0\"") && !text.contains("s3cret"));
    let mut c = bosun(d.path(), d.path());
    c.args(["report", "--input", "-", "--format", "json", "--no-redact"]);
    let out = run_with_stdin(c, issues);
    assert!(String::from_utf8(out.stdout).unwrap().contains("s3cret"));
}
