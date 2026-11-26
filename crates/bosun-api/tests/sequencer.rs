#![allow(clippy::unwrap_used)]
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::stack;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn splitmix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn random_token(i: u64) -> String {
    format!("{:016x}{:016x}", splitmix(i * 2), splitmix(i * 2 + 1))
}

/// A server that sets a session cookie on each request: a counter, or random-looking.
async fn origin(counter: bool) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let n = Arc::new(AtomicU64::new(1000));
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let n = n.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    let k = s.read(&mut buf).await.unwrap_or(0);
                    if k == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..k]);
                }
                let i = n.fetch_add(1, Ordering::SeqCst);
                let tok = if counter { i.to_string() } else { random_token(i) };
                let body = format!("{{\"csrf\":\"{tok}\"}}");
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nSet-Cookie: sid={tok}; Path=/\r\nX-Token: {tok}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    port
}

async fn post(
    s: &common::Stack,
    c: &reqwest::Client,
    csrf: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let r = c
        .post(s.url(path))
        .header("x-csrf-token", csrf)
        .json(&body)
        .send()
        .await
        .unwrap();
    let st = r.status();
    (st, r.json().await.unwrap_or(Value::Null))
}

fn capture_body(port: u16, source: Value, count: u32, delay_ms: u64) -> Value {
    json!({
        "scheme": "http", "host": "127.0.0.1", "port": port,
        "request": B64.encode(b"GET /login HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
        "source": source, "count": count, "delay_ms": delay_ms,
    })
}

async fn allow_loopback(s: &common::Stack, c: &reqwest::Client, csrf: &str) {
    let r = c
        .put(s.url("/scope"))
        .header("x-csrf-token", csrf)
        .json(&json!({ "include": [{ "host": "127.0.0.1", "allow_private": true }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

/// Poll until the capture leaves `running`.
async fn finished(s: &common::Stack, c: &reqwest::Client, id: u64) -> Value {
    let t = Instant::now();
    loop {
        let v: Value = c
            .get(s.url(&format!("/sequencer/capture/{id}")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if v["state"] != "running" {
            return v;
        }
        assert!(t.elapsed() < Duration::from_secs(20), "still running: {v}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn analysis_gives_verdicts_for_manual_tokens() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let good: Vec<String> = (0..300).map(random_token).collect();
    let (st, v) = post(&s, &c, &csrf, "/sequencer/analyze", json!({ "tokens": good })).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["verdict"], "excellent", "{v}");
    assert_eq!(v["reliable"], true);
    let bad: Vec<String> = (5000..5300).map(|i: u32| i.to_string()).collect();
    let (_, v) = post(&s, &c, &csrf, "/sequencer/analyze", json!({ "tokens": bad })).await;
    assert_eq!(v["verdict"], "not_random", "{v}");
    let (st, v) = post(
        &s,
        &c,
        &csrf,
        "/sequencer/analyze",
        json!({ "tokens": ["a", "b"] }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn a_capture_goes_through_the_gate_and_is_recorded() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let port = origin(false).await;
    let cookie = json!({ "kind": "cookie", "name": "sid" });

    // Nothing is in scope: the gate refuses and nothing is recorded.
    let (st, v) = post(
        &s,
        &c,
        &csrf,
        "/sequencer/capture",
        capture_body(port, cookie.clone(), 5, 0),
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED, "{v}");
    let done = finished(&s, &c, v["id"].as_u64().unwrap()).await;
    assert_eq!(done["state"], "failed", "{done}");
    assert!(done["last_error"].as_str().unwrap().contains("scope"), "{done}");
    s.state.inner.proxy.flush();
    assert_eq!(s.project.flow_count().unwrap(), 0);

    // In scope: every request is sent, recorded, and its cookie taken.
    allow_loopback(&s, &c, &csrf).await;
    let (_, v) = post(
        &s,
        &c,
        &csrf,
        "/sequencer/capture",
        capture_body(port, cookie, 150, 0),
    )
    .await;
    let id = v["id"].as_u64().unwrap();
    let done = finished(&s, &c, id).await;
    assert_eq!(done["state"], "done", "{done}");
    assert_eq!(done["sent"], 150);
    assert_eq!(done["tokens"].as_array().unwrap().len(), 150);
    s.state.inner.proxy.flush();
    assert_eq!(s.project.flow_count().unwrap(), 150);
    let f: Value = c.get(s.url("/flows")).send().await.unwrap().json().await.unwrap();
    assert!(f.to_string().contains("repeater"), "{f}");

    // The tokens go to the analysis, and from an offset only the later ones come back.
    let tokens = done["tokens"].clone();
    let (_, a) = post(&s, &c, &csrf, "/sequencer/analyze", json!({ "tokens": tokens })).await;
    assert_eq!(a["verdict"], "excellent", "{a}");
    let part: Value = c
        .get(s.url(&format!("/sequencer/capture/{id}?from=140")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(part["tokens"].as_array().unwrap().len(), 10);
    assert_eq!(part["extracted"], 150);
}

#[tokio::test]
async fn header_and_body_sources_and_a_counter_server() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    allow_loopback(&s, &c, &csrf).await;
    let port = origin(true).await;
    for source in [
        json!({ "kind": "header", "name": "X-Token" }),
        json!({ "kind": "regex", "pattern": "\"csrf\":\"(\\d+)\"" }),
    ] {
        let (_, v) = post(
            &s,
            &c,
            &csrf,
            "/sequencer/capture",
            capture_body(port, source, 100, 0),
        )
        .await;
        let done = finished(&s, &c, v["id"].as_u64().unwrap()).await;
        assert_eq!(done["state"], "done", "{done}");
        let (_, a) = post(
            &s,
            &c,
            &csrf,
            "/sequencer/analyze",
            json!({ "tokens": done["tokens"] }),
        )
        .await;
        assert_eq!(a["verdict"], "not_random", "{a}");
    }
    // A token that is not there is counted, not an error.
    let (_, v) = post(
        &s,
        &c,
        &csrf,
        "/sequencer/capture",
        capture_body(port, json!({ "kind": "cookie", "name": "nope" }), 3, 0),
    )
    .await;
    let done = finished(&s, &c, v["id"].as_u64().unwrap()).await;
    assert_eq!(
        (done["missing"].as_u64(), done["extracted"].as_u64()),
        (Some(3), Some(0)),
        "{done}"
    );
}

#[tokio::test]
async fn the_stop_switch_the_caps_and_the_rate_limit() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    allow_loopback(&s, &c, &csrf).await;
    let port = origin(false).await;
    let cookie = json!({ "kind": "cookie", "name": "sid" });

    // Stop a slow capture.
    let (_, v) = post(
        &s,
        &c,
        &csrf,
        "/sequencer/capture",
        capture_body(port, cookie.clone(), 1000, 100),
    )
    .await;
    let id = v["id"].as_u64().unwrap();
    tokio::time::sleep(Duration::from_millis(350)).await;
    let (st, _) = post(&s, &c, &csrf, &format!("/sequencer/capture/{id}/stop"), json!({})).await;
    assert_eq!(st, StatusCode::OK);
    let done = finished(&s, &c, id).await;
    assert_eq!(done["state"], "stopped", "{done}");
    assert!(done["sent"].as_u64().unwrap() < 20, "{done}");

    // Limits are refused.
    for (b, what) in [
        (capture_body(port, cookie.clone(), 0, 0), "count 0"),
        (capture_body(port, cookie.clone(), 5001, 0), "count too large"),
        (capture_body(port, cookie.clone(), 5, 10_001), "delay too long"),
        (
            capture_body(port, json!({ "kind": "regex", "pattern": "(" }), 5, 0),
            "bad pattern",
        ),
    ] {
        let (st, v) = post(&s, &c, &csrf, "/sequencer/capture", b).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{what}: {v}");
    }
    let r = c.get(s.url("/sequencer/capture/9999")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    // The gate's per-host rate limit slows the capture down instead of failing it.
    s.state.inner.gate.set_rate_limit(5);
    let t = Instant::now();
    let (_, v) = post(
        &s,
        &c,
        &csrf,
        "/sequencer/capture",
        capture_body(port, cookie.clone(), 12, 0),
    )
    .await;
    let done = finished(&s, &c, v["id"].as_u64().unwrap()).await;
    s.state.inner.gate.set_rate_limit(0);
    assert_eq!(done["state"], "done", "{done}");
    assert_eq!(done["tokens"].as_array().unwrap().len(), 12);
    assert!(t.elapsed() >= Duration::from_secs(1), "{:?}", t.elapsed());

    // The kill switch fails a capture.
    c.put(s.url("/tools/stop"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "stopped": true }))
        .send()
        .await
        .unwrap();
    let (_, v) = post(
        &s,
        &c,
        &csrf,
        "/sequencer/capture",
        capture_body(port, cookie, 5, 0),
    )
    .await;
    let done = finished(&s, &c, v["id"].as_u64().unwrap()).await;
    assert_eq!(done["state"], "failed", "{done}");
}

#[tokio::test]
async fn a_viewer_may_analyse_but_not_capture() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let r = c
        .post(s.url("/users"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "username": "view", "password": "a long enough password", "role": "viewer" }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    let v = common::client();
    let r = v
        .post(s.url("/auth/login"))
        .json(&json!({ "username": "view", "password": "a long enough password" }))
        .send()
        .await
        .unwrap();
    let me: Value = r.json().await.unwrap();
    let vcsrf = me["csrf"].as_str().unwrap().to_string();
    let toks: Vec<String> = (0..30).map(random_token).collect();
    let (st, _) = post(&s, &v, &vcsrf, "/sequencer/analyze", json!({ "tokens": toks })).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = post(
        &s,
        &v,
        &vcsrf,
        "/sequencer/capture",
        capture_body(1, json!({ "kind": "cookie", "name": "sid" }), 1, 0),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}
