#![allow(clippy::unwrap_used)]
mod common;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bosun_client::Event;
use common::{Stack, client, stack};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A server that answers `200 <target>` to everything, after `delay_ms`.
async fn origin(delay_ms: u64) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                let target = String::from_utf8_lossy(&got)
                    .split(' ')
                    .nth(1)
                    .unwrap_or("")
                    .to_string();
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let body = format!("hello {target}");
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

fn attack(port: u16, request: &str, kind: &str, sets: Value) -> Value {
    json!({
        "scheme": "http", "host": "127.0.0.1", "port": port,
        "request": B64.encode(request),
        "attack_type": kind,
        "payload_sets": sets,
        "greps": { "matches": [{ "pattern": "hello" }], "extracts": [{ "pattern": "hello /(\\w+)" }] },
    })
}

fn list(items: &[&str]) -> Value {
    json!({ "source": { "type": "list", "items": items } })
}

async fn in_scope(s: &Stack, c: &reqwest::Client, csrf: &str) {
    let r = c
        .put(s.url("/scope"))
        .header("x-csrf-token", csrf)
        .json(&json!({ "include": [{ "host": "127.0.0.1", "allow_private": true }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

async fn signed_in(s: &Stack) -> bosun_client::Client {
    let cl = bosun_client::Client::new(format!("http://127.0.0.1:{}", s.api.port())).unwrap();
    cl.login("admin", "a long enough password").await.unwrap();
    cl
}

/// Wait until the attack is over.
async fn finished(cl: &bosun_client::Client, id: i64) -> Value {
    for _ in 0..200 {
        let a = cl.intruder_attack(id).await.unwrap();
        if a["state"] != "running" {
            return a;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the attack did not finish");
}

#[tokio::test]
async fn an_attack_runs_stores_its_results_and_streams_them() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    in_scope(&s, &c, &csrf).await;
    let port = origin(0).await;
    let cl = signed_in(&s).await;
    let mut events = cl.events(None).await.unwrap();

    let body = attack(
        port,
        "GET /§a§/§b§ HTTP/1.1\r\nHost: x\r\n\r\n",
        "cluster_bomb",
        json!([list(&["one", "two"]), list(&["x", "y", "z"])]),
    );
    let plan = cl.intruder_plan(&body).await.unwrap();
    assert_eq!(
        (plan["total"].as_u64(), plan["positions"].as_u64()),
        (Some(6), Some(2))
    );
    assert_eq!(plan["preview"][1]["payloads"], json!(["one", "y"]));

    let started = cl.intruder_start(&body).await.unwrap();
    let id = started["id"].as_i64().unwrap();
    assert_eq!(started["total"], 6);
    let done = finished(&cl, id).await;
    assert_eq!(
        (done["state"].as_str(), done["done"].as_u64()),
        (Some("completed"), Some(6))
    );
    assert_eq!(done["config"]["attack_type"], "cluster_bomb");

    // The results are stored, in order, with grep applied and a flow for each request.
    let r = cl.intruder_results(id, 0, 100).await.unwrap();
    let rows = r["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 6);
    assert_eq!(rows[4]["payloads"], json!(["two", "y"]));
    assert_eq!(rows[4]["status"], 200);
    assert_eq!(rows[4]["matches"], json!([true]));
    assert_eq!(rows[4]["extracts"], json!(["two"]));
    assert!(rows[4]["flow_id"].as_i64().is_some());
    assert_eq!(
        cl.intruder_results(id, 4, 100).await.unwrap()["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    s.state.inner.proxy.flush();
    let f: Value = c.get(s.url("/flows")).send().await.unwrap().json().await.unwrap();
    assert!(f.to_string().contains("intruder"), "{f}");
    assert_eq!(s.project.flow_count().unwrap(), 6);

    // ... and they were sent on the event stream while it ran.
    let mut seen = 0;
    let mut ended = false;
    while !ended {
        let e = tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("an event")
            .unwrap()
            .unwrap();
        match e.event {
            Event::IntruderResult {
                attack_id, status, ..
            } if attack_id == id => {
                assert_eq!(status, Some(200));
                seen += 1;
            }
            Event::IntruderState { attack_id, state, .. } if attack_id == id && state == "completed" => {
                ended = true;
            }
            _ => {}
        }
    }
    assert_eq!(seen, 6);

    // The list shows it; starting and deleting are audited.
    assert_eq!(cl.intruder_attacks().await.unwrap()["attacks"][0]["id"], id);
    cl.intruder_delete(id).await.unwrap();
    assert!(cl.intruder_attack(id).await.is_err());
    assert!(
        cl.intruder_attacks().await.unwrap()["attacks"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    let audit = audit.to_string();
    assert!(
        audit.contains("intruder.start") && audit.contains("intruder.delete"),
        "{audit}"
    );
}

#[tokio::test]
async fn an_attack_out_of_scope_fails_and_sends_nothing() {
    let s = stack(true).await;
    let (_c, _csrf) = s.admin().await;
    let port = origin(0).await;
    let cl = signed_in(&s).await;
    let id = cl
        .intruder_start(&attack(
            port,
            "GET /§a§ HTTP/1.1\r\n\r\n",
            "sniper",
            json!([list(&["1", "2"])]),
        ))
        .await
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let done = finished(&cl, id).await;
    assert_eq!(done["state"], "failed");
    assert!(done["error"].as_str().unwrap().contains("out of scope"), "{done}");
    s.state.inner.proxy.flush();
    assert_eq!(s.project.flow_count().unwrap(), 0);
}

#[tokio::test]
async fn the_stop_switch_ends_a_running_attack() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    in_scope(&s, &c, &csrf).await;
    let port = origin(1500).await;
    let cl = signed_in(&s).await;
    let mut b = attack(
        port,
        "GET /§a§ HTTP/1.1\r\n\r\n",
        "battering_ram",
        json!([{ "source": { "type": "null", "count": 50 } }]),
    );
    b["options"] = json!({ "concurrency": 2 });
    let id = cl.intruder_start(&b).await.unwrap()["id"].as_i64().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // A running attack cannot be deleted.
    assert!(cl.intruder_delete(id).await.is_err());
    assert!(cl.intruder_stop(id).await.unwrap());
    let done = tokio::time::timeout(Duration::from_secs(2), finished(&cl, id))
        .await
        .unwrap();
    assert_eq!(done["state"], "stopped");
    assert!(done["done"].as_u64().unwrap() < 50);
    // Stopping again is harmless.
    assert!(!cl.intruder_stop(id).await.unwrap());
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    assert!(audit.to_string().contains("intruder.stop"));
}

#[tokio::test]
async fn bad_attacks_are_rejected_and_viewers_cannot_start() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    in_scope(&s, &c, &csrf).await;
    let cl = signed_in(&s).await;
    let ok = attack(1, "GET /§a§ HTTP/1.1\r\n\r\n", "sniper", json!([list(&["1"])]));
    let with = |k: &str, v: Value| {
        let mut b = ok.clone();
        b[k] = v;
        b
    };
    let rejected = |b: Value| {
        let cl = cl.clone();
        async move { cl.intruder_start(&b).await.unwrap_err().status() }
    };
    assert_eq!(
        rejected(with("request", json!(B64.encode("GET / HTTP/1.1\r\n\r\n")))).await,
        Some(400),
        "no positions"
    );
    assert_eq!(
        rejected(with("request", json!(B64.encode("GET /§a HTTP/1.1\r\n\r\n")))).await,
        Some(400),
        "unpaired"
    );
    assert_eq!(rejected(with("request", json!("not base64!"))).await, Some(400));
    assert_eq!(rejected(with("payload_sets", json!([]))).await, Some(400));
    let mut two = with("attack_type", json!("pitchfork"));
    two["request"] = json!(B64.encode("GET /§a§/§b§ HTTP/1.1\r\n\r\n"));
    assert_eq!(rejected(two).await, Some(400), "needs a set per position");
    assert_eq!(rejected(with("port", json!(0))).await, Some(400));
    assert_eq!(
        rejected(with("options", json!({ "concurrency": 0 }))).await,
        Some(400)
    );
    assert_eq!(
        rejected(with(
            "greps",
            json!({ "matches": [{ "pattern": "(", "regex": true }] })
        ))
        .await,
        Some(400)
    );
    assert_eq!(
        rejected(with(
            "payload_sets",
            json!([{ "source": { "type": "list", "items": ["a"] }, "processing": [{ "type": "replace_regex", "pattern": "(", "replacement": "" }] }])
        ))
        .await,
        Some(400)
    );
    assert_eq!(
        rejected(with("payload_sets", json!([{ "source": { "type": "brute_force", "charset": "abcdefghij", "min_len": 1, "max_len": 12 } }]))).await,
        Some(400),
        "too many requests"
    );
    assert_eq!(
        rejected(with("payload_sets", json!([list(&[])]))).await,
        Some(400),
        "no requests"
    );

    // A viewer may read attacks and not start, plan or stop them.
    c.post(s.url("/users"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "username": "watcher", "password": "another long password", "role": "viewer" }))
        .send()
        .await
        .unwrap();
    let viewer = client();
    let v: Value = viewer
        .post(s.url("/auth/login"))
        .json(&json!({ "username": "watcher", "password": "another long password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let vcsrf = v["csrf"].as_str().unwrap();
    for (path, method) in [
        ("/intruder/plan", "post"),
        ("/intruder/attacks", "post"),
        ("/intruder/attacks/1/stop", "post"),
    ] {
        let rb = if method == "post" {
            viewer.post(s.url(path))
        } else {
            viewer.get(s.url(path))
        };
        let r = rb.header("x-csrf-token", vcsrf).json(&ok).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "{path}");
    }
    assert_eq!(
        viewer
            .get(s.url("/intruder/attacks"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        viewer
            .delete(s.url("/intruder/attacks/1"))
            .header("x-csrf-token", vcsrf)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}
