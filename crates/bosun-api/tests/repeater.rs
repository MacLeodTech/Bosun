#![allow(clippy::unwrap_used)]
mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::{client, stack};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A server that answers each connection once with `body` and closes.
async fn origin() -> u16 {
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
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
                    .await;
            });
        }
    });
    port
}

fn body(port: u16, count: u32, mode: &str) -> Value {
    json!({
        "scheme": "http", "host": "127.0.0.1", "port": port,
        "request": B64.encode(b"GET /r HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
        "count": count, "mode": mode,
    })
}

#[tokio::test]
async fn a_send_goes_through_the_gate_and_is_recorded() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let port = origin().await;
    let post = |b: Value| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url("/repeater/send"));
        async move {
            c.post(url)
                .header("x-csrf-token", csrf)
                .json(&b)
                .send()
                .await
                .unwrap()
        }
    };

    // Nothing is in scope yet: refused, nothing recorded.
    let v: Value = post(body(port, 1, "sequential")).await.json().await.unwrap();
    assert_eq!(v["results"][0]["refused"], true, "{v}");
    assert!(v["results"][0]["flow_id"].is_null());
    s.state.inner.proxy.flush();
    assert_eq!(s.project.flow_count().unwrap(), 0);

    // In scope (loopback needs allow_private): it is sent and recorded as a repeater flow.
    let r = c
        .put(s.url("/scope"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "include": [{ "host": "127.0.0.1", "allow_private": true }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value = post(body(port, 3, "parallel")).await.json().await.unwrap();
    let rs = v["results"].as_array().unwrap();
    assert_eq!(rs.len(), 3);
    for r in rs {
        assert_eq!(r["status"], 200, "{v}");
        assert!(
            B64.decode(r["response"].as_str().unwrap())
                .unwrap()
                .ends_with(b"hello")
        );
        assert_eq!(r["in_scope"], true);
    }
    s.state.inner.proxy.flush();
    assert_eq!(s.project.flow_count().unwrap(), 3);
    let f: Value = c.get(s.url("/flows")).send().await.unwrap().json().await.unwrap();
    assert!(f.to_string().contains("repeater"), "{f}");

    // The kill switch stops it.
    c.put(s.url("/tools/stop"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "stopped": true }))
        .send()
        .await
        .unwrap();
    let v: Value = post(body(port, 1, "sequential")).await.json().await.unwrap();
    assert_eq!(v["results"][0]["refused"], true);
}

#[tokio::test]
async fn out_of_scope_sends_need_an_explicit_audited_setting() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let port = origin().await;
    // Loopback is private, so even out of scope it needs the rule's allow_private: use an unrelated scope.
    c.put(s.url("/scope"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "include": [{ "host": "somewhere.test" }] }))
        .send()
        .await
        .unwrap();
    let get = |c: reqwest::Client| {
        let u = s.url("/repeater/settings");
        async move { c.get(u).send().await.unwrap().json::<Value>().await.unwrap() }
    };
    assert_eq!(get(c.clone()).await["allow_out_of_scope"], false);
    let r = c
        .put(s.url("/repeater/settings"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "allow_out_of_scope": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(get(c.clone()).await["allow_out_of_scope"], true);
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    assert!(audit.to_string().contains("repeater.settings"), "{audit}");
    // Opening or closing a project puts it back to refuse.
    let r = c
        .post(s.url("/projects/close"))
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    assert_eq!(get(c.clone()).await["allow_out_of_scope"], false);
    let _ = port;
}

#[tokio::test]
async fn bad_requests_are_rejected_and_viewers_cannot_send() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let send = |b: Value| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url("/repeater/send"));
        async move {
            c.post(url)
                .header("x-csrf-token", csrf)
                .json(&b)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    let ok = body(1, 1, "sequential");
    let with = |k: &str, v: Value| {
        let mut b = ok.clone();
        b[k] = v;
        b
    };
    assert_eq!(send(with("count", json!(0))).await, StatusCode::BAD_REQUEST);
    assert_eq!(send(with("count", json!(101))).await, StatusCode::BAD_REQUEST);
    assert_eq!(
        send(with("request", json!("not base64!"))).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(send(with("request", json!(""))).await, StatusCode::BAD_REQUEST);
    assert_eq!(send(with("port", json!(0))).await, StatusCode::BAD_REQUEST);
    assert_eq!(
        send(with("mode", json!("single_packet"))).await,
        StatusCode::BAD_REQUEST,
        "needs h2"
    );
    let mut h2 = with("protocol", json!("h2"));
    h2["follow_redirects"] = json!(true);
    assert_eq!(send(h2).await, StatusCode::BAD_REQUEST);

    // A viewer may read the setting and not send.
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
    assert_eq!(
        viewer
            .get(s.url("/repeater/settings"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    for (m, p, b) in [
        ("post", "/repeater/send", ok.clone()),
        ("put", "/repeater/settings", json!({ "allow_out_of_scope": true })),
        ("post", "/repeater/ws", ok.clone()),
        ("put", "/repeater/tabs", json!({ "tabs": [] })),
    ] {
        let rb = if m == "post" {
            viewer.post(s.url(p))
        } else {
            viewer.put(s.url(p))
        };
        let r = rb.header("x-csrf-token", vcsrf).json(&b).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "{p}");
    }
    // And unauthenticated callers get nothing.
    let r = client()
        .post(s.url("/repeater/send"))
        .json(&ok)
        .send()
        .await
        .unwrap();
    assert!(matches!(
        r.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));
}

#[tokio::test]
async fn the_client_can_send_and_change_the_setting() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    c.put(s.url("/scope"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "include": [{ "host": "127.0.0.1", "allow_private": true }] }))
        .send()
        .await
        .unwrap();
    let port = origin().await;
    let cl = bosun_client::Client::new(format!("http://127.0.0.1:{}", s.api.port())).unwrap();
    cl.login("admin", "a long enough password").await.unwrap();
    let v = cl.repeater_send(&body(port, 2, "sequential")).await.unwrap();
    assert_eq!(v["results"].as_array().unwrap().len(), 2);
    assert!(!cl.repeater_settings().await.unwrap());
    assert!(cl.put_repeater_settings(true).await.unwrap());
}

#[tokio::test]
async fn tabs_are_saved_in_the_project_and_bounded() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let put = |b: Value| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url("/repeater/tabs"));
        async move {
            c.put(url)
                .header("x-csrf-token", csrf)
                .json(&b)
                .send()
                .await
                .unwrap()
        }
    };

    // Nothing saved yet.
    let v: Value = c
        .get(s.url("/repeater/tabs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["tabs"], json!([]));

    // Saved, and read back as written (including fields the server does not know).
    let doc = json!({ "tabs": [{ "id": 1, "host": "a.test", "request": "GET / HTTP/1.1\r\n\r\n", "extra": [1, 2] }], "active": 1, "next": 2 });
    assert_eq!(put(doc.clone()).await.status(), StatusCode::OK);
    let v: Value = c
        .get(s.url("/repeater/tabs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v, doc);
    // It is in the project file, so another project would not see it.
    assert!(
        s.project
            .setting::<Value>(bosun_api::SETTING_REPEATER_TABS)
            .unwrap()
            .is_some()
    );

    // Bounds: too many tabs, and something that is not a tab.
    let many: Vec<Value> = (0..101).map(|i| json!({ "id": i })).collect();
    assert_eq!(
        put(json!({ "tabs": many })).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put(json!({ "tabs": ["x"] })).await.status(),
        StatusCode::BAD_REQUEST
    );
    // Refused saves leave the stored tabs alone.
    let v: Value = c
        .get(s.url("/repeater/tabs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v, doc);

    // Writing needs a CSRF token like every other change.
    let r = c.put(s.url("/repeater/tabs")).json(&doc).send().await.unwrap();
    assert!(r.status().is_client_error());

    // The client crate reads and writes it too.
    let cl = bosun_client::Client::new(format!("http://127.0.0.1:{}", s.api.port())).unwrap();
    cl.login("admin", "a long enough password").await.unwrap();
    assert_eq!(cl.repeater_tabs().await.unwrap(), doc);
    let doc2 = json!({ "tabs": [], "active": 0, "next": 1 });
    assert_eq!(cl.put_repeater_tabs(&doc2).await.unwrap(), doc2);
}

/// Accepts the upgrade and echoes every frame back unmasked, with the same opcode and flags.
async fn ws_origin() -> u16 {
    use bosun_http::ws::{Frame, parse_frame};
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let _ = s
                    .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n")
                    .await;
                let (mut buf, mut chunk) = (Vec::new(), [0u8; 4096]);
                loop {
                    let n = s.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    while let Ok(Some((f, used))) = parse_frame(&buf, 1 << 20) {
                        buf.drain(..used);
                        let _ = s.write_all(&Frame { mask: None, ..f }.encode()).await;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn websocket_frames_are_sent_as_described_and_recorded() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let handshake = B64.encode(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    );
    let port = ws_origin().await;
    let post = |b: Value| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url("/repeater/ws"));
        async move {
            c.post(url)
                .header("x-csrf-token", csrf)
                .json(&b)
                .send()
                .await
                .unwrap()
        }
    };
    let body = json!({
        "scheme": "http", "host": "127.0.0.1", "port": port, "request": handshake, "listen_ms": 400,
        "frames": [
            { "opcode": 1, "payload": B64.encode(b"hello") },
            { "opcode": 2, "fin": false, "rsv": 0, "mask": "01020304", "payload": B64.encode([1u8, 2, 3]) },
            { "opcode": 9, "mask": "none", "payload": "" },
        ],
    });

    // Out of scope: refused, nothing sent.
    let v: Value = post(body.clone()).await.json().await.unwrap();
    assert_eq!(v["refused"], true, "{v}");
    assert!(v["flow_id"].is_null());

    c.put(s.url("/scope"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "include": [{ "host": "127.0.0.1", "allow_private": true }] }))
        .send()
        .await
        .unwrap();
    let v: Value = post(body.clone()).await.json().await.unwrap();
    assert_eq!(v["status"], 101, "{v}");
    assert!(v["error"].is_null(), "{v}");
    let frames = v["frames"].as_array().unwrap();
    let sent: Vec<_> = frames
        .iter()
        .filter(|f| f["direction"] == "client_to_server")
        .collect();
    let got: Vec<_> = frames
        .iter()
        .filter(|f| f["direction"] == "server_to_client")
        .collect();
    // Three frames as written, then our close; the echo returns the three (flags kept) before the close is sent.
    assert_eq!(sent.len(), 4, "{v}");
    assert_eq!(got.len(), 3, "{v}");
    assert_eq!(got[0]["opcode"], 1);
    assert_eq!(got[0]["payload"], B64.encode(b"hello"));
    assert_eq!(got[1]["fin"], false);
    assert_eq!(got[1]["opcode"], 2);
    assert_eq!(sent[1]["masked"], true);
    assert_eq!(sent[2]["masked"], false);

    // The handshake is a repeater flow and the frames are its messages.
    s.state.inner.proxy.flush();
    let id = v["flow_id"].as_i64().unwrap();
    let flow = s.project.get_flow(id).unwrap().unwrap();
    assert_eq!(flow.summary.source.as_str(), "repeater");
    let msgs = s.project.ws_messages(id, None, 100).unwrap();
    assert_eq!(msgs.len(), 7, "3 sent, 3 echoed, 1 close");

    // Not an upgrade: the answer is shown and recorded, with no frames.
    let plain = origin().await;
    let mut b2 = body.clone();
    b2["port"] = json!(plain);
    let v: Value = post(b2).await.json().await.unwrap();
    assert_eq!(v["status"], 200, "{v}");
    assert!(v["error"].as_str().unwrap().contains("did not switch"));
    assert_eq!(v["frames"], json!([]));

    // Bad input.
    for bad in [
        json!({ "frames": [{ "opcode": 16 }] }),
        json!({ "frames": [{ "opcode": 1, "mask": "zz" }] }),
        json!({ "frames": [{ "opcode": 1, "payload": "!!" }] }),
        json!({ "listen_ms": 99999 }),
    ] {
        let mut b = body.clone();
        for (k, val) in bad.as_object().unwrap() {
            b[k] = val.clone();
        }
        assert_eq!(post(b).await.status(), StatusCode::BAD_REQUEST);
    }
}
