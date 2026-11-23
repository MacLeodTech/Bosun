//! Security behaviour of the API, end to end over real sockets.

#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

mod common;
use common::*;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bosun_store::Role;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn setup_needs_the_code_and_happens_once() {
    let s = stack(true).await;
    let c = client();
    let v: Value = c
        .get(s.url("/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["setup_required"], true);
    let r = c
        .post(s.url("/setup"))
        .json(&json!({ "code": "guess", "username": "admin", "password": "a long enough password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = c
        .post(s.url("/setup"))
        .json(&json!({ "code": s.code, "username": "admin", "password": "short" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    s.admin().await;
    let r = c
        .post(s.url("/setup"))
        .json(&json!({ "code": s.code, "username": "x", "password": "a long enough password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn everything_needs_auth_and_csrf() {
    let s = stack(true).await;
    assert_eq!(
        client().get(s.url("/flows")).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let (c, csrf) = s.admin().await;
    assert_eq!(
        c.get(s.url("/flows")).send().await.unwrap().status(),
        StatusCode::OK
    );
    let scope = json!({ "include": [{ "host": "example.com" }] });
    let r = c.put(s.url("/scope")).json(&scope).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "no CSRF token");
    let r = c
        .put(s.url("/scope"))
        .header("x-csrf-token", "wrong")
        .json(&scope)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = c
        .put(s.url("/scope"))
        .header("x-csrf-token", &csrf)
        .json(&scope)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let got: Value = c.get(s.url("/scope")).send().await.unwrap().json().await.unwrap();
    assert_eq!(got["include"][0]["host"], "example.com");
    let r = c.get(s.url("/flows")).send().await.unwrap();
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert!(
        r.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("script-src 'self'")
    );
    assert!(r.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn rebinding_hosts_and_foreign_origins_are_refused() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let r = c
        .get(s.url("/flows"))
        .header("host", "attacker.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::MISDIRECTED_REQUEST);
    let r = c
        .get(s.url("/flows"))
        .header("origin", "https://attacker.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = c
        .get(s.url("/flows"))
        .header("origin", "null")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = c
        .put(s.url("/intercept"))
        .header("origin", format!("http://localhost:{}", s.api.port() + 1))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "requests": true, "responses": false, "in_scope_only": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "same host, different port is a different origin"
    );
    let r = c
        .get(s.url("/flows"))
        .header("origin", format!("http://localhost:{}", s.api.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = c
        .get(s.url("/flows"))
        .header("sec-fetch-site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn api_tokens_and_roles() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let r = c
        .post(s.url("/users"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "username": "watcher", "password": "another long password", "role": "viewer" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
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
    let r = viewer
        .put(s.url("/scope"))
        .header("x-csrf-token", vcsrf)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "viewers can't change scope");
    assert_eq!(
        viewer.get(s.url("/users")).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let t: Value = c
        .post(s.url("/tokens"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "name": "ci" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = t["token"].as_str().unwrap();
    let bare = client();
    let r = bare
        .put(s.url("/scope"))
        .bearer_auth(token)
        .json(&json!({ "include": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "bearer tokens need no CSRF token");
    let r = bare
        .get(s.url("/flows"))
        .bearer_auth("bosun_wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "token.create")
    );
    let _ = s
        .app
        .list_users()
        .unwrap()
        .iter()
        .find(|u| u.role == Role::Viewer)
        .unwrap();
}

async fn try_login(c: &reqwest::Client, s: &Stack, xff: Option<&str>, password: &str) -> reqwest::Response {
    let mut r = c
        .post(s.url("/auth/login"))
        .json(&json!({ "username": "admin", "password": password }));
    if let Some(x) = xff {
        r = r.header("x-forwarded-for", x);
    }
    r.send().await.unwrap()
}

#[tokio::test]
async fn repeated_wrong_passwords_back_off() {
    let s = stack(true).await;
    s.admin().await;
    let c = client();
    // A few tries are free, then the pair is made to wait.
    for _ in 0..3 {
        let r = try_login(&c, &s, None, "wrong password!!").await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
    let r = try_login(&c, &s, None, "wrong password!!").await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers().contains_key("retry-after"));
    // Even the right password waits its turn from the same address...
    let r = try_login(&c, &s, None, "a long enough password").await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    // ...but only until the delay passes.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = try_login(&c, &s, None, "a long enough password").await;
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_burst_of_guesses_is_throttled_before_hashing_and_others_can_still_sign_in() {
    let s = stack_with(true, |c| c.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()]).await;
    s.admin().await;
    let attacker = "203.0.113.9";
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let url = s.url("/auth/login");
        tasks.push(tokio::spawn(async move {
            client()
                .post(url)
                .header("x-forwarded-for", attacker)
                .json(&json!({ "username": "admin", "password": "wrong password!!" }))
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    let mut hashed = 0;
    let mut refused = 0;
    for t in tasks {
        match t.await.unwrap() {
            StatusCode::UNAUTHORIZED => hashed += 1,
            StatusCode::TOO_MANY_REQUESTS => refused += 1,
            other => panic!("unexpected {other}"),
        }
    }
    assert!(hashed <= 3, "only the free attempts reach the hash: {hashed}");
    assert_eq!(hashed + refused, 50);
    // The admin is not locked out from anywhere else.
    let r = try_login(&client(), &s, Some("198.51.100.7"), "a long enough password").await;
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn forwarded_headers_are_ignored_from_untrusted_peers_and_honoured_from_trusted_ones() {
    // Untrusted: the header is ignored, so rotating it doesn't dodge the throttle.
    let s = stack(true).await;
    s.admin().await;
    let c = client();
    for i in 0..3 {
        try_login(&c, &s, Some(&format!("203.0.113.{i}")), "wrong password!!").await;
    }
    let r = try_login(&c, &s, Some("203.0.113.99"), "wrong password!!").await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);

    // Trusted: each forwarded client is throttled on its own, and the audit log names it.
    let s = stack_with(true, |c| {
        c.trusted_proxies = vec!["127.0.0.1/32".parse().unwrap()]
    })
    .await;
    let (admin, _) = s.admin().await;
    let c = client();
    for _ in 0..3 {
        try_login(&c, &s, Some("203.0.113.5"), "wrong password!!").await;
    }
    assert_eq!(
        try_login(&c, &s, Some("203.0.113.5"), "wrong password!!")
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        try_login(&c, &s, Some("203.0.113.6"), "wrong password!!")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let audit: Value = admin
        .get(s.url("/audit"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "login.failed" && e["remote"] == "203.0.113.5")
    );
}

#[tokio::test]
async fn event_stream_checks_origin() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let s = stack(true).await;
    s.admin().await;
    // Log in again to read the cookie value for a raw WebSocket client.
    let r = client()
        .post(s.url("/auth/login"))
        .json(&json!({ "username": "admin", "password": "a long enough password" }))
        .send()
        .await
        .unwrap();
    let cookie = r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let url = format!("ws://127.0.0.1:{}/api/v1/events", s.api.port());

    let mut req = url.clone().into_client_request().unwrap();
    req.headers_mut().insert("cookie", cookie.parse().unwrap());
    req.headers_mut()
        .insert("origin", "https://attacker.example".parse().unwrap());
    assert!(
        tokio_tungstenite::connect_async(req).await.is_err(),
        "foreign origin must not get the stream"
    );

    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert("cookie", cookie.parse().unwrap());
    req.headers_mut().insert(
        "origin",
        format!("http://127.0.0.1:{}", s.api.port()).parse().unwrap(),
    );
    assert!(tokio_tungstenite::connect_async(req).await.is_ok());
}

#[tokio::test]
async fn the_proxy_cannot_reach_the_api() {
    for knows in [true, false] {
        let s = stack(knows).await;
        let c = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", s.proxy)).unwrap())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let r = c.get(s.url("/status")).send().await.unwrap();
        // Refused either by the proxy (it knows the API address) or by the API (it sees its own proxy's
        // outbound connection). The API refuses in one of two places depending on whether the proxy has
        // registered the connection by the time it is accepted: before any HTTP (the proxy then reports 502)
        // or per request (508). Both are refusals; what matters is that the request never reaches a handler.
        let ok: &[StatusCode] = if knows {
            &[StatusCode::BAD_GATEWAY]
        } else {
            &[StatusCode::BAD_GATEWAY, StatusCode::LOOP_DETECTED]
        };
        assert!(
            ok.contains(&r.status()),
            "proxy_knows_api={knows}: got {}",
            r.status()
        );
        assert!(!r.text().await.unwrap().contains("setup_required"));
    }
}

/// Send the start of a request one byte at a time; true if the server hung up before we finished.
async fn dribble_gets_cut_off(addr: SocketAddr) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head =
        b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let started = std::time::Instant::now();
    for b in head {
        if s.write_all(&[*b]).await.is_err() {
            return started.elapsed() < Duration::from_secs(8);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut buf = [0u8; 64];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(1), s.read(&mut buf)).await {
            // EOF, or an error response: the server gave up on us.
            let _ = n;
            return true;
        }
    }
    false
}

#[tokio::test]
async fn slow_header_senders_are_disconnected() {
    let s = stack_with(true, |c| c.header_timeout_secs = 1).await;
    assert!(dribble_gets_cut_off(s.api).await);
}

#[tokio::test]
async fn connections_over_the_cap_are_refused_while_existing_ones_keep_working() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let s = stack_with(true, |c| c.max_connections = 2).await;
    let req = b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let mut a = tokio::net::TcpStream::connect(s.api).await.unwrap();
    let mut b = tokio::net::TcpStream::connect(s.api).await.unwrap();
    // Make sure both are accepted (and counted) before the third arrives.
    for c in [&mut a, &mut b] {
        c.write_all(req).await.unwrap();
        let mut buf = [0u8; 12];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HTTP/1.1 200");
    }
    let mut third = tokio::net::TcpStream::connect(s.api).await.unwrap();
    let _ = third.write_all(req).await;
    let mut buf = [0u8; 12];
    let got = tokio::time::timeout(Duration::from_secs(5), third.read(&mut buf))
        .await
        .unwrap();
    assert!(
        matches!(got, Ok(0) | Err(_)),
        "the third connection gets nothing: {got:?}"
    );
    // The first two still work (after draining the rest of the first response).
    let mut sink = vec![0u8; 16384];
    let _ = tokio::time::timeout(Duration::from_millis(300), a.read(&mut sink)).await;
    a.write_all(req).await.unwrap();
    let mut buf = [0u8; 12];
    a.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"HTTP/1.1 200");
    // Freeing a slot lets a new connection in.
    drop(b);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut buf = [0u8; 12];
    let mut d = tokio::net::TcpStream::connect(s.api).await.unwrap();
    d.write_all(req).await.unwrap();
    d.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"HTTP/1.1 200");
}

async fn make_token(c: &reqwest::Client, s: &Stack, csrf: &str, body: Value) -> Value {
    let r = c
        .post(s.url("/tokens"))
        .header("x-csrf-token", csrf)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    r.json().await.unwrap()
}

#[tokio::test]
async fn a_password_change_ends_sessions_and_tokens() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let keep = make_token(&c, &s, &csrf, json!({ "name": "before" })).await;
    let token = keep["token"].as_str().unwrap();
    let bare = client();
    let ok = |r: reqwest::Response| r.status() == StatusCode::OK;
    assert!(ok(bare
        .get(s.url("/scope"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()));

    // Asking to keep tokens is honoured.
    let r = c
        .post(s.url("/auth/password"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "current": "a long enough password", "new": "a second long password", "revoke_tokens": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert!(ok(bare
        .get(s.url("/scope"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()));
    assert_eq!(
        c.get(s.url("/scope")).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "the session ended"
    );

    // By default the tokens go too.
    let c = client();
    let v: Value = c
        .post(s.url("/auth/login"))
        .json(&json!({ "username": "admin", "password": "a second long password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csrf = v["csrf"].as_str().unwrap();
    let r = c
        .post(s.url("/auth/password"))
        .header("x-csrf-token", csrf)
        .json(&json!({ "current": "a second long password", "new": "a third long password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        bare.get(s.url("/scope"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED,
        "a token made before the reset no longer works"
    );
}

#[tokio::test]
async fn read_tokens_cannot_change_anything_and_expired_tokens_do_not_work() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let t = make_token(
        &c,
        &s,
        &csrf,
        json!({ "name": "ro", "scope": "read", "expires_days": 1 }),
    )
    .await;
    assert_eq!(t["info"]["scope"], "read");
    assert!(t["info"]["expires_ms"].as_i64().unwrap() > 0);
    let token = t["token"].as_str().unwrap();
    let bare = client();
    assert_eq!(
        bare.get(s.url("/scope"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    for r in [
        bare.put(s.url("/scope"))
            .bearer_auth(token)
            .json(&json!({}))
            .send()
            .await
            .unwrap(),
        bare.post(s.url("/tokens"))
            .bearer_auth(token)
            .json(&json!({ "name": "x" }))
            .send()
            .await
            .unwrap(),
        bare.post(s.url("/intercept/forward-all"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap(),
    ] {
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    let bad = c
        .post(s.url("/tokens"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "name": "x", "expires_days": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    let admin = s.app.user_for_login("admin").unwrap().unwrap().0;
    s.app
        .create_api_token(
            "old",
            "bosun_expired",
            admin.id,
            bosun_store::TokenScope::Full,
            Some(1),
        )
        .unwrap();
    assert_eq!(
        bare.get(s.url("/scope"))
            .bearer_auth("bosun_expired")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn admins_change_roles_and_manage_sessions_and_tokens() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let me = s.app.user_for_login("admin").unwrap().unwrap().0;
    let r = c
        .post(s.url("/users"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "username": "pat", "password": "another long password", "role": "viewer" }))
        .send()
        .await
        .unwrap();
    let pat: Value = r.json().await.unwrap();
    let pat_id = pat["id"].as_i64().unwrap();

    // Pat signs in twice and makes a token.
    let mut pats = Vec::new();
    for _ in 0..2 {
        let pc = client();
        let v: Value = pc
            .post(s.url("/auth/login"))
            .json(&json!({ "username": "pat", "password": "another long password" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        pats.push((pc, v["csrf"].as_str().unwrap().to_string()));
    }
    make_token(&pats[0].0, &s, &pats[0].1, json!({ "name": "pat's" })).await;

    // Pat sees only their own sessions.
    let own: Value = pats[0]
        .0
        .get(s.url(&format!("/users/{pat_id}/sessions")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(own.as_array().unwrap().len(), 2);
    assert_eq!(
        pats[0]
            .0
            .get(s.url(&format!("/users/{}/sessions", me.id)))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        pats[0]
            .0
            .get(s.url(&format!("/users/{}/tokens", me.id)))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    // An admin lists them, revokes one, then the other.
    let list: Value = c
        .get(s.url(&format!("/users/{pat_id}/sessions")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let first = list[0]["id"].as_str().unwrap();
    let r = c
        .delete(s.url(&format!("/users/{pat_id}/sessions/{first}")))
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let alive = [
        pats[0].0.get(s.url("/scope")).send().await.unwrap().status() == StatusCode::OK,
        pats[1].0.get(s.url("/scope")).send().await.unwrap().status() == StatusCode::OK,
    ];
    assert_eq!(
        alive.iter().filter(|a| **a).count(),
        1,
        "exactly one session was revoked"
    );

    let toks: Value = c
        .get(s.url(&format!("/users/{pat_id}/tokens")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tid = toks[0]["id"].as_i64().unwrap();
    let r = c
        .delete(s.url(&format!("/users/{pat_id}/tokens/{tid}")))
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    // Role changes: tester now, the last admin stays admin, and the change ends the user's sessions.
    let r = c
        .put(s.url(&format!("/users/{pat_id}/role")))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "role": "tester" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    for (pc, _) in &pats {
        assert_eq!(
            pc.get(s.url("/scope")).send().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let r = c
        .put(s.url(&format!("/users/{}/role", me.id)))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "role": "viewer" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT, "never demote the last admin");

    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    let actions: Vec<_> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_string())
        .collect();
    for a in ["session.revoke", "token.revoke", "user.role"] {
        assert!(actions.iter().any(|x| x == a), "{a} missing from {actions:?}");
    }
}

#[tokio::test]
async fn intercept_changes_are_audited() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let r = c
        .put(s.url("/intercept"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "requests": true, "responses": false, "in_scope_only": true, "timeout_secs": 30 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = c
        .post(s.url("/intercept/forward-all"))
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    let find = |a: &str| {
        audit
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["action"] == a)
            .cloned()
    };
    assert!(
        find("intercept.settings").unwrap()["detail"]
            .as_str()
            .unwrap()
            .contains("timeout=30s")
    );
    assert!(find("intercept.forward_all").is_some());
}

/// Connect over TLS trusting only `root_der`; returns the certificate the server presented and the response to
/// `GET /api/v1/status`.
async fn tls_get(addr: SocketAddr, root_der: &[u8]) -> (Vec<u8>, String) {
    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(root_der.to_vec())).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("the certificate must verify against the expected root");
    let presented = tls.get_ref().1.peer_certificates().unwrap()[0].as_ref().to_vec();
    tls.write_all(
        format!(
            "GET /api/v1/status HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            addr.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    let _ = tls.read_to_string(&mut out).await;
    (presented, out)
}

#[tokio::test]
async fn the_ui_serves_configured_certificate_files_and_otherwise_its_own_self_signed_one() {
    use rustls::pki_types::pem::PemObject;
    let dir = tempfile::tempdir().unwrap();

    // Configured files: that exact certificate is served, and the UI answers over it.
    let pair = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&pair)
        .unwrap();
    let (cp, kp) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    std::fs::write(&cp, cert.pem()).unwrap();
    std::fs::write(&kp, pair.serialize_pem()).unwrap();
    let ui = Arc::new(bosun_ca::UiTls::from_files(&cp, &kp).unwrap());
    let s = stack_full(true, |c| c.tls = true, Some(ui)).await;
    let (presented, body) = tls_get(s.api, cert.der()).await;
    assert_eq!(presented, cert.der().as_ref());
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");

    // Without files: a certificate made for the UI, which is neither the interception CA nor issued by it.
    let ui = Arc::new(
        bosun_ca::UiTls::self_signed(
            &dir.path().join("own"),
            &bosun_ca::DataKey::generate(),
            &["localhost".into()],
        )
        .unwrap(),
    );
    let s = stack_full(true, |c| c.tls = true, Some(ui)).await;
    let own = std::fs::read_to_string(dir.path().join("own/ui.crt.pem")).unwrap();
    let own_der = rustls::pki_types::CertificateDer::from_pem_slice(own.as_bytes()).unwrap();
    let (presented, body) = tls_get(s.api, own_der.as_ref()).await;
    assert_eq!(presented, own_der.as_ref());
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");

    // It is not signed by the CA: a client that trusts only the CA refuses it.
    let ca = bosun_ca::CertificateAuthority::ephemeral().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca.cert_der().to_vec()))
        .unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(s.api).await.unwrap();
    let r = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(), tcp)
        .await;
    assert!(r.is_err());
}

// ---- Flow bodies ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_flow_is_its_metadata_and_bodies_come_separately_in_ranges() {
    let s = stack(true).await;
    let (c, _csrf) = s.admin().await;
    let body: Vec<u8> = (0..2_000_000u32).map(|i| (i % 253) as u8).collect();
    let id = recorded(
        &s,
        "/big",
        "Content-Type: application/octet-stream\r\n",
        &body,
        None,
    );

    // The overview is small whatever the body size, and has the head and the sizes.
    let r = c.get(s.url(&format!("/flows/{id}"))).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let text = r.text().await.unwrap();
    assert!(text.len() < 4_000, "{} bytes", text.len());
    let meta: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(meta["id"], id);
    assert_eq!(meta["response"]["body_len"], 2_000_000);
    assert!(meta["original_response"].is_null());
    assert!(meta.get("response_body_decoded").is_none());

    let url = s.url(&format!("/flows/{id}/response/body"));
    let all = c.get(&url).send().await.unwrap();
    assert_eq!(all.status(), StatusCode::OK);
    let h = all.headers().clone();
    assert_eq!(h["content-length"], "2000000");
    assert_eq!(h["accept-ranges"], "bytes");
    assert_eq!(h["content-type"], "application/octet-stream");
    assert!(
        h["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment")
    );
    assert_eq!(all.bytes().await.unwrap().as_ref(), &body[..]);

    let ranged = |range: &'static str| {
        let (c, url) = (c.clone(), url.clone());
        async move { c.get(&url).header("range", range).send().await.unwrap() }
    };
    let r = ranged("bytes=1000-1009").await;
    assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(r.headers()["content-range"], "bytes 1000-1009/2000000");
    assert_eq!(r.bytes().await.unwrap().as_ref(), &body[1000..1010]);
    let r = ranged("bytes=1999990-").await;
    assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(r.bytes().await.unwrap().as_ref(), &body[1_999_990..]);
    let r = ranged("bytes=-5").await;
    assert_eq!(r.headers()["content-range"], "bytes 1999995-1999999/2000000");
    assert_eq!(r.bytes().await.unwrap().as_ref(), &body[1_999_995..]);
    let r = ranged("bytes=1999990-9999999999").await;
    assert_eq!(r.headers()["content-range"], "bytes 1999990-1999999/2000000");
    for bad in ["bytes=2000000-", "bytes=-0"] {
        let r = ranged(bad).await;
        assert_eq!(r.status(), StatusCode::RANGE_NOT_SATISFIABLE, "{bad}");
        assert_eq!(r.headers()["content-range"], "bytes */2000000");
    }
    for bad in ["bytes=0-1,5-6", "items=0-1", "bytes=9-1", "bytes=x-"] {
        assert_eq!(
            ranged(bad).await.status(),
            StatusCode::RANGE_NOT_SATISFIABLE,
            "{bad}"
        );
    }

    // Parts that are not there, and names that are not parts.
    let get = |p: String| {
        let c = c.clone();
        let u = s.url(&p);
        async move { c.get(u).send().await.unwrap().status() }
    };
    assert_eq!(
        get(format!("/flows/{id}/original-response/body")).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(format!("/flows/{id}/original-request/body")).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get("/flows/99999/response/body".into()).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(format!("/flows/{id}/secrets/body")).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(get(format!("/flows/{id}/request/body")).await, StatusCode::OK);
    assert_eq!(
        get(format!("/flows/{id}/request/body?decoded=1")).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn a_decoded_body_is_streamed_and_ranges_apply_to_the_decoded_bytes() {
    use std::io::Write;
    let s = stack(true).await;
    let (c, _csrf) = s.admin().await;
    let text: Vec<u8> = (0..500_000u32).flat_map(|i| i.to_le_bytes()).collect();
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(&text).unwrap();
    let gz = e.finish().unwrap();
    let id = recorded(
        &s,
        "/gz",
        "Content-Encoding: gzip\r\n",
        &gz,
        Some(b"HTTP/1.1 200 OK\r\n\r\nbefore".to_vec()),
    );

    let meta: Value = c
        .get(s.url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(meta["response_encoding"], "gzip");
    assert_eq!(meta["response"]["body_len"], gz.len());
    assert_eq!(meta["original_response"]["body_len"], 6);

    let base = s.url(&format!("/flows/{id}/response/body"));
    // As stored: still compressed.
    assert_eq!(
        c.get(&base).send().await.unwrap().bytes().await.unwrap().as_ref(),
        &gz[..]
    );
    // Decoded: the text, without a length announced in advance.
    let r = c.get(format!("{base}?decoded=1")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.headers().get("content-length").is_none());
    assert_eq!(r.bytes().await.unwrap().as_ref(), &text[..]);
    // A range of the decoded bytes; the total is not known until the end is reached.
    let r = c
        .get(format!("{base}?decoded=1"))
        .header("range", "bytes=1000-1999")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(r.headers()["content-range"], "bytes 1000-1999/*");
    assert_eq!(r.bytes().await.unwrap().as_ref(), &text[1000..2000]);
    let r = c
        .get(format!("{base}?decoded=1"))
        .header("range", format!("bytes={}-", text.len() - 10))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.headers()["content-range"].to_str().unwrap(),
        format!("bytes {}-{}/{}", text.len() - 10, text.len() - 1, text.len())
    );
    assert_eq!(r.bytes().await.unwrap().as_ref(), &text[text.len() - 10..]);
    let r = c
        .get(format!("{base}?decoded=1"))
        .header("range", format!("bytes={}-", text.len() + 5))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    // The original (before edits) is its own message.
    let o = s.url(&format!("/flows/{id}/original-response/body"));
    assert_eq!(
        c.get(o).send().await.unwrap().bytes().await.unwrap().as_ref(),
        b"before"
    );

    // An encoding we cannot undo is said so, not guessed.
    let weird = recorded(&s, "/x", "Content-Encoding: compress\r\n", b"zzz", None);
    let r = c
        .get(s.url(&format!("/flows/{weird}/response/body?decoded=1")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn flow_bodies_need_a_session() {
    let s = stack(true).await;
    let (_c, _csrf) = s.admin().await;
    let id = recorded(&s, "/p", "", b"secret", None);
    let anon = client();
    for p in [format!("/flows/{id}"), format!("/flows/{id}/response/body")] {
        let r = anon.get(s.url(&p)).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{p}");
    }
}

// ---- Event stream resume ----------------------------------------------------------------------------------

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn events_socket(s: &Stack, cookie: &str, query: &str) -> Ws {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("ws://127.0.0.1:{}/api/v1/events{query}", s.api.port())
        .into_client_request()
        .unwrap();
    req.headers_mut().insert("cookie", cookie.parse().unwrap());
    req.headers_mut().insert(
        "origin",
        format!("http://127.0.0.1:{}", s.api.port()).parse().unwrap(),
    );
    tokio_tungstenite::connect_async(req).await.unwrap().0
}

/// The next text message as JSON.
async fn next_json(ws: &mut Ws) -> Value {
    use futures_util::StreamExt;
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("an event within 5 s")
            .unwrap()
            .unwrap();
        if let tokio_tungstenite::tungstenite::Message::Text(t) = m {
            return serde_json::from_str(t.as_str()).unwrap();
        }
    }
}

async fn session_cookie(s: &Stack) -> String {
    s.admin().await;
    let r = client()
        .post(s.url("/auth/login"))
        .json(&json!({ "username": "admin", "password": "a long enough password" }))
        .send()
        .await
        .unwrap();
    r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn a_client_that_reconnects_gets_the_events_it_missed_and_none_twice() {
    use bosun_proxy::ProxyEvent;
    let s = stack(true).await;
    let cookie = session_cookie(&s).await;
    let ev = |id| ProxyEvent::InterceptResolved { id };

    // A fresh connection says where the stream stands.
    let mut ws = events_socket(&s, &cookie, "").await;
    let hello = next_json(&mut ws).await;
    assert_eq!(hello["type"], "hello");
    assert_eq!(hello["seq"], 0);
    let epoch = hello["epoch"].as_str().unwrap().to_string();
    s.events.send(ev(1));
    let first = next_json(&mut ws).await;
    assert_eq!(
        (first["seq"].as_u64(), first["type"].as_str()),
        (Some(1), Some("intercept_resolved"))
    );
    drop(ws);

    // Events while nobody is connected.
    for id in 2..=4 {
        s.events.send(ev(id));
    }
    let mut ws = events_socket(&s, &cookie, &format!("?since=1&epoch={epoch}")).await;
    assert_eq!(next_json(&mut ws).await["type"], "hello");
    for want in 2..=4u64 {
        let e = next_json(&mut ws).await;
        assert_eq!((e["seq"].as_u64(), e["id"].as_u64()), (Some(want), Some(want)));
    }
    // And then live ones carry on from there.
    s.events.send(ev(5));
    assert_eq!(next_json(&mut ws).await["seq"], 5);
    drop(ws);

    // Another engine run's position means nothing: reload.
    let mut ws = events_socket(&s, &cookie, "?since=3&epoch=0000000000000000").await;
    assert_eq!(next_json(&mut ws).await["type"], "hello");
    assert_eq!(next_json(&mut ws).await["type"], "reload");
    drop(ws);

    // A position from the future (the engine restarted) is the same.
    let mut ws = events_socket(&s, &cookie, &format!("?since=999&epoch={epoch}")).await;
    assert_eq!(next_json(&mut ws).await["type"], "hello");
    assert_eq!(next_json(&mut ws).await["type"], "reload");
    drop(ws);

    // Too much has happened to replay: the bus keeps the last 64.
    for id in 6..=200 {
        s.events.send(ev(id));
    }
    let mut ws = events_socket(&s, &cookie, &format!("?since=5&epoch={epoch}")).await;
    assert_eq!(next_json(&mut ws).await["type"], "hello");
    assert_eq!(next_json(&mut ws).await["type"], "reload");
    // Live events still arrive after a reload.
    s.events.send(ev(201));
    assert_eq!(next_json(&mut ws).await["seq"], 201);
}

// ---- OpenAPI description ----------------------------------------------------------------------------------

#[tokio::test]
async fn the_committed_openapi_description_is_current() {
    let now = bosun_api::openapi::json();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/openapi.json");
    if std::env::var_os("BLESS").is_some() {
        std::fs::write(&path, &now).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == now,
        "docs/openapi.json is out of date: run `BLESS=1 cargo test -p bosun-api --test api openapi` and commit it"
    );
}

#[tokio::test]
async fn every_documented_operation_is_served_and_needs_a_session_unless_public() {
    let s = stack(true).await;
    let public = ["/status", "/setup", "/auth/login", "/auth/ticket", "/auth/sso"];
    for (method, path) in bosun_api::openapi::OPERATIONS {
        if *path == "/events" {
            continue; // needs an upgrade request; covered by its own tests
        }
        let url = s.url(
            &path
                .replace("{id}", "1")
                .replace("{sid}", "x")
                .replace("{tid}", "1")
                .replace("{part}", "request"),
        );
        let m = reqwest::Method::from_bytes(method.to_uppercase().as_bytes()).unwrap();
        let r = client().request(m, &url).json(&json!({})).send().await.unwrap();
        let st = r.status().as_u16();
        assert!(
            st != 404 && st != 405,
            "{method} {path} is documented but not served ({st})"
        );
        if !public.contains(path) {
            assert_eq!(st, 401, "{method} {path} should need a session");
        }
    }
}

/// The other direction of the check above: every route the router serves is documented. The router cannot be
/// listed at run time, so this reads the `.route(...)` calls out of the source of `router()`.
#[test]
fn every_served_route_is_documented() {
    let src = include_str!("../src/lib.rs");
    let body = &src[src.find("pub fn router(").expect("router fn")..];
    let body = &body[..body
        .find("Router::new()\n        .nest")
        .expect("end of the api routes")];
    let mut served = std::collections::BTreeSet::new();
    for chunk in body.split(".route(").skip(1) {
        let path = chunk.split('"').nth(1).expect("route path");
        // The handler part runs to the end of this call: methods are `get(`, `post(`, ... `delete(`.
        let handlers = &chunk[chunk.find(',').unwrap()..];
        for m in ["get", "post", "put", "patch", "delete"] {
            let mut rest = handlers;
            while let Some(i) = rest.find(&format!("{m}(")) {
                let before = rest[..i].chars().last();
                if !before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    served.insert((m.to_string(), path.to_string()));
                }
                rest = &rest[i + m.len()..];
            }
        }
    }
    let documented: std::collections::BTreeSet<_> = bosun_api::openapi::OPERATIONS
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect();
    assert_eq!(
        served, documented,
        "the router and docs/openapi.json disagree (left: served, right: documented)"
    );
}
