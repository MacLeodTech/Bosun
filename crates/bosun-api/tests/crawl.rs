#![allow(clippy::unwrap_used)]
mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Stack, client, stack};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type Seen = Arc<Mutex<Vec<String>>>;

/// A site: `/` links to `/a`, `/b` and (by another host name) `/secret`; every page answers after `delay_ms`.
/// With `many`, `/` links to `/p0` to `/p39` instead. Returns the port and the paths asked for.
async fn site(delay_ms: u64, many: bool) -> (u16, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let log = log.clone();
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
                let path = String::from_utf8_lossy(&got).split(' ').nth(1).unwrap_or("").to_string();
                log.lock().unwrap().push(path.clone());
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let (status, ctype, body) = match path.as_str() {
                    "/" if many => {
                        let links: String = (0..40).map(|i| format!("<a href=\"/p{i}\">p</a>")).collect();
                        ("200 OK", "text/html", format!("<title>home</title>{links}"))
                    }
                    "/" => (
                        "200 OK",
                        "text/html",
                        format!(
                            "<title>home</title><a href=\"/a\">a</a><a href=\"/b\">b</a><a href=\"http://localhost:{port}/secret\">s</a>"
                        ),
                    ),
                    "/a" | "/b" => ("200 OK", "text/html", "<title>leaf</title>leaf".to_string()),
                    p if p.starts_with("/p") => ("200 OK", "text/html", "<title>p</title>x".to_string()),
                    _ => ("404 Not Found", "text/plain", "no".to_string()),
                };
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    (port, seen)
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

async fn start(s: &Stack, c: &reqwest::Client, csrf: &str, port: u16, extra: Value) -> (StatusCode, Value) {
    let mut b = json!({ "start": [format!("http://127.0.0.1:{port}/")], "max_depth": 3, "delay_ms": 0 });
    b.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    let r = c
        .post(s.url("/crawl/crawls"))
        .header("x-csrf-token", csrf)
        .json(&b)
        .send()
        .await
        .unwrap();
    (r.status(), r.json().await.unwrap_or_default())
}

async fn ended(s: &Stack, c: &reqwest::Client, id: u64) -> Value {
    for _ in 0..300 {
        let d: Value = c
            .get(s.url(&format!("/crawl/crawls/{id}")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if d["state"] != "running" {
            return d;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the crawl did not end");
}

#[tokio::test]
async fn a_crawl_stays_in_scope_and_announces_itself_on_the_event_stream() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    in_scope(&s, &c, &csrf).await;
    let (port, seen) = site(0, false).await;
    let mut rx = s.events.subscribe();
    let (st, v) = start(&s, &c, &csrf, port, json!({ "respect_robots": false, "use_sitemap": false })).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let id = v["id"].as_u64().unwrap();
    let d = ended(&s, &c, id).await;
    assert_eq!(d["state"], "done", "{d}");
    let urls: Vec<&str> = d["results"].as_array().unwrap().iter().map(|p| p["url"].as_str().unwrap()).collect();
    for p in ["/", "/a", "/b"] {
        assert!(urls.iter().any(|u| u.ends_with(p)), "{p} missing in {urls:?}");
    }
    // The link to the other host name is listed, and never requested.
    assert!(d["out_of_scope"].to_string().contains("/secret"), "{d}");
    assert!(!seen.lock().unwrap().iter().any(|p| p == "/secret"));
    // Crawled pages are in the history as crawler flows, and the start is audited.
    let flows: Value = c.get(s.url("/flows")).send().await.unwrap().json().await.unwrap();
    assert!(flows.to_string().contains("crawler"));
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    assert!(audit.to_string().contains("crawl.start"));
    // The event stream saw it begin, and end.
    let mut kinds = Vec::new();
    while let Ok(Ok(e)) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
        let v = serde_json::to_value(&e).unwrap();
        let t = v["type"].as_str().unwrap_or("").to_string();
        if t.starts_with("crawl_") {
            assert_eq!(v["id"], id);
            let last = t == "crawl_done";
            kinds.push((t, v));
            if last {
                break;
            }
        }
    }
    assert_eq!(kinds.first().map(|k| k.0.as_str()), Some("crawl_started"), "{kinds:?}");
    assert!(kinds.iter().any(|k| k.0 == "crawl_progress"), "{kinds:?}");
    let done = kinds.last().unwrap();
    assert_eq!(done.0, "crawl_done");
    assert_eq!(done.1["state"], "done");
    assert_eq!(done.1["pages"], d["pages"]);
}

#[tokio::test]
async fn the_gate_refuses_a_start_url_outside_the_scope() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    // No scope at all: nothing may be requested.
    let (port, seen) = site(0, false).await;
    let (st, v) = start(&s, &c, &csrf, port, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let d = ended(&s, &c, v["id"].as_u64().unwrap()).await;
    assert_eq!(d["pages"], 0, "{d}");
    assert!(d["out_of_scope"].to_string().contains(&port.to_string()), "{d}");
    assert!(seen.lock().unwrap().is_empty(), "{:?}", seen.lock().unwrap());
    // A malformed request is refused up front.
    let (st, _) = start(&s, &c, &csrf, port, json!({ "start": ["ftp://x/"] })).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = start(&s, &c, &csrf, port, json!({ "max_pages": 100_000 })).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_running_crawl_can_be_stopped_once() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    in_scope(&s, &c, &csrf).await;
    let (port, seen) = site(150, true).await;
    let mut rx = s.events.subscribe();
    let (_, v) = start(&s, &c, &csrf, port, json!({ "concurrency": 1, "respect_robots": false, "use_sitemap": false })).await;
    let id = v["id"].as_u64().unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let stop = |c: reqwest::Client, csrf: String| {
        let url = s.url(&format!("/crawl/crawls/{id}/stop"));
        async move { c.post(url).header("x-csrf-token", csrf).send().await.unwrap() }
    };
    let r = stop(c.clone(), csrf.clone()).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.json::<Value>().await.unwrap()["stopped"], true);
    let d = ended(&s, &c, id).await;
    assert_eq!(d["state"], "stopped", "{d}");
    assert!(seen.lock().unwrap().len() < 40, "it should not have finished the site");
    // Stopping an ended crawl says so, and an unknown one is not found.
    let r: Value = stop(c.clone(), csrf.clone()).await.json().await.unwrap();
    assert_eq!(r["stopped"], false);
    let r = c
        .post(s.url("/crawl/crawls/999/stop"))
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let mut last = String::new();
    while let Ok(Ok(e)) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
        let v = serde_json::to_value(&e).unwrap();
        if v["type"] == "crawl_done" {
            last = v["state"].as_str().unwrap().to_string();
            break;
        }
    }
    assert_eq!(last, "stopped");
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    assert!(audit.to_string().contains("crawl.stop"));
}

#[tokio::test]
async fn the_crawl_routes_need_a_session_and_a_role() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    // Not signed in.
    let anon = client();
    assert_eq!(anon.get(s.url("/crawl/crawls")).send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
    // A viewer may look, not start or stop.
    let r = c
        .post(s.url("/users"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "username": "view", "password": "a long enough password", "role": "viewer" }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let v = client();
    let me: Value = v
        .post(s.url("/auth/login"))
        .json(&json!({ "username": "view", "password": "a long enough password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let vcsrf = me["csrf"].as_str().unwrap().to_string();
    let r = v.get(s.url("/crawl/crawls")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let (port, _) = site(0, false).await;
    let r = v
        .post(s.url("/crawl/crawls"))
        .header("x-csrf-token", &vcsrf)
        .json(&json!({ "start": [format!("http://127.0.0.1:{port}/")] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = v
        .post(s.url("/crawl/crawls/1/stop"))
        .header("x-csrf-token", &vcsrf)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}
