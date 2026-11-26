#![allow(clippy::unwrap_used)]
mod common;

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use common::stack;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A server that records each request it gets and answers with the introspection result (chunked).
async fn graphql_origin() -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let log = log.clone();
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0u8; 8192];
                while !String::from_utf8_lossy(&got).contains("IntrospectionQuery") {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&got).to_string());
                let body = r#"{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"hello","args":[],"type":{"kind":"SCALAR","name":"String"}}]}]}}}"#;
                let (a, b) = body.split_at(40);
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
                            a.len(),
                            b.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    (port, seen)
}

#[tokio::test]
async fn graphql_introspection_is_fetched_live_through_the_gate() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let (port, seen) = graphql_origin().await;
    let post = |b: Value| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url("/import"));
        async move {
            c.post(url)
                .header("x-csrf-token", csrf)
                .json(&b)
                .send()
                .await
                .unwrap()
        }
    };
    let body =
        json!({ "format": "graphql", "introspection_url": format!("http://127.0.0.1:{port}/graphql") });

    // Out of scope: refused by the gate, nothing sent.
    let r = post(body.clone()).await;
    let st = r.status();
    assert_eq!(st, StatusCode::FORBIDDEN, "{}", r.text().await.unwrap());
    assert!(seen.lock().unwrap().is_empty());

    // In scope: the query is POSTed, the result parsed, tabs saved, the import audited with the URL.
    let r = c
        .put(s.url("/scope"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "include": [{ "host": "127.0.0.1", "allow_private": true }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = post(body.clone()).await;
    assert_eq!(r.status(), StatusCode::OK);
    let r: Value = r.json().await.unwrap();
    assert_eq!(
        (r["parsed"].as_u64(), r["added"].as_u64()),
        (Some(1), Some(1)),
        "{r}"
    );
    assert_eq!(r["hosts"], json!([format!("127.0.0.1:{port}")]));
    let sent = seen.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].starts_with("POST /graphql HTTP/1.1"), "{}", sent[0]);
    let tabs: Value = c
        .get(s.url("/repeater/tabs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(tabs["tabs"][0]["request"].as_str().unwrap().contains("hello"));
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    assert!(audit.to_string().contains("fetched=http://127.0.0.1"), "{audit}");

    // The URL is only for GraphQL, and must be http(s).
    for b in [
        json!({ "format": "har", "content": "{}", "introspection_url": "http://127.0.0.1/" }),
        json!({ "format": "graphql", "introspection_url": "ftp://x/" }),
    ] {
        assert_eq!(post(b).await.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn har_and_burp_responses_are_stored_as_flows_on_request() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let har = json!({ "log": { "entries": [{
        "request": { "method": "GET", "url": "http://shop.test/item?id=1", "headers": [] },
        "response": { "status": 200, "statusText": "OK",
            "headers": [{ "name": "Content-Type", "value": "text/plain" }, { "name": "Content-Encoding", "value": "gzip" }],
            "content": { "text": "hello world", "mimeType": "text/plain" } }
    }] } })
    .to_string();
    let b64 = base64::engine::general_purpose::STANDARD;
    let burp = format!(
        "<items><item><url>http://shop.test/b</url><request base64=\"true\">{}</request><response base64=\"true\">{}</response></item></items>",
        b64.encode("GET /b HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
        b64.encode("HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno")
    );
    for (format, content, status, needle) in [("har", har, 200, "hello world"), ("burp", burp, 404, "no")] {
        let import = |store: bool| {
            let (c, csrf, url) = (c.clone(), csrf.clone(), s.url("/import"));
            let b = json!({ "format": format, "content": content, "store_responses": store });
            async move {
                let r: Value = c
                    .post(url)
                    .header("x-csrf-token", csrf)
                    .json(&b)
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                r
            }
        };
        // Not asked for: no flow.
        assert_eq!(import(false).await["responses_stored"], 0);
        let r = import(true).await;
        assert_eq!(r["responses_stored"], 1, "{r}");
        let flows: Value = c
            .get(s.url("/flows?source=import"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let f = flows
            .as_array()
            .or_else(|| flows["flows"].as_array())
            .or_else(|| flows["items"].as_array())
            .unwrap_or_else(|| panic!("flows: {flows}"))
            .iter()
            .find(|f| f["status"] == status)
            .unwrap_or_else(|| panic!("no {status} flow in {flows}"));
        assert_eq!(f["source"], "import");
        let id = f["id"].as_i64().unwrap();
        let text = c
            .get(s.url(&format!("/flows/{id}/response/body")))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let _ = &b64;
        assert!(text.contains(needle), "{text}");
    }
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    assert!(audit.to_string().contains("responses=1"));
}
