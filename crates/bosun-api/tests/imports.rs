#![allow(clippy::unwrap_used)]
mod common;

use common::{client, stack};
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn imports_become_repeater_tabs_without_sending_anything() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let post = |b: Value| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url("/import"));
        async move { c.post(url).header("x-csrf-token", csrf).json(&b).send().await.unwrap() }
    };

    // A dry run saves nothing.
    let r: Value = post(json!({ "format": "urls", "content": "http://nowhere.invalid:9/a\nhttps://other.invalid/b\n", "dry_run": true }))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!((r["parsed"].as_u64(), r["added"].as_u64()), (Some(2), Some(0)));
    let tabs: Value = c.get(s.url("/repeater/tabs")).send().await.unwrap().json().await.unwrap();
    assert_eq!(tabs["tabs"].as_array().unwrap().len(), 0);

    // A real one saves tabs, lists the hosts, is audited, and sends nothing (the hosts do not resolve).
    let r: Value = post(json!({ "format": "urls", "content": "http://nowhere.invalid:9/a\nhttps://other.invalid/b?x=1\n" }))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(r["added"], 2);
    assert_eq!(r["hosts"], json!(["nowhere.invalid:9", "other.invalid:443"]));
    let tabs: Value = c.get(s.url("/repeater/tabs")).send().await.unwrap().json().await.unwrap();
    let t = &tabs["tabs"][1];
    assert_eq!((t["host"].as_str(), t["port"].as_u64()), (Some("other.invalid"), Some(443)));
    assert_eq!(t["request"], "GET /b?x=1 HTTP/1.1\r\nHost: other.invalid\r\n\r\n");
    assert_ne!(tabs["tabs"][0]["id"], t["id"]);
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    assert!(audit.to_string().contains("import.requests"));
    let flows: Value = c.get(s.url("/flows")).send().await.unwrap().json().await.unwrap();
    assert_eq!(flows.to_string().matches("invalid").count(), 0);

    // Hostile and wrong input is refused cleanly.
    let bomb = "<!DOCTYPE x [<!ENTITY a \"aa\">]><items><item><url>&a;</url></item></items>";
    for (b, want) in [
        (json!({ "format": "burp", "content": bomb }), StatusCode::UNPROCESSABLE_ENTITY),
        (json!({ "format": "graphql", "content": "{}" }), StatusCode::UNPROCESSABLE_ENTITY),
        (json!({ "format": "har", "content": "not json" }), StatusCode::UNPROCESSABLE_ENTITY),
        (json!({ "format": "urls", "content": "http://a.test/", "base_url": "ftp://x" }), StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(post(b.clone()).await.status(), want, "{b}");
    }

    // A viewer may not import.
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
    let r = viewer
        .post(s.url("/import"))
        .header("x-csrf-token", v["csrf"].as_str().unwrap())
        .json(&json!({ "format": "urls", "content": "http://a.test/" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}
