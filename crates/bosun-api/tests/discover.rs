#![allow(clippy::unwrap_used)]
mod common;

use std::time::Duration;

use common::stack;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn discovery_finds_planted_content_records_only_hits_and_respects_scope() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let port = tb.addr.port();
    let post = |body: Value| {
        let (c, csrf) = (c.clone(), csrf.clone());
        let url = s.url("/discover/runs");
        async move {
            let r = c
                .post(url)
                .header("x-csrf-token", csrf)
                .json(&body)
                .send()
                .await
                .unwrap();
            (r.status(), r.json::<Value>().await.unwrap_or_default())
        }
    };
    let ended = |id: u64| {
        let c = c.clone();
        let url = s.url(&format!("/discover/runs/{id}"));
        async move {
            for _ in 0..300 {
                let d: Value = c.get(&url).send().await.unwrap().json().await.unwrap();
                if d["state"] != "running" {
                    return d;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("the run did not end");
        }
    };

    // Out of scope: the run fails with the gate's reason and nothing reaches the server.
    let (st, v) = post(json!({ "base": format!("http://127.0.0.1:{port}/"), "words": ["admin"] })).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let d = ended(v["id"].as_u64().unwrap()).await;
    assert_eq!(d["state"], "failed", "{d}");
    assert!(d["error"].as_str().unwrap().contains("refused"), "{d}");
    assert!(tb.hits().is_empty());

    let r = c
        .put(s.url("/scope"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "include": [{ "host": "127.0.0.1", "allow_private": true }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    let (st, v) = post(json!({
        "base": format!("http://127.0.0.1:{port}/"),
        "words": ["admin", "ghost", "backup.zip", "nothing-here"],
        "max_depth": 2
    }))
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let d = ended(v["id"].as_u64().unwrap()).await;
    assert_eq!(d["state"], "done", "{d}");
    let urls: Vec<&str> = d["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["url"].as_str().unwrap())
        .collect();
    for p in ["/admin", "/backup.zip", "/ghost"] {
        assert!(
            urls.iter().any(|u| u.trim_end_matches('/').ends_with(p)),
            "{p} in {urls:?}"
        );
    }
    assert!(
        !urls
            .iter()
            .any(|u| u.contains("nothing-here") || u.ends_with("/ghost/ghost")),
        "{urls:?}"
    );

    // Parameters.
    let (st, v) = post(json!({
        "base": format!("http://127.0.0.1:{port}/tool"), "mode": "params", "words": ["q", "debug", "zz"]
    }))
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let d = ended(v["id"].as_u64().unwrap()).await;
    assert_eq!(d["results"].as_array().unwrap().len(), 1, "{d}");
    assert_eq!(d["results"][0]["word"], "debug");

    // Only hits are in the history, source intruder; the start is audited.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let flows: Value = c
        .get(s.url("/flows?limit=200"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let n = flows.as_array().map_or(0, Vec::len);
    assert!((1..=12).contains(&n), "{n} flows: {flows}");
    let audit = c.get(s.url("/audit")).send().await.unwrap().text().await.unwrap();
    assert!(audit.contains("discover.start"), "{audit}");

    // Bad input is 400; a viewer cannot start; the list names the runs.
    for bad in [
        json!({ "base": "nonsense" }),
        json!({ "base": "http://127.0.0.1/", "mode": "x" }),
        json!({ "base": "http://127.0.0.1/", "words": ["a b"] }),
    ] {
        assert_eq!(post(bad).await.0, StatusCode::BAD_REQUEST);
    }
    let l: Value = c
        .get(s.url("/discover/runs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(l["runs"].as_array().unwrap().len() >= 3, "{l}");
    assert_eq!(
        c.get(s.url("/discover/runs/999")).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}
