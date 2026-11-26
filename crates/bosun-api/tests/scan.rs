#![allow(clippy::unwrap_used)]
mod common;

use std::time::Duration;

use common::{Stack, client, stack};
use reqwest::StatusCode;
use serde_json::{Value, json};

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

async fn post(s: &Stack, c: &reqwest::Client, csrf: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let r = c
        .post(s.url(path))
        .header("x-csrf-token", csrf)
        .json(&body)
        .send()
        .await
        .unwrap();
    (r.status(), r.json().await.unwrap_or_default())
}

async fn get(s: &Stack, c: &reqwest::Client, path: &str) -> Value {
    c.get(s.url(path)).send().await.unwrap().json().await.unwrap()
}

#[tokio::test]
async fn a_scan_of_the_testbed_pauses_resumes_finds_issues_and_is_audited() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    in_scope(&s, &c, &csrf).await;
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let base = format!("http://127.0.0.1:{}", tb.addr.port());
    let body = json!({
        "targets": [
            { "url": format!("{base}/search?q=boat") },
            { "url": format!("{base}/item?id=1") },
            { "url": format!("{base}/safe?id=1") },
            { "url": "http://localhost:9/outside?q=1" },
        ],
        "concurrency": 1,
    });
    let (st, v) = post(&s, &c, &csrf, "/scan/scans", body).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let id = v["id"].as_u64().unwrap();
    // Paused right after the start: a request already out may finish, but then the scan must hold.
    let (_, p) = post(&s, &c, &csrf, &format!("/scan/scans/{id}/pause"), json!({})).await;
    assert_eq!(p["changed"], true);
    assert_eq!(get(&s, &c, &format!("/scan/scans/{id}")).await["state"], "paused");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let held = tb.hits().len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(tb.hits().len(), held, "requests went out while paused");
    let (_, r) = post(&s, &c, &csrf, &format!("/scan/scans/{id}/resume"), json!({})).await;
    assert_eq!(r["changed"], true);
    let mut d = Value::Null;
    for _ in 0..300 {
        d = get(&s, &c, &format!("/scan/scans/{id}")).await;
        if d["state"] == "done" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(d["state"], "done", "{d}");
    let found: Vec<String> = d["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            format!(
                "{} {}",
                f["check"].as_str().unwrap(),
                f["point"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found.contains(&"active-sqli-error query:id".to_string()));
    assert!(found.contains(&"active-xss-reflected query:q".to_string()));
    assert_eq!(d["refused"].as_array().unwrap().len(), 1);
    // The findings are issues, the probes are scanner flows, and the lifecycle is audited.
    let issues = get(&s, &c, "/issues").await.to_string();
    assert!(issues.contains("active-sqli-error"), "{issues}");
    assert!(
        get(&s, &c, "/flows?limit=200")
            .await
            .to_string()
            .contains("scanner")
    );
    let audit = get(&s, &c, "/audit").await.to_string();
    for a in ["scan.start", "scan.pause", "scan.resume"] {
        assert!(audit.contains(a), "{a} missing");
    }
    // A finished scan cannot be stopped, and an unknown one is not found.
    let (_, st) = post(&s, &c, &csrf, &format!("/scan/scans/{id}/stop"), json!({})).await;
    assert_eq!(st["changed"], false);
    let (code, _) = post(&s, &c, &csrf, "/scan/scans/999/stop", json!({})).await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    let checks = get(&s, &c, "/scan/checks").await;
    let checks = checks["checks"].as_array().unwrap();
    assert!(checks.len() >= 12);
    let destructive: Vec<&str> = checks
        .iter()
        .filter(|c| c["destructive"] == true)
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(destructive, ["active-xss-stored"]);
}

#[tokio::test]
async fn the_scan_routes_need_a_session_and_the_tester_role() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let anon = client();
    assert_eq!(
        anon.get(s.url("/scan/scans")).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
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
    assert_eq!(
        v.get(s.url("/scan/scans")).send().await.unwrap().status(),
        StatusCode::OK
    );
    for (path, body) in [
        (
            "/scan/scans",
            json!({ "targets": [{ "url": "http://127.0.0.1:9/?a=1" }] }),
        ),
        ("/scan/scans/1/stop", json!({})),
        ("/scan/scans/1/pause", json!({})),
        ("/scan/scans/1/resume", json!({})),
    ] {
        let (code, _) = post(&s, &v, &vcsrf, path, body).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{path}");
    }
    // Bad input is a 400 for a tester.
    for body in [
        json!({ "targets": [] }),
        json!({ "targets": [{ "url": "not a url" }] }),
        json!({ "targets": [{ "url": "http://127.0.0.1:9/?a=1" }], "strength": "extreme" }),
        json!({ "targets": [{ "url": "http://127.0.0.1:9/?a=1" }], "checks": ["nope"] }),
    ] {
        let (code, _) = post(&s, &c, &csrf, "/scan/scans", body).await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }
}
