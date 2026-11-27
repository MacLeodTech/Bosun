#![allow(clippy::unwrap_used)]
//! Scans and crawls that sign in with a login macro whose password comes from the vault.
mod common;

use common::{Stack, stack};
use reqwest::StatusCode;
use serde_json::{Value, json};

async fn post(s: &Stack, c: &reqwest::Client, csrf: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let r = c
        .post(s.url(path))
        .header("x-csrf-token", csrf)
        .json(&body)
        .send()
        .await
        .unwrap();
    let st = r.status();
    let t = r.text().await.unwrap();
    (st, serde_json::from_str(&t).unwrap_or(Value::String(t)))
}

async fn until_ended(s: &Stack, c: &reqwest::Client, path: &str) -> Value {
    for _ in 0..200 {
        let v: Value = c.get(s.url(path)).send().await.unwrap().json().await.unwrap();
        if v["state"] != "running" && v["state"] != "paused" {
            return v;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("did not end: {path}");
}

fn spec(port: u16, vault_id: i64) -> Value {
    json!({
        "login": {
            "url": format!("http://127.0.0.1:{port}/login"),
            "body": format!("user=alice&pass={{{{vault:{vault_id}|url}}}}"),
        },
        "capture": { "kind": "cookies" },
    })
}

#[tokio::test]
async fn scans_and_crawls_sign_in_with_a_vault_password_and_stop_on_a_wrong_one() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let r = c
        .put(s.url("/scope"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "include": [{ "host": "127.0.0.1", "allow_private": true }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let port = tb.addr.port();

    let (st, v) = post(
        &s,
        &c,
        &csrf,
        "/vault",
        json!({ "name": "alice pw", "kind": "password", "secret": "alicepw" }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let good = v["id"].as_i64().unwrap();
    let (_, v) = post(
        &s,
        &c,
        &csrf,
        "/vault",
        json!({ "name": "wrong", "kind": "password", "secret": "nope" }),
    )
    .await;
    let wrong = v["id"].as_i64().unwrap();

    // A crawl of the logged-in area sees its pages (without a session it is sent to the login page).
    let start = format!("http://127.0.0.1:{port}/app");
    let (st, v) = post(
        &s,
        &c,
        &csrf,
        "/crawl/crawls",
        json!({ "start": [start], "max_depth": 1, "max_pages": 10, "session": spec(port, good) }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let id = v["id"].as_u64().unwrap();
    let done = until_ended(&s, &c, &format!("/crawl/crawls/{id}")).await;
    assert_eq!(done["state"], "done", "{done}");
    let pages = done["results"].as_array().unwrap();
    assert!(
        pages
            .iter()
            .any(|p| p["url"].as_str().unwrap().ends_with("/app") && p["status"] == 200),
        "the crawl was not signed in: {done}"
    );

    // A scan signs in too.
    let (st, v) = post(
        &s,
        &c,
        &csrf,
        "/scan/scans",
        json!({
            "targets": [{ "url": format!("http://127.0.0.1:{port}/app/orders/1?q=a") }],
            "checks": ["active-xss-reflected"],
            "session": spec(port, good),
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let id = v["id"].as_u64().unwrap();
    let done = until_ended(&s, &c, &format!("/scan/scans/{id}")).await;
    assert_eq!(done["state"], "done", "{done}");

    // A wrong password ends the scan with the reason, after one attempt.
    let (_, v) = post(
        &s,
        &c,
        &csrf,
        "/scan/scans",
        json!({
            "targets": [{ "url": format!("http://127.0.0.1:{port}/app/orders/1?q=a") }],
            "session": spec(port, wrong),
        }),
    )
    .await;
    let id = v["id"].as_u64().unwrap();
    let done = until_ended(&s, &c, &format!("/scan/scans/{id}")).await;
    assert_eq!(done["state"], "failed", "{done}");
    assert!(done["error"].as_str().unwrap().contains("credentials"), "{done}");

    // Bad input: a missing vault entry, a line break in the secret's place, a bad pattern.
    let mut bad = spec(port, 9999);
    let (st, _) = post(
        &s,
        &c,
        &csrf,
        "/scan/scans",
        json!({ "targets": [{ "url": start }], "session": bad }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    bad = spec(port, good);
    bad["capture"] = json!({ "kind": "body", "pattern": "(", "header": "Authorization" });
    let (st, _) = post(
        &s,
        &c,
        &csrf,
        "/scan/scans",
        json!({ "targets": [{ "url": start }], "session": bad }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // The password is never in the audit log.
    let audit = c.get(s.url("/audit")).send().await.unwrap().text().await.unwrap();
    assert!(
        audit.contains("scan.start") && !audit.contains("alicepw"),
        "{audit}"
    );
}
