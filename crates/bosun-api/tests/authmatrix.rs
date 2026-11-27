#![allow(clippy::unwrap_used)]
//! The authorisation matrix API: probes are recorded flows, an account's header can come from the vault, the
//! secret never appears in the answer, and the run is gated, role-checked and audited.
mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::{Stack, stack};
use reqwest::StatusCode;
use serde_json::{Value, json};

async fn post(s: &Stack, c: &reqwest::Client, csrf: &str, path: &str, body: Value) -> (StatusCode, String) {
    let r = c
        .post(s.url(path))
        .header("x-csrf-token", csrf)
        .json(&body)
        .send()
        .await
        .unwrap();
    (r.status(), r.text().await.unwrap())
}

async fn sid(base: &str, user: &str, pass: &str) -> String {
    let c = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let r = c
        .post(format!("{base}/login"))
        .form(&[("user", user), ("pass", pass)])
        .send()
        .await
        .unwrap();
    let cookie = r
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    cookie.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn the_matrix_finds_the_planted_idor_with_a_vault_credential_and_is_audited() {
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
    let base = format!("http://127.0.0.1:{port}");
    let alice = sid(&base, "alice", "alicepw").await;
    let bob = sid(&base, "bob", "bobpw").await;

    // Bob's cookie goes into the vault; alice's is given inline.
    let (st, v) = post(
        &s,
        &c,
        &csrf,
        "/vault",
        json!({ "name": "bob cookie", "kind": "other", "secret": bob }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let vault_id = serde_json::from_str::<Value>(&v).unwrap()["id"].as_i64().unwrap();

    // Record alice's order 1 and her safe-twin as flows with the Repeater.
    let mut flows = Vec::new();
    for path in ["/app/orders/1", "/app/orders-safe/1"] {
        let raw = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: {alice}\r\n\r\n");
        let (st, v) = post(
            &s,
            &c,
            &csrf,
            "/repeater/send",
            json!({ "scheme": "http", "host": "127.0.0.1", "port": port, "request": B64.encode(raw) }),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{v}");
        let v: Value = serde_json::from_str(&v).unwrap();
        let id = v["results"][0]["flow_id"].as_i64().unwrap();
        // Recording is asynchronous: wait until the flow can be read.
        for _ in 0..100 {
            if c.get(s.url(&format!("/flows/{id}")))
                .send()
                .await
                .unwrap()
                .status()
                == StatusCode::OK
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        flows.push(id);
    }

    let body = json!({
        "identities": [
            { "name": "alice", "headers": [["Cookie", alice]] },
            { "name": "bob", "vault": [{ "vault_id": vault_id, "header": "Cookie" }] },
        ],
        "probes": [
            { "flow_id": flows[0], "owner": "alice", "label": "order 1" },
            { "flow_id": flows[1], "owner": "alice", "label": "order 1 (safe)" },
        ],
    });
    let (st, text) = post(&s, &c, &csrf, "/auth-matrix", body.clone()).await;
    assert_eq!(st, StatusCode::OK, "{text}");
    assert!(!text.contains(&bob), "the vault secret came back: {text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    let f = v["findings"].as_array().unwrap();
    assert!(
        f.iter().any(|x| x["label"] == "order 1"
            && x["identity"] == "bob"
            && x["kind"] == "broken_access_control"),
        "{v}"
    );
    assert!(
        f.iter().all(|x| x["label"] != "order 1 (safe)"),
        "false positive on the safe twin: {v}"
    );

    // Saving the findings makes one issue, once (a second run does not duplicate it).
    assert_eq!(v["issues_saved"], 0);
    let mut save = body.clone();
    save["save_issues"] = json!(true);
    for _ in 0..2 {
        let (st, text) = post(&s, &c, &csrf, "/auth-matrix", save.clone()).await;
        assert_eq!(st, StatusCode::OK, "{text}");
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["issues_saved"], 1);
    }
    let issues = c
        .get(s.url("/issues"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(issues.matches("authz-matrix").count(), 1, "{issues}");

    // Validation and a missing vault entry.
    let mut bad = body.clone();
    bad["probes"][0]["owner"] = json!("nobody");
    assert_eq!(
        post(&s, &c, &csrf, "/auth-matrix", bad).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut bad = body.clone();
    bad["identities"][1]["vault"][0]["vault_id"] = json!(9999);
    assert_eq!(
        post(&s, &c, &csrf, "/auth-matrix", bad).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut bad = body.clone();
    bad["probes"][0]["flow_id"] = json!(99999);
    assert_eq!(
        post(&s, &c, &csrf, "/auth-matrix", bad).await.0,
        StatusCode::NOT_FOUND
    );

    // Audited, without the secret.
    let audit = c.get(s.url("/audit")).send().await.unwrap().text().await.unwrap();
    assert!(audit.contains("authmatrix.run"), "{audit}");
    assert!(!audit.contains(&bob));
}
