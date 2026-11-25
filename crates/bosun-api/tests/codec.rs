#![allow(clippy::unwrap_used)]
mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::stack;
use reqwest::StatusCode;
use serde_json::{Value, json};

fn b(s: &[u8]) -> String {
    B64.encode(s)
}

async fn post(
    s: &common::Stack,
    c: &reqwest::Client,
    csrf: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let r = c
        .post(s.url(path))
        .header("x-csrf-token", csrf)
        .json(&body)
        .send()
        .await
        .unwrap();
    let st = r.status();
    (st, r.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_chain_returns_each_step_and_the_last_in_full() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let (st, v) = post(
        &s,
        &c,
        &csrf,
        "/decoder/apply",
        json!({ "input": b(b"a b<c>"), "ops": ["url_encode", "base64_encode", "base64_decode", "url_decode"] }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let steps = v["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 4);
    assert_eq!(
        B64.decode(steps[3]["output"].as_str().unwrap()).unwrap(),
        b"a b<c>"
    );
    assert!(v["error"].is_null());
}

#[tokio::test]
async fn a_failing_step_is_reported_with_the_steps_before_it() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let (st, v) = post(
        &s,
        &c,
        &csrf,
        "/decoder/apply",
        json!({ "input": b(b"hello"), "ops": ["base64_encode", "gzip_decode", "hex_encode"] }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["steps"].as_array().unwrap().len(), 1);
    assert_eq!(v["error"]["step"], 1);
    assert!(v["error"]["message"].as_str().unwrap().contains("gzip"));
}

#[tokio::test]
async fn a_decompression_bomb_is_refused_and_bad_input_is_a_400() {
    use std::io::Write;
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    // Ten layers of 4 MiB zeros would be 40 MiB if the limit were not applied per step; one layer is at the limit.
    let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    g.write_all(&vec![0u8; 8 << 20]).unwrap();
    let bomb = g.finish().unwrap();
    let (st, v) = post(
        &s,
        &c,
        &csrf,
        "/decoder/apply",
        json!({ "input": b(&bomb), "ops": ["gzip_decode"] }),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(v["error"]["message"].as_str().unwrap().contains("limit"), "{v}");
    assert!(v["steps"].as_array().unwrap().is_empty());

    let (st, _) = post(
        &s,
        &c,
        &csrf,
        "/decoder/apply",
        json!({ "input": "!!!", "ops": [] }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = post(
        &s,
        &c,
        &csrf,
        "/decoder/apply",
        json!({ "input": b(b"x"), "ops": ["nope"] }),
    )
    .await;
    assert!(st.is_client_error());
    let many: Vec<&str> = vec!["hex_encode"; 17];
    let (st, _) = post(
        &s,
        &c,
        &csrf,
        "/decoder/apply",
        json!({ "input": b(b"x"), "ops": many }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let huge = "A".repeat(7 << 20);
    let (st, _) = post(
        &s,
        &c,
        &csrf,
        "/decoder/apply",
        json!({ "input": huge, "ops": [] }),
    )
    .await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn smart_decode_peels_layers_and_leaves_plain_text() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let inner = b(b"%3Cb%3E");
    let (st, v) = post(
        &s,
        &c,
        &csrf,
        "/decoder/smart",
        json!({ "input": b(inner.as_bytes()) }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let steps = v["steps"].as_array().unwrap();
    assert_eq!(
        B64.decode(steps.last().unwrap()["output"].as_str().unwrap())
            .unwrap(),
        b"<b>"
    );
    let (_, v) = post(
        &s,
        &c,
        &csrf,
        "/decoder/smart",
        json!({ "input": b(b"plain words") }),
    )
    .await;
    assert!(v["steps"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn diff_reports_runs_and_enforces_limits() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let (st, v) = post(
        &s,
        &c,
        &csrf,
        "/comparer/diff",
        json!({ "a": b(b"GET /a HTTP/1.1"), "b": b(b"GET /b HTTP/1.1"), "level": "words" }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["coarse"], false);
    let kinds: Vec<&str> = v["ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"delete") && kinds.contains(&"insert") && kinds.contains(&"equal"),
        "{kinds:?}"
    );
    let big = b(&vec![b'x'; (1 << 20) + 1]);
    let (st, _) = post(
        &s,
        &c,
        &csrf,
        "/comparer/diff",
        json!({ "a": big, "b": b(b"y"), "level": "bytes" }),
    )
    .await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn the_tools_need_a_signed_in_user() {
    let s = stack(true).await;
    let c = common::client();
    for path in ["/decoder/apply", "/decoder/smart", "/comparer/diff"] {
        let r = c.post(s.url(path)).json(&json!({})).send().await.unwrap();
        assert!(
            r.status() == StatusCode::UNAUTHORIZED || r.status() == StatusCode::FORBIDDEN,
            "{path}: {}",
            r.status()
        );
    }
}
