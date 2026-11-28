#![allow(clippy::unwrap_used)]
//! Map Local, Map Remote and throttle rules over the API: roles, validation against the scope gate and the
//! directory, persistence in the project, and the audit entry.
mod common;

use common::{client, stack};
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn map_rules_are_validated_stored_and_audited() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let put = |body: Value| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url("/map-rules"));
        async move {
            c.put(url)
                .header("x-csrf-token", csrf)
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    // Empty to begin with.
    let r: Value = c
        .get(s.url("/map-rules"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r, json!([]));

    // Throttle: accepted, stored, applied, audited.
    let r =
        put(json!([{ "kind": "throttle", "host": "slow.test", "latency_ms": 250, "comment": "slow" }])).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(s.project.map_rule_specs().unwrap().len(), 1);
    assert_eq!(s.state.inner.proxy.map_rules()[0].latency_ms, 250);
    // A throttle with nothing to do is a 400 that names the rule.
    let r = put(json!([{ "kind": "throttle" }])).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(r.text().await.unwrap().contains("rule 1"));
    assert_eq!(
        s.project.map_rule_specs().unwrap().len(),
        1,
        "a refused list changes nothing"
    );

    // Map Remote to a target the scope does not allow is refused.
    let remote = json!([{ "kind": "map_remote", "host": "a.test", "target": "http://127.0.0.1:9" }]);
    let r = put(remote.clone()).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let text = r.text().await.unwrap();
    assert!(text.contains("not allowed"), "{text}");
    assert_eq!(s.state.inner.proxy.map_rules().len(), 1);
    // Bad targets are refused as well.
    assert_eq!(
        put(json!([{ "kind": "map_remote", "target": "https://x.test/path" }]))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    // Once the target is in scope the same rule is accepted.
    let r = c
        .put(s.url("/scope"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "include": [{ "host": "127.0.0.1" }], "exclude": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(put(remote).await.status(), StatusCode::OK);

    // Map Local needs a real directory.
    let r = put(json!([{ "kind": "map_local", "directory": "/nonexistent/bosun/dir" }])).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let dir = tempfile::tempdir().unwrap();
    let local = json!([{ "kind": "map_local", "path_prefix": "/static", "directory": dir.path() }]);
    assert_eq!(put(local.clone()).await.status(), StatusCode::OK);
    let got: Value = c
        .get(s.url("/map-rules"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got[0]["kind"], "map_local");

    // It all went to the audit log.
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    let n = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "maprules.update")
        .count();
    assert_eq!(n, 3, "{audit}");

    // Roles: a viewer reads only; a tester may change throttles and remotes but not Map Local (it serves files).
    for (name, role) in [("viewer1", "viewer"), ("tester1", "tester")] {
        let r = c
            .post(s.url("/users"))
            .header("x-csrf-token", &csrf)
            .json(&json!({ "username": name, "password": "another long password", "role": role }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
    }
    let login = |name: &'static str| {
        let url = s.url("/auth/login");
        async move {
            let u = client();
            let v: Value = u
                .post(url)
                .json(&json!({ "username": name, "password": "another long password" }))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            (u, v["csrf"].as_str().unwrap().to_string())
        }
    };
    let (viewer, vcsrf) = login("viewer1").await;
    assert_eq!(
        viewer.get(s.url("/map-rules")).send().await.unwrap().status(),
        StatusCode::OK
    );
    let r = viewer
        .put(s.url("/map-rules"))
        .header("x-csrf-token", &vcsrf)
        .json(&json!([]))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let (tester, tcsrf) = login("tester1").await;
    let tput = |b: Value| {
        let (t, cs, url) = (tester.clone(), tcsrf.clone(), s.url("/map-rules"));
        async move {
            t.put(url)
                .header("x-csrf-token", cs)
                .json(&b)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(tput(local).await, StatusCode::FORBIDDEN);
    assert_eq!(
        tput(json!([{ "kind": "throttle", "bytes_per_sec": 1000 }])).await,
        StatusCode::OK
    );
    assert_eq!(s.project.map_rule_specs().unwrap().len(), 1);
}
