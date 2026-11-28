#![allow(clippy::unwrap_used)]
//! The credential vault: sealed in the project file, never in an API response, admin-only writes, audited by name.
mod common;

use common::{client, stack};
use reqwest::StatusCode;
use serde_json::{Value, json};

const SECRET: &str = "s3cr3t-VAULT-value-0123456789-ZZ";

#[tokio::test]
async fn vault_secrets_are_sealed_never_returned_and_writes_are_admin_and_audited() {
    let s = stack(false).await;
    let (c, csrf) = s.admin().await;
    let post = |body: Value| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url("/vault"));
        async move {
            c.post(url)
                .header("x-csrf-token", csrf)
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    // Validation.
    assert_eq!(
        post(json!({ "name": "", "kind": "token", "secret": "x" }))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(json!({ "name": "a", "kind": "nope", "secret": "x" }))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(json!({ "name": "a", "kind": "token", "secret": "" }))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );

    let r = post(json!({ "name": "staging api", "kind": "api_key", "secret": SECRET })).await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let created = r.text().await.unwrap();
    assert!(!created.contains(SECRET), "{created}");
    let e: Value = serde_json::from_str(&created).unwrap();
    let id = e["id"].as_i64().unwrap();
    assert_eq!(e["hint"], "••••ZZ");
    assert_eq!(
        post(json!({ "name": "staging api", "kind": "token", "secret": "y" }))
            .await
            .status(),
        StatusCode::CONFLICT
    );

    // Not in a list, and not in the project file's bytes (the secret, nor its base64 or hex forms).
    let list = c.get(s.url("/vault")).send().await.unwrap().text().await.unwrap();
    assert!(!list.contains(SECRET) && list.contains("staging api"), "{list}");
    let out = s.dir.path().join("copy.bosun");
    s.project.backup_to(&out).unwrap();
    let raw = std::fs::read(&out).unwrap();
    let has = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
    assert!(has(b"staging api"), "the copy is of the right project");
    assert!(!has(SECRET.as_bytes()));
    assert!(!has(&SECRET.as_bytes()[..12]));

    // The server can open it by id; a wrong id is nothing.
    let key = s.state.inner.data_key.clone();
    let opened = bosun_api::vault::open_secret(&s.project, &key, id)
        .unwrap()
        .unwrap();
    assert_eq!(opened, SECRET.as_bytes());
    assert!(
        bosun_api::vault::open_secret(&s.project, &key, id + 1)
            .unwrap()
            .is_none()
    );

    // Update: rename and replace the secret; the response never carries it.
    let patch = |id: i64, body: Value| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url(&format!("/vault/{id}")));
        async move {
            c.patch(url)
                .header("x-csrf-token", csrf)
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };
    let r = patch(
        id,
        json!({ "name": "prod api", "secret": "rotated-secret-value-99" }),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let t = r.text().await.unwrap();
    assert!(t.contains("prod api") && !t.contains("rotated-secret"), "{t}");
    let key = s.state.inner.data_key.clone();
    assert_eq!(
        bosun_api::vault::open_secret(&s.project, &key, id)
            .unwrap()
            .unwrap(),
        b"rotated-secret-value-99"
    );
    assert_eq!(
        patch(id + 50, json!({ "name": "x" })).await.status(),
        StatusCode::NOT_FOUND
    );

    // A viewer may list but not write.
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
        v.get(s.url("/vault")).send().await.unwrap().status(),
        StatusCode::OK
    );
    let r = v
        .post(s.url("/vault"))
        .header("x-csrf-token", &vcsrf)
        .json(&json!({ "name": "v", "kind": "token", "secret": "x" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = v
        .delete(s.url(&format!("/vault/{id}")))
        .header("x-csrf-token", &vcsrf)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = v
        .patch(s.url(&format!("/vault/{id}")))
        .header("x-csrf-token", &vcsrf)
        .json(&json!({ "name": "z" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // Delete, audited by name and never by value.
    let del = |id: i64| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url(&format!("/vault/{id}")));
        async move {
            c.delete(url)
                .header("x-csrf-token", csrf)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(del(id).await, StatusCode::NO_CONTENT);
    assert_eq!(del(id).await, StatusCode::NOT_FOUND);
    let audit = c.get(s.url("/audit")).send().await.unwrap().text().await.unwrap();
    for a in ["vault.create", "vault.update", "vault.delete"] {
        assert!(audit.contains(a), "{a} in {audit}");
    }
    assert!(
        !audit.contains(SECRET) && !audit.contains("rotated-secret"),
        "{audit}"
    );
}
