#![allow(clippy::unwrap_used)]
//! WP-55, the rest: XXE, file upload, JWT, deserialization, prototype pollution, GraphQL, session cookies and TLS,
//! each against a planted testbed target and its safe twin.

use std::sync::Arc;

use bosun_active::{Control, Options, Report, Strength, Target, scan};
use bosun_http::Engine;
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, RuleSpec, Scope, ScopeSpec};
use bosun_testbed::{STRONG_SECRET, TlsKind, jwt_hs256};

type Found = Vec<(String, String, String)>;

fn engine(ports: &[u16]) -> Engine {
    let include = ports
        .iter()
        .map(|p| RuleSpec {
            scheme: None,
            host: "127.0.0.1".into(),
            port: Some(*p),
            path: None,
            allow_private: true,
        })
        .collect();
    let scope = Scope::compile(ScopeSpec {
        include,
        exclude: vec![],
    })
    .unwrap();
    Engine::new(Gate::new(scope), MemoryBudget::new(64 << 20))
}

fn target(url: String) -> Target {
    Target {
        method: None,
        url,
        headers: vec![],
        body: None,
        content_type: None,
    }
}

fn post(url: String, ct: &str, body: &str) -> Target {
    Target {
        method: Some("POST".into()),
        body: Some(body.into()),
        content_type: Some(ct.into()),
        ..target(url)
    }
}

fn bearer(url: String, token: &str) -> Target {
    Target {
        headers: vec![("Authorization".into(), format!("Bearer {token}"))],
        ..target(url)
    }
}

async fn run(
    checks: &[&str],
    strength: Strength,
    make: impl FnOnce(&str) -> Vec<Target>,
) -> (Found, Report, bosun_testbed::Testbed) {
    let tb = bosun_testbed::start("127.0.0.1:0", None).await.unwrap();
    let base = format!("http://127.0.0.1:{}", tb.addr.port());
    let opts = Options {
        checks: checks.iter().map(|c| (*c).to_string()).collect(),
        strength,
        concurrency: 8,
        ..Options::default()
    };
    let r = scan(
        &engine(&[tb.addr.port()]),
        &opts,
        &make(&base),
        Arc::new(()),
        &Control::new(),
    )
    .await
    .unwrap();
    (found(&r, &base), r, tb)
}

fn found(r: &Report, base: &str) -> Found {
    let mut got: Found = r
        .findings
        .iter()
        .map(|f| {
            (
                f.check.clone(),
                f.url.strip_prefix(base).unwrap_or(&f.url).to_string(),
                f.point.clone(),
            )
        })
        .collect();
    got.sort();
    got
}

fn want(items: &[(&str, &str, &str)]) -> Found {
    let mut w: Found = items
        .iter()
        .map(|(a, b, c)| ((*a).to_string(), (*b).to_string(), (*c).to_string()))
        .collect();
    w.sort();
    w
}

const ORDER: &str = r#"<?xml version="1.0"?><order><item>book</item></order>"#;

#[tokio::test]
async fn xxe_is_found_by_file_read_and_by_error_and_not_in_the_twin() {
    let (got, r, _) = run(&["active-xxe"], Strength::Medium, |b| {
        vec![
            post(format!("{b}/xml/import"), "application/xml", ORDER),
            post(format!("{b}/xml/import-safe"), "application/xml", ORDER),
            post(format!("{b}/xml/import-blind"), "text/xml", ORDER),
            // Not XML: never probed.
            post(format!("{b}/api/echo"), "application/json", r#"{"name":"sam"}"#),
        ]
    })
    .await;
    assert_eq!(
        got,
        want(&[
            ("active-xxe", "/xml/import", "xxe:file-read"),
            ("active-xxe", "/xml/import-blind", "xxe:entity-error"),
        ])
    );
    assert!(r.findings.iter().any(|f| f.detail.contains("/etc/passwd")));
}

fn upload_body(name: &str) -> String {
    format!(
        "--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
         Content-Type: text/plain\r\n\r\nhello\r\n--BOUND--\r\n"
    )
}

#[tokio::test]
async fn upload_is_destructive_off_by_default_and_found_when_named() {
    let make = |b: &str| {
        let ct = "multipart/form-data; boundary=BOUND";
        vec![
            post(format!("{b}/upload"), ct, &upload_body("a.txt")),
            post(format!("{b}/upload-safe"), ct, &upload_body("a.txt")),
        ]
    };
    let (got, _, tb) = run(&["active-file-upload"], Strength::Medium, make).await;
    assert_eq!(got, want(&[("active-file-upload", "/upload", "upload:php")]));
    assert!(tb.hits().iter().any(|h| h.starts_with("POST /upload-safe")));
    assert!(bosun_active::is_destructive("active-file-upload"));
}

#[tokio::test]
async fn jwt_weak_secret_none_and_unverified_signature_are_found_and_not_in_the_twin() {
    let claims = r#"{"sub":"alice"}"#;
    let weak = jwt_hs256("secret", claims);
    let strong = jwt_hs256(STRONG_SECRET, claims);
    let (got, ..) = run(&["active-jwt"], Strength::Medium, |b| {
        vec![
            bearer(format!("{b}/api/jwt"), &weak),
            bearer(format!("{b}/api/jwt-unsigned"), &strong),
            bearer(format!("{b}/api/jwt-safe"), &strong),
            target(format!("{b}/search?q=boat")),
        ]
    })
    .await;
    assert_eq!(
        got,
        want(&[
            ("active-jwt", "/api/jwt", "jwt:alg-none"),
            ("active-jwt", "/api/jwt", "jwt:weak-secret"),
            ("active-jwt", "/api/jwt-unsigned", "jwt:signature-not-verified"),
        ])
    );
}

#[tokio::test]
async fn deserialization_indicators_are_found_and_not_in_the_twin() {
    let (got, r, _) = run(&["active-deserialization"], Strength::Medium, |b| {
        vec![
            target(format!("{b}/session/restore?data=abc")),
            target(format!("{b}/session/restore-safe?data=abc")),
            target(format!("{b}/search?q=boat")),
        ]
    })
    .await;
    assert_eq!(
        got,
        want(&[("active-deserialization", "/session/restore", "query:data")])
    );
    assert!(r.findings[0].detail.contains("Java"));
}

#[tokio::test]
async fn prototype_pollution_is_found_and_not_in_the_twin() {
    let (got, ..) = run(&["active-prototype-pollution"], Strength::Medium, |b| {
        vec![
            post(
                format!("{b}/api/settings"),
                "application/json",
                r#"{"theme":"light"}"#,
            ),
            post(
                format!("{b}/api/settings-safe"),
                "application/json",
                r#"{"theme":"light"}"#,
            ),
            post(format!("{b}/api/echo"), "application/json", r#"{"name":"sam"}"#),
        ]
    })
    .await;
    assert_eq!(
        got,
        want(&[("active-prototype-pollution", "/api/settings", "json:__proto__")])
    );
}

#[tokio::test]
async fn graphql_issues_are_found_and_not_in_the_twin() {
    let q = r#"{"query":"{ __typename }"}"#;
    let (got, ..) = run(&["active-graphql"], Strength::Medium, |b| {
        vec![
            post(format!("{b}/graphql"), "application/json", q),
            post(format!("{b}/graphql-safe"), "application/json", q),
            post(format!("{b}/api/echo"), "application/json", r#"{"name":"sam"}"#),
            target(format!("{b}/search?q=boat")),
        ]
    })
    .await;
    assert_eq!(
        got,
        want(&[
            ("active-graphql", "/graphql", "graphql:aliases"),
            ("active-graphql", "/graphql", "graphql:batching"),
            ("active-graphql", "/graphql", "graphql:introspection"),
            ("active-graphql", "/graphql", "graphql:suggestions"),
        ])
    );
}

#[tokio::test]
async fn session_cookie_flags_and_fixation_are_found_and_not_in_the_twin() {
    let (got, ..) = run(&["active-session"], Strength::Medium, |b| {
        vec![
            target(format!("{b}/session/start")),
            target(format!("{b}/session/start-safe")),
            // A cookie that is not a session's.
            target(format!("{b}/lang?set=en")),
            target(format!("{b}/search?q=boat")),
        ]
    })
    .await;
    assert_eq!(
        got,
        want(&[
            ("active-session", "/session/start", "cookie:sid"),
            ("active-session", "/session/start", "fixation:sid"),
        ])
    );
}

async fn tls_scan(kind: TlsKind, strength: Strength) -> (Found, Report) {
    let addr = bosun_testbed::start_tls(kind).await.unwrap();
    let opts = Options {
        checks: vec!["active-tls".into()],
        strength,
        ..Options::default()
    };
    let base = format!("https://127.0.0.1:{}", addr.port());
    let t = vec![target(format!("{base}/")), target(format!("{base}/other"))];
    let r = scan(&engine(&[addr.port()]), &opts, &t, Arc::new(()), &Control::new())
        .await
        .unwrap();
    (found(&r, &base), r)
}

#[tokio::test]
async fn tls_configuration_problems_are_found_and_not_on_a_good_server() {
    let (got, r) = tls_scan(TlsKind::Good, Strength::High).await;
    assert!(got.is_empty(), "{got:?}");
    assert!(r.requests > 0);

    let (got, _) = tls_scan(TlsKind::Expired, Strength::Medium).await;
    assert_eq!(got, want(&[("active-tls", "/", "tls:expired")]));

    let (got, _) = tls_scan(TlsKind::SelfSigned, Strength::Medium).await;
    assert_eq!(got, want(&[("active-tls", "/", "tls:self-signed")]));

    // Once for the host, not once per target.
    let (got, _) = tls_scan(TlsKind::Legacy, Strength::High).await;
    assert_eq!(
        got,
        want(&[
            ("active-tls", "/", "tls:3des"),
            ("active-tls", "/", "tls:null-or-export"),
            ("active-tls", "/", "tls:rc4"),
            ("active-tls", "/", "tls:ssl3.0"),
            ("active-tls", "/", "tls:tls1.0"),
            ("active-tls", "/", "tls:tls1.1"),
        ])
    );
    // Low: no 3DES, no SSL 3.0.
    let (got, _) = tls_scan(TlsKind::Legacy, Strength::Low).await;
    assert_eq!(got.len(), 4, "{got:?}");
}

#[tokio::test]
async fn tls_probes_stay_inside_the_scope() {
    let addr = bosun_testbed::start_tls(TlsKind::Legacy).await.unwrap();
    let other = bosun_testbed::start_tls(TlsKind::Legacy).await.unwrap();
    let opts = Options {
        checks: vec!["active-tls".into()],
        ..Options::default()
    };
    let t = vec![target(format!("https://127.0.0.1:{}/", other.port()))];
    let r = scan(&engine(&[addr.port()]), &opts, &t, Arc::new(()), &Control::new())
        .await
        .unwrap();
    assert!(r.findings.is_empty());
    assert_eq!(r.refused.len(), 1);
}

#[tokio::test]
async fn a_default_scan_finds_exactly_the_planted_issues_of_the_new_checks() {
    let claims = r#"{"sub":"alice"}"#;
    let weak = jwt_hs256("secret", claims);
    let strong = jwt_hs256(STRONG_SECRET, claims);
    let q = r#"{"query":"{ __typename }"}"#;
    let ct = "multipart/form-data; boundary=BOUND";
    let (got, r, tb) = run(&[], Strength::Medium, |b| {
        vec![
            post(format!("{b}/xml/import"), "application/xml", ORDER),
            post(format!("{b}/xml/import-safe"), "application/xml", ORDER),
            post(format!("{b}/upload"), ct, &upload_body("a.txt")),
            post(format!("{b}/upload-safe"), ct, &upload_body("a.txt")),
            bearer(format!("{b}/api/jwt"), &weak),
            bearer(format!("{b}/api/jwt-unsigned"), &strong),
            bearer(format!("{b}/api/jwt-safe"), &strong),
            target(format!("{b}/session/restore?data=abc")),
            target(format!("{b}/session/restore-safe?data=abc")),
            post(
                format!("{b}/api/settings"),
                "application/json",
                r#"{"theme":"light"}"#,
            ),
            post(
                format!("{b}/api/settings-safe"),
                "application/json",
                r#"{"theme":"light"}"#,
            ),
            post(format!("{b}/graphql"), "application/json", q),
            post(format!("{b}/graphql-safe"), "application/json", q),
            target(format!("{b}/session/start")),
            target(format!("{b}/session/start-safe")),
        ]
    })
    .await;
    assert_eq!(
        got,
        want(&[
            ("active-xxe", "/xml/import", "xxe:file-read"),
            ("active-jwt", "/api/jwt", "jwt:alg-none"),
            ("active-jwt", "/api/jwt", "jwt:weak-secret"),
            ("active-jwt", "/api/jwt-unsigned", "jwt:signature-not-verified"),
            ("active-deserialization", "/session/restore", "query:data"),
            ("active-prototype-pollution", "/api/settings", "json:__proto__"),
            ("active-graphql", "/graphql", "graphql:aliases"),
            ("active-graphql", "/graphql", "graphql:batching"),
            ("active-graphql", "/graphql", "graphql:introspection"),
            ("active-graphql", "/graphql", "graphql:suggestions"),
            ("active-session", "/session/start", "cookie:sid"),
            ("active-session", "/session/start", "fixation:sid"),
        ])
    );
    assert!(r.units_done == r.units_total && !r.truncated);
    // The upload is destructive: unnamed, it finds nothing at /upload (the other checks only read it).
    assert!(r.requests > 0 && !tb.hits().is_empty());
}
