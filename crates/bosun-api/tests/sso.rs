//! Single sign-on: Edge SSO (a trusted proxy forwards the provider's ID token) and the guards around it.

#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use bosun_api::sso::SsoConfig;
use bosun_api::{ApiConfig, AppState, Deps};
use bosun_ca::CertificateAuthority;
use bosun_proxy::{Proxy, ProxyConfig};
use bosun_scope::{Gate, Scope, ScopeSpec};
use bosun_store::{AppDb, Project};
use reqwest::StatusCode;
use rsa::pkcs1v15::SigningKey;
use rsa::rand_core::OsRng;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, sha2::Sha256};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const PROXY_CLIENT: &str = "proxy-client";

struct Idp {
    url: String,
}

fn sign(key: &RsaPrivateKey, claims: &Value) -> String {
    let head = B64.encode(json!({"alg": "RS256", "typ": "JWT", "kid": "k1"}).to_string());
    let body = B64.encode(claims.to_string());
    let signing = SigningKey::<Sha256>::new(key.clone());
    let sig = signing.sign(format!("{head}.{body}").as_bytes());
    format!("{head}.{body}.{}", B64.encode(sig.to_bytes()))
}

async fn idp(key: &RsaPrivateKey) -> Idp {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let pubk = key.to_public_key();
    let jwks = json!({"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
        "n": B64.encode(pubk.n().to_bytes_be()), "e": B64.encode(pubk.e().to_bytes_be())}]});
    let disc = json!({"issuer": url, "authorization_endpoint": format!("{url}/authorize"), "token_endpoint": format!("{url}/token"),
        "jwks_uri": format!("{url}/jwks"), "response_types_supported": ["code"], "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]});
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || async move { axum::Json(disc) }),
        )
        .route(
            "/jwks",
            axum::routing::get(move || async move { axum::Json(jwks) }),
        );
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    Idp { url }
}

impl Idp {
    fn claims(&self, aud: &str, email: &str, verified: bool, ttl: i64) -> Value {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        json!({"iss": self.url, "aud": aud, "sub": format!("sub-{}", email.to_lowercase()), "email": email,
            "email_verified": verified, "iat": now - 60, "exp": now + ttl})
    }
}

fn config(idp: &Idp, proxies: &str) -> SsoConfig {
    SsoConfig {
        issuer: idp.url.clone(),
        client_id: "own-client".into(),
        client_secret: Some("s3cret".into()),
        public_url: "http://localhost:8090".into(),
        name: "Test".into(),
        email_roles: [
            ("me@example.com".to_string(), "admin".to_string()),
            ("you@example.com".to_string(), "viewer".to_string()),
        ]
        .into(),
        edge_audience: Some(PROXY_CLIENT.into()),
        edge_trusted_proxies: vec![proxies.parse().unwrap()],
    }
}

async fn serve(sso: SsoConfig) -> (SocketAddr, Arc<AppDb>) {
    let ca = Arc::new(CertificateAuthority::ephemeral().unwrap());
    let project = Arc::new(Project::open_in_memory().unwrap());
    let app = Arc::new(AppDb::open_in_memory().unwrap());
    let gate = Gate::new(Scope::compile(ScopeSpec::default()).unwrap());
    let (events, _) = tokio::sync::broadcast::channel(64);
    let api_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = api_l.local_addr().unwrap();
    let proxy_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pcfg = ProxyConfig {
        listen: proxy_l.local_addr().unwrap(),
        ..Default::default()
    };
    let proxy = Proxy::new(pcfg, ca.clone(), gate.clone(), project.clone(), events.clone()).unwrap();
    let p = proxy.clone();
    tokio::spawn(async move { p.serve(proxy_l, std::future::pending()).await });
    let cfg = ApiConfig {
        listen: api,
        sso: Some(sso),
        ..Default::default()
    };
    let (st, _) = AppState::new(
        &cfg,
        Deps {
            app: app.clone(),
            project,
            proxy,
            gate,
            ca,
            events,
            browser: None,
            ui_tls: None,
        },
    )
    .unwrap();
    tokio::spawn(bosun_api::serve(st, api_l, std::future::pending()));
    (api, app)
}

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap()
}

async fn edge(c: &reqwest::Client, api: SocketAddr, token: Option<&str>) -> (StatusCode, String) {
    let mut r = c.get(format!("http://{api}/auth/oidc/edge"));
    if let Some(t) = token {
        r = r.bearer_auth(t);
    }
    let r = r.send().await.unwrap();
    (
        r.status(),
        r.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
    )
}

async fn me(c: &reqwest::Client, api: SocketAddr) -> (StatusCode, Value) {
    let r = c
        .get(format!("http://{api}/api/v1/auth/me"))
        .send()
        .await
        .unwrap();
    (r.status(), r.json().await.unwrap_or(Value::Null))
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_sso_signs_in_listed_addresses_and_refuses_the_rest() {
    let key = Arc::new(RsaPrivateKey::new(&mut OsRng, 2048).unwrap());
    let other = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let idp = idp(&key).await;
    let (api, _app) = serve(config(&idp, "127.0.0.0/8")).await;

    // The sign-in page learns the button.
    let r: Value = browser()
        .get(format!("http://{api}/api/v1/auth/sso"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["sso"]["edge"], "/auth/oidc/edge");

    // A listed, verified address signs in and gets the listed role and an account named after the email.
    let c = browser();
    let good = sign(&key, &idp.claims(PROXY_CLIENT, "You@Example.com", true, 3600));
    assert_eq!(edge(&c, api, Some(&good)).await, (StatusCode::FOUND, "/".into()));
    let (s, v) = me(&c, api).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["user"]["username"], "you@example.com");
    assert_eq!(v["user"]["role"], "viewer");
    let id = v["user"]["id"].clone();

    // The same person next time is the same account, and it has no password that works.
    let c2 = browser();
    edge(&c2, api, Some(&good)).await;
    assert_eq!(me(&c2, api).await.1["user"]["id"], id);
    let r = browser()
        .post(format!("http://{api}/api/v1/auth/login"))
        .json(&json!({"username": "you@example.com", "password": ""}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let cases: Vec<(&str, Option<String>)> = vec![
        ("no token", None),
        ("garbage", Some("not.a.jwt".into())),
        (
            "this app's own audience",
            Some(sign(
                &key,
                &idp.claims("own-client", "me@example.com", true, 3600),
            )),
        ),
        (
            "another audience",
            Some(sign(
                &key,
                &idp.claims("someone-else", "me@example.com", true, 3600),
            )),
        ),
        (
            "another signing key",
            Some(sign(
                &other,
                &idp.claims(PROXY_CLIENT, "me@example.com", true, 3600),
            )),
        ),
        (
            "expired",
            Some(sign(
                &key,
                &idp.claims(PROXY_CLIENT, "me@example.com", true, -3600),
            )),
        ),
        (
            "unverified email",
            Some(sign(
                &key,
                &idp.claims(PROXY_CLIENT, "me@example.com", false, 3600),
            )),
        ),
        (
            "not on the list",
            Some(sign(
                &key,
                &idp.claims(PROXY_CLIENT, "mallory@example.com", true, 3600),
            )),
        ),
    ];
    for (name, tok) in cases {
        let c = browser();
        let (s, loc) = edge(&c, api, tok.as_deref()).await;
        assert!(
            s == StatusCode::FOUND && loc.starts_with("/?sso_error="),
            "{name}: {s} {loc}"
        );
        assert_eq!(
            me(&c, api).await.0,
            StatusCode::UNAUTHORIZED,
            "{name} left a session"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_sso_refuses_a_peer_that_is_not_the_trusted_proxy() {
    let key = Arc::new(RsaPrivateKey::new(&mut OsRng, 2048).unwrap());
    let idp = idp(&key).await;
    let (api, _app) = serve(config(&idp, "203.0.113.0/24")).await; // the test client is 127.0.0.1
    let c = browser();
    let good = sign(&key, &idp.claims(PROXY_CLIENT, "me@example.com", true, 3600));
    let (s, loc) = edge(&c, api, Some(&good)).await;
    assert!(
        s == StatusCode::FOUND && loc.starts_with("/?sso_error="),
        "{s} {loc}"
    );
    assert_eq!(me(&c, api).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_route_is_absent_unless_configured() {
    let key = Arc::new(RsaPrivateKey::new(&mut OsRng, 2048).unwrap());
    let idp = idp(&key).await;
    let mut cfg = config(&idp, "127.0.0.0/8");
    cfg.edge_audience = None;
    cfg.edge_trusted_proxies.clear();
    let (api, _app) = serve(cfg).await;
    assert_eq!(edge(&browser(), api, Some("x")).await.0, StatusCode::NOT_FOUND);
}

#[test]
fn unsafe_sso_setups_are_refused() {
    let base = SsoConfig {
        issuer: "https://accounts.google.com".into(),
        client_id: "c".into(),
        client_secret: Some("s".into()),
        public_url: "https://bosun.example.com".into(),
        email_roles: [("a@b.co".to_string(), "admin".to_string())].into(),
        ..Default::default()
    };
    assert!(base.validate().is_ok());
    let bad: Vec<(&str, SsoConfig)> = vec![
        (
            "no allow-list",
            SsoConfig {
                email_roles: Default::default(),
                ..base.clone()
            },
        ),
        (
            "http issuer",
            SsoConfig {
                issuer: "http://idp.example.com".into(),
                ..base.clone()
            },
        ),
        (
            "http public url",
            SsoConfig {
                public_url: "http://bosun.example.com".into(),
                ..base.clone()
            },
        ),
        (
            "unknown role",
            SsoConfig {
                email_roles: [("a@b.co".to_string(), "root".to_string())].into(),
                ..base.clone()
            },
        ),
        (
            "upper-case email",
            SsoConfig {
                email_roles: [("A@b.co".to_string(), "admin".to_string())].into(),
                ..base.clone()
            },
        ),
        (
            "edge without proxies",
            SsoConfig {
                edge_audience: Some("p".into()),
                ..base.clone()
            },
        ),
    ];
    for (name, c) in bad {
        assert!(c.validate().is_err(), "{name} was accepted");
    }
}
