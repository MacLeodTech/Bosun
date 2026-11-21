//! Security behaviour of the API, end to end over real sockets.

#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bosun_api::{ApiConfig, AppState, Deps};
use bosun_ca::CertificateAuthority;
use bosun_proxy::{Proxy, ProxyConfig};
use bosun_scope::{Gate, Scope, ScopeSpec};
use bosun_store::{AppDb, Project, Role};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::net::TcpListener;

struct Stack {
    api: SocketAddr,
    proxy: SocketAddr,
    code: String,
    app: Arc<AppDb>,
}

async fn stack(proxy_knows_api: bool) -> Stack {
    let ca = Arc::new(CertificateAuthority::ephemeral().unwrap());
    let project = Arc::new(Project::open_in_memory().unwrap());
    let app = Arc::new(AppDb::open_in_memory().unwrap());
    let gate = Gate::new(Scope::compile(ScopeSpec::default()).unwrap());
    let (events, _) = tokio::sync::broadcast::channel(64);
    let api_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = api_l.local_addr().unwrap();
    let proxy_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_l.local_addr().unwrap();
    let pcfg = ProxyConfig {
        listen: proxy_addr,
        self_addrs: if proxy_knows_api { vec![api] } else { vec![] },
        ..Default::default()
    };
    let proxy = Proxy::new(pcfg, ca.clone(), gate.clone(), project.clone(), events.clone()).unwrap();
    let p = proxy.clone();
    tokio::spawn(async move { p.serve(proxy_l, std::future::pending()).await });
    let cfg = ApiConfig {
        listen: api,
        ..Default::default()
    };
    let (st, code) = AppState::new(
        &cfg,
        Deps {
            app: app.clone(),
            project,
            proxy,
            gate,
            ca,
            events,
            browser: None,
        },
    )
    .unwrap();
    tokio::spawn(bosun_api::serve(st, api_l, std::future::pending()));
    Stack {
        api,
        proxy: proxy_addr,
        code: code.unwrap(),
        app,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

impl Stack {
    fn url(&self, p: &str) -> String {
        format!("http://127.0.0.1:{}/api/v1{p}", self.api.port())
    }

    /// Complete setup; returns a cookie-carrying client and its CSRF token.
    async fn admin(&self) -> (reqwest::Client, String) {
        let c = client();
        let r = c
            .post(self.url("/setup"))
            .json(&json!({ "code": self.code, "username": "admin", "password": "a long enough password" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let cookie = r.headers()["set-cookie"].to_str().unwrap().to_string();
        assert!(
            cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"),
            "{cookie}"
        );
        let v: Value = r.json().await.unwrap();
        (c, v["csrf"].as_str().unwrap().to_string())
    }
}

#[tokio::test]
async fn setup_needs_the_code_and_happens_once() {
    let s = stack(true).await;
    let c = client();
    let v: Value = c
        .get(s.url("/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["setup_required"], true);
    let r = c
        .post(s.url("/setup"))
        .json(&json!({ "code": "guess", "username": "admin", "password": "a long enough password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = c
        .post(s.url("/setup"))
        .json(&json!({ "code": s.code, "username": "admin", "password": "short" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    s.admin().await;
    let r = c
        .post(s.url("/setup"))
        .json(&json!({ "code": s.code, "username": "x", "password": "a long enough password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn everything_needs_auth_and_csrf() {
    let s = stack(true).await;
    assert_eq!(
        client().get(s.url("/flows")).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let (c, csrf) = s.admin().await;
    assert_eq!(
        c.get(s.url("/flows")).send().await.unwrap().status(),
        StatusCode::OK
    );
    let scope = json!({ "include": [{ "host": "example.com" }] });
    let r = c.put(s.url("/scope")).json(&scope).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "no CSRF token");
    let r = c
        .put(s.url("/scope"))
        .header("x-csrf-token", "wrong")
        .json(&scope)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = c
        .put(s.url("/scope"))
        .header("x-csrf-token", &csrf)
        .json(&scope)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let got: Value = c.get(s.url("/scope")).send().await.unwrap().json().await.unwrap();
    assert_eq!(got["include"][0]["host"], "example.com");
    let r = c.get(s.url("/flows")).send().await.unwrap();
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert!(
        r.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("script-src 'self'")
    );
    assert!(r.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn rebinding_hosts_and_foreign_origins_are_refused() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let r = c
        .get(s.url("/flows"))
        .header("host", "attacker.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::MISDIRECTED_REQUEST);
    let r = c
        .get(s.url("/flows"))
        .header("origin", "https://attacker.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = c
        .get(s.url("/flows"))
        .header("origin", "null")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = c
        .put(s.url("/intercept"))
        .header("origin", format!("http://localhost:{}", s.api.port() + 1))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "requests": true, "responses": false, "in_scope_only": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "same host, different port is a different origin"
    );
    let r = c
        .get(s.url("/flows"))
        .header("origin", format!("http://localhost:{}", s.api.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = c
        .get(s.url("/flows"))
        .header("sec-fetch-site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn api_tokens_and_roles() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let r = c
        .post(s.url("/users"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "username": "watcher", "password": "another long password", "role": "viewer" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
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
    let vcsrf = v["csrf"].as_str().unwrap();
    let r = viewer
        .put(s.url("/scope"))
        .header("x-csrf-token", vcsrf)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "viewers can't change scope");
    assert_eq!(
        viewer.get(s.url("/users")).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let t: Value = c
        .post(s.url("/tokens"))
        .header("x-csrf-token", &csrf)
        .json(&json!({ "name": "ci" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = t["token"].as_str().unwrap();
    let bare = client();
    let r = bare
        .put(s.url("/scope"))
        .bearer_auth(token)
        .json(&json!({ "include": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "bearer tokens need no CSRF token");
    let r = bare
        .get(s.url("/flows"))
        .bearer_auth("bosun_wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "token.create")
    );
    let _ = s
        .app
        .list_users()
        .unwrap()
        .iter()
        .find(|u| u.role == Role::Viewer)
        .unwrap();
}

#[tokio::test]
async fn login_failures_are_rate_limited() {
    let s = stack(true).await;
    s.admin().await;
    let c = client();
    let mut last = StatusCode::OK;
    for _ in 0..11 {
        last = c
            .post(s.url("/auth/login"))
            .json(&json!({ "username": "admin", "password": "wrong password!!" }))
            .send()
            .await
            .unwrap()
            .status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn event_stream_checks_origin() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let s = stack(true).await;
    s.admin().await;
    // Log in again to read the cookie value for a raw WebSocket client.
    let r = client()
        .post(s.url("/auth/login"))
        .json(&json!({ "username": "admin", "password": "a long enough password" }))
        .send()
        .await
        .unwrap();
    let cookie = r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let url = format!("ws://127.0.0.1:{}/api/v1/events", s.api.port());

    let mut req = url.clone().into_client_request().unwrap();
    req.headers_mut().insert("cookie", cookie.parse().unwrap());
    req.headers_mut()
        .insert("origin", "https://attacker.example".parse().unwrap());
    assert!(
        tokio_tungstenite::connect_async(req).await.is_err(),
        "foreign origin must not get the stream"
    );

    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert("cookie", cookie.parse().unwrap());
    req.headers_mut().insert(
        "origin",
        format!("http://127.0.0.1:{}", s.api.port()).parse().unwrap(),
    );
    assert!(tokio_tungstenite::connect_async(req).await.is_ok());
}

#[tokio::test]
async fn the_proxy_cannot_reach_the_api() {
    for knows in [true, false] {
        let s = stack(knows).await;
        let c = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", s.proxy)).unwrap())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let r = c.get(s.url("/status")).send().await.unwrap();
        // Refused either by the proxy (it knows the API address) or by the API (it sees its own proxy's
        // outbound connection).
        let want = if knows {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::LOOP_DETECTED
        };
        assert_eq!(r.status(), want, "proxy_knows_api={knows}");
        assert!(!r.text().await.unwrap().contains("setup_required"));
    }
}
