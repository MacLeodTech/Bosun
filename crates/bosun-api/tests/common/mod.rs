//! A whole engine on loopback ports, shared by the API test files.

#![allow(clippy::unwrap_used, dead_code)] // test helpers outside #[test] fns

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bosun_api::{ApiConfig, AppState, Deps};
use bosun_ca::CertificateAuthority;
use bosun_proxy::{Proxy, ProxyConfig};
use bosun_scope::{Gate, Scope, ScopeSpec};
use bosun_store::{AppDb, Project};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::net::TcpListener;

pub struct Stack {
    pub api: SocketAddr,
    pub proxy: SocketAddr,
    pub code: String,
    pub app: Arc<AppDb>,
    pub project: Arc<Project>,
    /// The projects directory of this stack.
    pub dir: Arc<tempfile::TempDir>,
    pub events: bosun_proxy::EventBus,
    pub state: AppState,
}

pub async fn stack(proxy_knows_api: bool) -> Stack {
    stack_with(proxy_knows_api, |_| {}).await
}

pub async fn stack_with(proxy_knows_api: bool, tweak: impl FnOnce(&mut ApiConfig)) -> Stack {
    stack_full(proxy_knows_api, tweak, None).await
}

pub async fn stack_full(
    proxy_knows_api: bool,
    tweak: impl FnOnce(&mut ApiConfig),
    ui_tls: Option<Arc<bosun_ca::UiTls>>,
) -> Stack {
    let ca = Arc::new(CertificateAuthority::ephemeral().unwrap());
    let project = Arc::new(Project::open_in_memory().unwrap());
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let app = Arc::new(AppDb::open_in_memory().unwrap());
    let gate = Gate::new(Scope::compile(ScopeSpec::default()).unwrap());
    let events = bosun_proxy::EventBus::new(64);
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
    let mut cfg = ApiConfig {
        listen: api,
        ..Default::default()
    };
    tweak(&mut cfg);
    let (st, code) = AppState::new(
        &cfg,
        Deps {
            app: app.clone(),
            projects_dir: dir.path().to_path_buf(),
            project_path: None,
            proxy,
            gate,
            ca,
            events: events.clone(),
            browser: None,
            ui_tls,
        },
    )
    .unwrap();
    tokio::spawn(bosun_api::serve(st.clone(), api_l, std::future::pending()));
    Stack {
        api,
        proxy: proxy_addr,
        code: code.unwrap(),
        app,
        project,
        dir,
        events,
        state: st,
    }
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

impl Stack {
    pub fn url(&self, p: &str) -> String {
        format!("http://127.0.0.1:{}/api/v1{p}", self.api.port())
    }

    /// Complete setup; returns a cookie-carrying client and its CSRF token.
    pub async fn admin(&self) -> (reqwest::Client, String) {
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

pub fn recorded(s: &Stack, path: &str, head: &str, body: &[u8], original: Option<Vec<u8>>) -> i64 {
    use bosun_model::{FlowSource, Scheme};
    let mut resp = format!("HTTP/1.1 200 OK\r\n{head}Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    resp.extend_from_slice(body);
    let project = s.state.project();
    let id = project.next_flow_id();
    project
        .write_batch(
            &[bosun_store::NewFlow {
                id,
                source: FlowSource::Proxy,
                started_ms: 1,
                duration_ms: Some(1),
                scheme: Scheme::Https,
                host: "a.test".into(),
                port: 443,
                method: "GET".into(),
                path: path.into(),
                http_version: "HTTP/1.1".into(),
                status: Some(200),
                in_scope: true,
                edited: original.is_some(),
                error: None,
                request: b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec(),
                original_request: None,
                response: Some(resp),
                original_response: original,
                response_truncated: false,
            }],
            &[],
        )
        .unwrap();
    id
}
