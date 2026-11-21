//! End-to-end tests: a real upstream server, the proxy, and real clients.

#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bosun_ca::CertificateAuthority;
use bosun_proxy::{Decision, InterceptSettings, Proxy, ProxyAuth, ProxyConfig, RuleSpec, RuleTarget};
use bosun_scope::{Gate, RuleSpec as ScopeRule, Scope, ScopeSpec};
use bosun_store::{FlowFilter, Project};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Echoes the method, path and request headers back as the body.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut out = format!("{} {}\n", req.method(), req.uri());
    for (n, v) in req.headers() {
        out.push_str(&format!("{}: {}\n", n, v.to_str().unwrap_or("?")));
    }
    let body = req
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    out.push_str(&String::from_utf8_lossy(&body));
    Ok(Response::builder()
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(out)))
        .unwrap())
}

async fn upstream_http() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), service_fn(echo))
                    .await;
            });
        }
    });
    addr
}

async fn upstream_https() -> SocketAddr {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(s).await {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service_fn(echo))
                        .await;
                }
            });
        }
    });
    addr
}

async fn ws_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(s).await.unwrap();
                while let Some(Ok(m)) = ws.next().await {
                    if m.is_text() || m.is_binary() {
                        ws.send(m).await.unwrap();
                    }
                }
            });
        }
    });
    addr
}

struct Harness {
    proxy: Proxy,
    addr: SocketAddr,
    project: Arc<Project>,
    ca: Arc<CertificateAuthority>,
}

async fn start(cfg: ProxyConfig, scope_hosts: &[&str]) -> Harness {
    let ca = Arc::new(CertificateAuthority::ephemeral().unwrap());
    let project = Arc::new(Project::open_in_memory().unwrap());
    let scope = Scope::compile(ScopeSpec {
        include: scope_hosts
            .iter()
            .map(|h| ScopeRule {
                host: h.to_string(),
                ..Default::default()
            })
            .collect(),
        exclude: vec![],
    })
    .unwrap();
    let (events, _) = tokio::sync::broadcast::channel(64);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ProxyConfig { listen: addr, ..cfg };
    let proxy = Proxy::new(cfg, ca.clone(), Gate::new(scope), project.clone(), events).unwrap();
    let p = proxy.clone();
    tokio::spawn(async move { p.serve(listener, std::future::pending()).await });
    Harness {
        proxy,
        addr,
        project,
        ca,
    }
}

fn client(h: &Harness) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{}", h.addr)).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(h.ca.cert_pem().as_bytes()).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

#[tokio::test]
async fn proxies_and_records_plain_http() {
    let up = upstream_http().await;
    let h = start(ProxyConfig::default(), &["127.0.0.1"]).await;
    let r = client(&h)
        .post(format!("http://{up}/hello?x=1"))
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body = r.text().await.unwrap();
    assert!(body.starts_with("POST /hello?x=1"), "{body}");
    assert!(body.ends_with("payload"));
    assert!(!body.to_ascii_lowercase().contains("proxy-connection"));

    h.proxy.flush();
    let flows = h.project.list_flows(&FlowFilter::default()).unwrap();
    assert_eq!(flows.len(), 1);
    let f = &flows[0];
    assert_eq!(
        (f.method.as_str(), f.path.as_str(), f.status),
        ("POST", "/hello?x=1", Some(200))
    );
    assert!(f.in_scope);
    let d = h.project.get_flow(f.id).unwrap().unwrap();
    assert!(String::from_utf8_lossy(&d.request).ends_with("payload"));
    assert!(String::from_utf8_lossy(d.response.as_ref().unwrap()).contains("POST /hello?x=1"));
}

#[tokio::test]
async fn intercepts_https_with_http2_to_the_client() {
    let up = upstream_https().await;
    let h = start(ProxyConfig::default(), &[]).await;
    let c = client(&h);
    let r = c
        .get(format!("https://localhost:{}/secure", up.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.version(),
        reqwest::Version::HTTP_2,
        "browser side negotiates h2 with the proxy"
    );
    assert!(r.text().await.unwrap().starts_with("GET /secure"));
    h.proxy.flush();
    let flows = h.project.list_flows(&FlowFilter::default()).unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].scheme, bosun_model::Scheme::Https);
    assert_eq!(flows[0].http_version, "HTTP/2");
    assert!(!flows[0].in_scope);
    let d = h.project.get_flow(flows[0].id).unwrap().unwrap();
    assert!(String::from_utf8_lossy(&d.request).contains(&format!("host: localhost:{}", up.port())));
}

#[tokio::test]
async fn intercept_queue_edits_the_request() {
    let up = upstream_http().await;
    let h = start(ProxyConfig::default(), &["127.0.0.1"]).await;
    h.proxy.intercept().set(InterceptSettings {
        requests: true,
        responses: false,
        in_scope_only: true,
    });
    let c = client(&h);
    let url = format!("http://{up}/original");
    let req = tokio::spawn(async move { c.get(url).send().await.unwrap().text().await.unwrap() });
    let item = loop {
        if let Some(s) = h.proxy.intercept().list().first() {
            break h.proxy.intercept().get(s.id).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let edited = String::from_utf8(item.raw.clone())
        .unwrap()
        .replace("/original", "/edited");
    assert!(h.proxy.intercept().resolve(
        item.summary.id,
        Decision::Forward {
            raw: Some(edited.into_bytes())
        }
    ));
    let body = req.await.unwrap();
    assert!(body.starts_with("GET /edited"), "{body}");
    h.proxy.flush();
    let f = &h.project.list_flows(&FlowFilter::default()).unwrap()[0];
    assert!(f.edited);
    let d = h.project.get_flow(f.id).unwrap().unwrap();
    assert!(String::from_utf8_lossy(d.original_request.as_ref().unwrap()).contains("/original"));
}

#[tokio::test]
async fn dropped_requests_never_reach_the_target() {
    let up = upstream_http().await;
    let h = start(ProxyConfig::default(), &["127.0.0.1"]).await;
    h.proxy.intercept().set(InterceptSettings {
        requests: true,
        responses: false,
        in_scope_only: false,
    });
    let c = client(&h);
    let req = tokio::spawn(async move { c.get(format!("http://{up}/x")).send().await.unwrap() });
    let id = loop {
        if let Some(s) = h.proxy.intercept().list().first() {
            break s.id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    h.proxy.intercept().resolve(id, Decision::Drop);
    let r = req.await.unwrap();
    assert_eq!(r.status(), 502);
    h.proxy.flush();
    let f = &h.project.list_flows(&FlowFilter::default()).unwrap()[0];
    assert!(f.error.as_deref().unwrap().contains("dropped"));
    assert_eq!(f.status, None);
}

#[tokio::test]
async fn match_and_replace_rules_apply() {
    let up = upstream_http().await;
    let h = start(ProxyConfig::default(), &[]).await;
    h.proxy
        .set_rules(vec![
            RuleSpec {
                enabled: true,
                target: RuleTarget::RequestHeader,
                pattern: String::new(),
                replace: "X-Added: yes".into(),
                regex: false,
                comment: String::new(),
            },
            RuleSpec {
                enabled: true,
                target: RuleTarget::ResponseBody,
                pattern: "GET".into(),
                replace: "TEG".into(),
                regex: false,
                comment: String::new(),
            },
        ])
        .unwrap();
    let body = client(&h)
        .get(format!("http://{up}/r"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.starts_with("TEG /r"), "{body}");
    assert!(body.contains("x-added: yes"), "{body}");
}

#[tokio::test]
async fn refuses_to_proxy_to_itself_and_serves_the_ca() {
    let h = start(ProxyConfig::default(), &[]).await;
    let c = client(&h);
    let r = c.get(format!("http://{}/", h.addr)).send().await.unwrap();
    assert_eq!(r.status(), 502);
    assert!(r.text().await.unwrap().contains("own listener"));

    let pem = c
        .get("http://bosun/cert.pem")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(pem, h.ca.cert_pem());
    let page = c.get("http://bosun/").send().await.unwrap();
    assert!(
        page.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .starts_with("default-src 'none'")
    );
}

#[tokio::test]
async fn records_websocket_messages() {
    let up = ws_echo().await;
    let h = start(ProxyConfig::default(), &[]).await;
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    s.write_all(format!("CONNECT {up} HTTP/1.1\r\nHost: {up}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 256];
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    let (mut ws, resp) = tokio_tungstenite::client_async(format!("ws://{up}/chat"), s)
        .await
        .unwrap();
    assert_eq!(resp.status(), 101);
    ws.send("hello".into()).await.unwrap();
    let echoed = ws.next().await.unwrap().unwrap();
    assert_eq!(echoed.into_text().unwrap().as_str(), "hello");
    ws.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.proxy.flush();
    let flows = h.project.list_flows(&FlowFilter::default()).unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].status, Some(101));
    let msgs = h.project.ws_messages(flows[0].id, None, 100).unwrap();
    let texts: Vec<_> = msgs
        .iter()
        .filter(|m| m.opcode == 1)
        .map(|m| String::from_utf8_lossy(&m.payload).to_string())
        .collect();
    assert_eq!(texts, vec!["hello", "hello"], "one message each way, unmasked");
}

#[tokio::test]
async fn proxy_auth_is_enforced() {
    let up = upstream_http().await;
    let cfg = ProxyConfig {
        auth: Some(ProxyAuth {
            username: "tester".into(),
            password: "correct horse battery".into(),
        }),
        ..Default::default()
    };
    let h = start(cfg, &[]).await;
    let r = client(&h).get(format!("http://{up}/")).send().await.unwrap();
    assert_eq!(r.status(), 407);
    let c = reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("http://{}", h.addr))
                .unwrap()
                .basic_auth("tester", "correct horse battery"),
        )
        .build()
        .unwrap();
    let r = c.get(format!("http://{up}/")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        !r.text().await.unwrap().contains("proxy-authorization"),
        "credentials are not forwarded"
    );
}

#[test]
fn open_proxy_configurations_are_refused() {
    let cfg = ProxyConfig {
        listen: "0.0.0.0:8080".parse().unwrap(),
        ..Default::default()
    };
    assert!(cfg.validate().is_err());
    let cfg = ProxyConfig {
        allow_clients: vec!["10.0.0.0/8".parse().unwrap()],
        ..cfg
    };
    assert!(cfg.validate().is_ok());
}
