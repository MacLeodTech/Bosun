//! End-to-end tests: a real upstream server, the proxy, and real clients.

#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bosun_ca::CertificateAuthority;
use bosun_proxy::{
    Decision, InterceptSettings, Proxy, ProxyAuth, ProxyConfig, RuleSpec, RuleTarget, UpstreamProxy,
};
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
    let events = bosun_proxy::EventBus::new(64);
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
        timeout_secs: None,
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
        timeout_secs: None,
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
            password_file: None,
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

/// A TCP echo server.
async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// A minimal SOCKS5 server (no authentication) that records the target each client asked for.
async fn socks5(seen: Arc<std::sync::Mutex<Vec<String>>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut c, _) = l.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut hello = [0u8; 2];
                c.read_exact(&mut hello).await.unwrap();
                let mut methods = vec![0u8; hello[1] as usize];
                c.read_exact(&mut methods).await.unwrap();
                c.write_all(&[5, 0]).await.unwrap();
                let mut req = [0u8; 4];
                c.read_exact(&mut req).await.unwrap();
                let host = match req[3] {
                    1 => {
                        let mut a = [0u8; 4];
                        c.read_exact(&mut a).await.unwrap();
                        std::net::Ipv4Addr::from(a).to_string()
                    }
                    3 => {
                        let mut n = [0u8; 1];
                        c.read_exact(&mut n).await.unwrap();
                        let mut name = vec![0u8; n[0] as usize];
                        c.read_exact(&mut name).await.unwrap();
                        String::from_utf8(name).unwrap()
                    }
                    _ => return,
                };
                let mut port = [0u8; 2];
                c.read_exact(&mut port).await.unwrap();
                let port = u16::from_be_bytes(port);
                seen.lock().unwrap().push(format!("{host}:{port}"));
                let Ok(mut t) = TcpStream::connect((host.as_str(), port)).await else {
                    c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                    return;
                };
                c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut c, &mut t).await;
            });
        }
    });
    addr
}

/// Send `CONNECT host:port` to the proxy and return the stream once the proxy answers 200.
async fn connect_via(proxy: SocketAddr, target: &str) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.unwrap();
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    s
}

#[tokio::test]
async fn passthrough_tunnels_go_through_the_upstream_socks_proxy() {
    let echo = tcp_echo().await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let socks = socks5(seen.clone()).await;
    let h = start(
        ProxyConfig {
            tls_passthrough: vec!["localhost".into()],
            upstream: Some(UpstreamProxy::Socks5 {
                addr: socks.to_string(),
                username: None,
                password: None,
                password_file: None,
                local_dns: false,
            }),
            ..Default::default()
        },
        &[],
    )
    .await;
    let mut s = connect_via(h.addr, &format!("localhost:{}", echo.port())).await;
    s.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"ping");
    assert_eq!(*seen.lock().unwrap(), [format!("localhost:{}", echo.port())]);
}

#[tokio::test]
async fn passthrough_to_our_own_listener_is_refused() {
    let h = start(
        ProxyConfig {
            tls_passthrough: vec!["127.0.0.1".into()],
            ..Default::default()
        },
        &[],
    )
    .await;
    let mut s = connect_via(h.addr, &format!("127.0.0.1:{}", h.addr.port())).await;
    // The proxy accepted the CONNECT, then refused to dial itself and closed the tunnel.
    let _ = s.write_all(b"ping").await;
    let mut rest = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "no bytes may come back from our own listener");
}

#[tokio::test]
async fn slow_header_senders_are_disconnected() {
    let h = start(
        ProxyConfig {
            header_timeout_secs: 1,
            ..Default::default()
        },
        &[],
    )
    .await;
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    let head =
        b"GET http://bosun/ HTTP/1.1\r\nHost: bosun\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut cut = false;
    for b in head {
        if s.write_all(&[*b]).await.is_err() {
            cut = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut buf = [0u8; 64];
        if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(1), s.read(&mut buf)).await {
            cut = true;
            break;
        }
    }
    assert!(cut, "a client dribbling its headers must be disconnected");
}

#[tokio::test]
async fn connections_over_the_cap_are_refused_while_existing_ones_keep_working() {
    let h = start(
        ProxyConfig {
            max_connections: 2,
            ..Default::default()
        },
        &[],
    )
    .await;
    let req = b"GET http://bosun/cert.pem HTTP/1.1\r\nHost: bosun\r\n\r\n";
    let mut a = TcpStream::connect(h.addr).await.unwrap();
    let mut b = TcpStream::connect(h.addr).await.unwrap();
    for c in [&mut a, &mut b] {
        c.write_all(req).await.unwrap();
        let mut buf = [0u8; 12];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HTTP/1.1 200");
    }
    let mut third = TcpStream::connect(h.addr).await.unwrap();
    let _ = third.write_all(req).await;
    let mut buf = [0u8; 12];
    let got = tokio::time::timeout(Duration::from_secs(5), third.read(&mut buf))
        .await
        .unwrap();
    assert!(
        matches!(got, Ok(0) | Err(_)),
        "the third connection gets nothing: {got:?}"
    );
    assert_eq!(h.proxy.stats().connections_refused, 1, "the refusal is counted");
    // Existing connections are unaffected: read the rest of the first response off `a`, then reuse it.
    drop(third);
    let mut sink = vec![0u8; 8192];
    let _ = tokio::time::timeout(Duration::from_millis(200), a.read(&mut sink)).await;
    a.write_all(req).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), a.read(&mut sink))
        .await
        .unwrap()
        .unwrap();
}

/// An upstream that takes a while to answer, so concurrent requests overlap.
async fn slow_upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let _ = req.into_body().collect().await;
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn many_large_bodies_stay_under_the_memory_budget() {
    let up = slow_upstream().await;
    // 2 MiB budget; each 700 KB body reserves about 1.4 MB, so only one fits at a time.
    let h = start(
        ProxyConfig {
            memory_budget_mib: Some(2),
            ..Default::default()
        },
        &[],
    )
    .await;
    let c = client(&h);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (c, url) = (c.clone(), format!("http://{up}/"));
        tasks.push(tokio::spawn(async move {
            c.post(url)
                .body(vec![b'x'; 700_000])
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    let (mut ok, mut busy) = (0, 0);
    for t in tasks {
        match t.await.unwrap().as_u16() {
            200 => ok += 1,
            503 => busy += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert!(ok >= 1, "at least one request fits the budget");
    assert!(
        busy >= 1,
        "the others are refused with 503, not queued without bound"
    );
    h.proxy.flush(); // history waiting to be written is counted too
    let st = h.proxy.stats();
    assert_eq!(st.memory_used, 0, "everything is released afterwards: {st:?}");
    assert!(st.memory_refused >= busy);
    // A small body goes through once the budget is free again.
    let r = c
        .post(format!("http://{up}/"))
        .body(vec![b'x'; 10])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

/// Send a POST whose body is far over `max_request_body` in chunks, as a slow uploader would, and return what the
/// proxy answered. The client must always be able to read the refusal: a proxy that answers and closes while the
/// upload is still arriving resets the connection, and some clients (Windows ones in particular) then lose the
/// response.
async fn upload_and_read_answer(h: &Harness, up: SocketAddr, body_len: usize) -> String {
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    let head = format!(
        "POST http://{up}/ HTTP/1.1\r\nHost: {up}\r\nContent-Length: {body_len}\r\nContent-Type: application/octet-stream\r\n\r\n"
    );
    s.write_all(head.as_bytes()).await.unwrap();
    let chunk = vec![b'x'; 16 * 1024];
    let mut sent = 0;
    while sent < body_len {
        let n = chunk.len().min(body_len - sent);
        // Once the proxy has answered it may stop reading; a write error after that is fine, the answer is
        // already on its way.
        if s.write_all(&chunk[..n]).await.is_err() {
            break;
        }
        sent += n;
        tokio::task::yield_now().await;
    }
    // The connection stays open after the refusal, so read one response, not until it closes.
    tokio::time::timeout(Duration::from_secs(10), read_response(&mut s))
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

#[tokio::test]
async fn a_refused_upload_is_answered_and_the_client_can_read_the_answer() {
    let up = slow_upstream().await;
    // Over the per-message limit: 413.
    let h = start(
        ProxyConfig {
            max_request_body: 1024,
            ..Default::default()
        },
        &[],
    )
    .await;
    for _ in 0..20 {
        let answer = upload_and_read_answer(&h, up, 2 * 1024 * 1024).await;
        assert!(answer.starts_with("HTTP/1.1 413"), "got: {answer:?}");
    }
    // Over the memory budget: 503.
    let h = start(
        ProxyConfig {
            memory_budget_mib: Some(1),
            ..Default::default()
        },
        &[],
    )
    .await;
    for _ in 0..20 {
        let answer = upload_and_read_answer(&h, up, 2 * 1024 * 1024).await;
        assert!(answer.starts_with("HTTP/1.1 503"), "got: {answer:?}");
    }
    h.proxy.flush();
    assert_eq!(
        h.proxy.stats().memory_used,
        0,
        "everything is released afterwards"
    );
}

/// Read one HTTP/1.1 response (head and a Content-Length body) from a stream; None if the connection ended first.
async fn read_response(s: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let len = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.ok()?;
    Some(head + &String::from_utf8_lossy(&body))
}

#[tokio::test]
async fn after_a_refused_upload_the_connection_still_works() {
    // The proxy reads the rest of a refused body (up to a limit), so the client has finished its upload and the
    // connection can carry the next request. If it answered and closed with the upload unread, this second request
    // would find the connection gone, and a client could lose the refusal itself.
    let up = upstream_http().await;
    let h = start(
        ProxyConfig {
            max_request_body: 1024,
            ..Default::default()
        },
        &[],
    )
    .await;
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    let body = vec![b'x'; 256 * 1024];
    let head = format!(
        "POST http://{up}/ HTTP/1.1\r\nHost: {up}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(&body).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(10), read_response(&mut s))
        .await
        .unwrap()
        .expect("the refusal is delivered");
    assert!(first.starts_with("HTTP/1.1 413"), "got: {first:?}");

    s.write_all(format!("GET http://{up}/ HTTP/1.1\r\nHost: {up}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(10), read_response(&mut s))
        .await
        .unwrap()
        .expect("the connection is still open after the refusal");
    assert!(second.starts_with("HTTP/1.1 200"), "got: {second:?}");
}

#[tokio::test]
async fn a_full_intercept_queue_refuses_with_503_and_never_forwards() {
    let up = slow_upstream().await;
    let h = start(
        ProxyConfig {
            max_intercept_items: 1,
            ..Default::default()
        },
        &["127.0.0.1"],
    )
    .await;
    h.proxy.intercept().set(InterceptSettings {
        requests: true,
        responses: false,
        in_scope_only: true,
        timeout_secs: None,
    });
    let c = client(&h);
    let first = {
        let (c, url) = (c.clone(), format!("http://{up}/a"));
        tokio::spawn(async move { c.get(url).send().await.unwrap().status() })
    };
    while h.proxy.intercept().list().is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let second = c.get(format!("http://{up}/b")).send().await.unwrap();
    assert_eq!(second.status(), 503);
    assert_eq!(h.proxy.stats().intercept_refused, 1);
    h.proxy.intercept().forward_all();
    assert_eq!(first.await.unwrap(), 200);
}

#[tokio::test]
async fn a_large_streamed_upload_arrives_whole_and_is_recorded_whole() {
    let up = upstream_http().await;
    let h = start(ProxyConfig::default(), &[]).await;
    let c = client(&h);
    let body = "abcdefgh".repeat(40_000);
    let r = c
        .post(format!("http://{up}/up"))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.text().await.unwrap().ends_with(&body),
        "the upstream got the whole body"
    );
    h.proxy.flush();
    let flows = h.project.list_flows(&FlowFilter::default()).unwrap();
    let d = h.project.get_flow(flows[0].id).unwrap().unwrap();
    assert!(
        d.request.ends_with(body.as_bytes()),
        "the record holds the whole body"
    );
    assert_eq!(h.proxy.stats().memory_used, 0);
}

#[tokio::test]
async fn response_filter_decides_which_responses_are_held() {
    use bosun_proxy::ResponseFilter;
    let up = upstream_http().await;
    let h = start(ProxyConfig::default(), &[]).await;
    h.proxy.intercept().set(InterceptSettings {
        requests: false,
        responses: true,
        in_scope_only: false,
        timeout_secs: None,
    });
    // Not JSON: the response is not held, the request completes by itself.
    h.proxy.intercept().set_response_filter(ResponseFilter {
        mime_contains: vec!["json".into()],
        ..Default::default()
    });
    let c = client(&h);
    let r = tokio::time::timeout(Duration::from_secs(5), c.get(format!("http://{up}/a")).send())
        .await
        .expect("not held")
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(h.proxy.intercept().list().is_empty());
    // A body filter that does not match: not held. One that matches: held.
    h.proxy.intercept().set_response_filter(ResponseFilter {
        body_contains: Some("nothing-like-this".into()),
        ..Default::default()
    });
    tokio::time::timeout(Duration::from_secs(5), c.get(format!("http://{up}/b")).send())
        .await
        .expect("not held")
        .unwrap();
    h.proxy.intercept().set_response_filter(ResponseFilter {
        statuses: vec!["2xx".into()],
        mime_contains: vec!["PLAIN".into()],
        body_contains: Some("get /c".into()),
        ..Default::default()
    });
    let c2 = c.clone();
    let url = format!("http://{up}/c");
    let req = tokio::spawn(async move { c2.get(url).send().await.unwrap().status() });
    let id = loop {
        if let Some(s) = h.proxy.intercept().list().first() {
            break s.id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    h.proxy.intercept().resolve(id, Decision::Forward { raw: None });
    assert_eq!(req.await.unwrap(), 200);
    // Only when the request was held too.
    h.proxy.intercept().set_response_filter(ResponseFilter {
        only_if_request_held: true,
        ..Default::default()
    });
    tokio::time::timeout(Duration::from_secs(5), c.get(format!("http://{up}/d")).send())
        .await
        .expect("not held")
        .unwrap();
}

#[tokio::test]
async fn a_flow_answered_before_its_upload_ends_is_recorded_whole() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = l.local_addr().unwrap();
    // Answers as soon as the head has arrived, then keeps reading until the whole body is in.
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                let mut answered = false;
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                    if !answered && got.windows(4).any(|w| w == b"\r\n\r\n") {
                        answered = true;
                        let _ = s
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok",
                            )
                            .await;
                    }
                    if got.ends_with(b"0123456789abcdefghij") {
                        break;
                    }
                }
            });
        }
    });
    let h = start(ProxyConfig::default(), &[]).await;
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    s.write_all(
        format!("POST http://{up}/up HTTP/1.1\r\nHost: {up}\r\nContent-Length: 20\r\n\r\n0123456789")
            .as_bytes(),
    )
    .await
    .unwrap();
    let r = tokio::time::timeout(Duration::from_secs(5), read_response(&mut s))
        .await
        .unwrap()
        .unwrap();
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    s.write_all(b"abcdefghij").await.unwrap();
    let mut stored = String::new();
    for _ in 0..100 {
        h.proxy.flush();
        if let Some(f) = h.project.list_flows(&FlowFilter::default()).unwrap().first() {
            let d = h.project.get_flow(f.id).unwrap().unwrap();
            stored = String::from_utf8_lossy(&d.request).into_owned();
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(stored.ends_with("0123456789abcdefghij"), "{stored:?}");
}

/// A target that records the raw bytes of each request head it receives and answers 200.
async fn raw_target(seen: Arc<std::sync::Mutex<Vec<String>>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut b = [0u8; 1024];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&b[..n]),
                    }
                }
                seen.lock().unwrap().push(String::from_utf8_lossy(&got).into_owned());
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn header_name_case_survives_an_edit_of_the_request() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let up = raw_target(seen.clone()).await;
    let h = start(ProxyConfig::default(), &["127.0.0.1"]).await;
    h.proxy.intercept().set(InterceptSettings {
        requests: true,
        responses: false,
        in_scope_only: true,
        timeout_secs: None,
    });
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    s.write_all(
        format!("GET http://{up}/original HTTP/1.1\r\nHost: {up}\r\nX-Custom-CASE: yes\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let item = loop {
        if let Some(i) = h.proxy.intercept().list().first() {
            break h.proxy.intercept().get(i.id).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let edited = String::from_utf8(item.raw.clone()).unwrap().replace("/original", "/edited");
    assert!(h.proxy.intercept().resolve(
        item.summary.id,
        Decision::Forward {
            raw: Some(edited.into_bytes())
        }
    ));
    let mut resp = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut resp)).await;
    let got = seen.lock().unwrap().first().cloned().unwrap();
    assert!(got.starts_with("GET /edited"), "{got}");
    assert!(got.contains("X-Custom-CASE: yes"), "{got}");
}

#[tokio::test]
async fn upstream_sni_override_is_sent_to_the_target() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
            )
            .unwrap(),
    );
    let names = Arc::new(std::sync::Mutex::new(Vec::<Option<String>>::new()));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = l.local_addr().unwrap();
    let n2 = names.clone();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let (cfg, n2) = (cfg.clone(), n2.clone());
            tokio::spawn(async move {
                let Ok(start) =
                    tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), s).await
                else {
                    return;
                };
                n2.lock()
                    .unwrap()
                    .push(start.client_hello().server_name().map(str::to_string));
                if let Ok(tls) = start.into_stream(cfg).await {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service_fn(echo))
                        .await;
                }
            });
        }
    });
    let mut cfg = ProxyConfig::default();
    cfg.upstream_sni.insert("LOCALHOST".into(), "front.example.net".into());
    let h = start(cfg, &[]).await;
    let c = client(&h);
    let r = c
        .get(format!("https://localhost:{}/x", up.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.text().await.unwrap().starts_with("GET /x"));
    let seen = names.lock().unwrap().clone();
    assert!(!seen.is_empty());
    assert!(
        seen.iter().all(|n| n.as_deref() == Some("front.example.net")),
        "{seen:?}"
    );
}

/// A target that accepts the WebSocket handshake with `permessage-deflate` and sends two compressed text
/// messages sharing one window.
async fn deflate_ws_target() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut b = [0u8; 1024];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&b[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&got).into_owned();
                let key = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
                    .unwrap()
                    .trim()
                    .to_string();
                let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
                s.write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                         Sec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
                let mut c = flate2::Compress::new(flate2::Compression::default(), false);
                for text in ["compressed hello compressed hello", "compressed hello again"] {
                    let mut z = Vec::with_capacity(256);
                    c.compress_vec(text.as_bytes(), &mut z, flate2::FlushCompress::Sync)
                        .unwrap();
                    z.truncate(z.len() - 4);
                    let mut f = vec![0xC1, z.len() as u8];
                    f.extend_from_slice(&z);
                    s.write_all(&f).await.unwrap();
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn permessage_deflate_messages_are_recorded_inflated() {
    let up = deflate_ws_target().await;
    let h = start(ProxyConfig::default(), &[]).await;
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    s.write_all(format!("CONNECT {up} HTTP/1.1\r\nHost: {up}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 256];
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    s.write_all(
        format!(
            "GET /chat HTTP/1.1\r\nHost: {up}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    // The client still receives the compressed frames untouched.
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_millis(400), async {
        let mut b = [0u8; 1024];
        loop {
            match s.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&b[..n]),
            }
        }
    })
    .await;
    assert!(got.contains(&0xC1));
    h.proxy.flush();
    let flows = h.project.list_flows(&FlowFilter::default()).unwrap();
    assert_eq!(flows.len(), 1);
    let msgs = h.project.ws_messages(flows[0].id, None, 100).unwrap();
    let texts: Vec<_> = msgs
        .iter()
        .map(|m| String::from_utf8_lossy(&m.payload).to_string())
        .collect();
    assert_eq!(
        texts,
        vec!["compressed hello compressed hello", "compressed hello again"]
    );
}

#[tokio::test]
async fn listener_connection_cap_applies_per_listener_and_changes_live() {
    let h = start(ProxyConfig::default(), &[]).await;
    let spec = |addr: &str, max| bosun_proxy::ListenerSpec {
        addr: addr.parse().unwrap(),
        invisible: false,
        tls_passthrough: vec![],
        auth: None,
        allow_clients: vec![],
        max_connections: max,
    };
    let info = h.proxy.add_listener(spec("127.0.0.1:0", Some(1))).await.unwrap();
    let capped = info.spec.addr;
    let first = TcpStream::connect(capped).await.unwrap();
    // Let the accept loop register the first connection before the second arrives.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut second = TcpStream::connect(capped).await.unwrap();
    let mut b = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(2), second.read(&mut b)).await;
    assert!(matches!(r, Ok(Ok(0) | Err(_))), "the second connection is closed");
    // Raise the cap live: a second connection now stays open.
    h.proxy.update_listener(info.id, spec(&capped.to_string(), Some(2))).await.unwrap();
    let mut third = TcpStream::connect(capped).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), third.read(&mut b))
            .await
            .is_err(),
        "a connection under the raised cap stays open"
    );
    drop(first);
    assert!(
        h.proxy.update_listener(info.id, spec(&capped.to_string(), Some(0))).await.is_err(),
        "zero is refused"
    );
}

#[tokio::test]
async fn transparent_https_is_intercepted_by_sni_and_recorded() {
    let h = start(
        ProxyConfig {
            invisible: true,
            ..Default::default()
        },
        &[],
    )
    .await;
    // No proxy settings: the client connects straight to the listener, as a redirected connection would.
    let c = reqwest::Client::builder()
        .resolve("transparent.test", h.addr)
        .add_root_certificate(reqwest::Certificate::from_pem(h.ca.cert_pem().as_bytes()).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    // The proxy reaches for transparent.test:443, which does not exist, so it answers with an error page;
    // getting an answer over a certificate the Bosun CA issued for the SNI is the point.
    let r = c.get("https://transparent.test/x?y=1").send().await.unwrap();
    assert!(r.status().is_server_error(), "{}", r.status());

    h.proxy.flush();
    let flows = h.project.list_flows(&FlowFilter::default()).unwrap();
    assert!(
        flows
            .iter()
            .any(|f| f.host == "transparent.test" && f.path == "/x?y=1" && f.scheme == bosun_model::Scheme::Https),
        "{flows:?}"
    );
}
