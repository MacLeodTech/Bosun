//! Map Local, Map Remote and throttle rules through a real proxy.

#![allow(clippy::unwrap_used)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bosun_ca::CertificateAuthority;
use bosun_proxy::mapping::{MapKind, MapRule};
use bosun_proxy::{Proxy, ProxyConfig};
use bosun_scope::{Gate, RuleSpec as ScopeRule, Scope, ScopeSpec};
use bosun_store::{FlowFilter, Project};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut out = format!("UPSTREAM {} {}\n", req.method(), req.uri());
    for (n, v) in req.headers() {
        out.push_str(&format!("{}: {}\n", n, v.to_str().unwrap_or("?")));
    }
    let _ = req.into_body().collect().await;
    Ok(Response::new(Full::new(Bytes::from(out))))
}

async fn upstream() -> SocketAddr {
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

struct Harness {
    proxy: Proxy,
    addr: SocketAddr,
    project: Arc<Project>,
    ca: Arc<CertificateAuthority>,
}

async fn start(scope_hosts: &[&str]) -> Harness {
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ProxyConfig {
        listen: addr,
        ..Default::default()
    };
    let events = bosun_proxy::EventBus::new(64);
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

fn rule(kind: MapKind) -> MapRule {
    MapRule {
        enabled: true,
        kind,
        host: "127.0.0.1".into(),
        path_prefix: String::new(),
        directory: String::new(),
        target: String::new(),
        latency_ms: 0,
        bytes_per_sec: 0,
        comment: String::new(),
    }
}

#[tokio::test]
async fn map_local_answers_from_a_file_and_records_it() {
    let up = upstream().await;
    let h = start(&["127.0.0.1"]).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.js"), b"console.log('local')").unwrap();
    h.proxy
        .set_map_rules(vec![MapRule {
            path_prefix: "/static".into(),
            directory: dir.path().to_str().unwrap().into(),
            ..rule(MapKind::MapLocal)
        }])
        .unwrap();
    let c = client(&h);
    let r = c
        .get(format!("http://{up}/static/app.js?v=2"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "text/javascript; charset=utf-8");
    assert_eq!(r.text().await.unwrap(), "console.log('local')");

    // A file that is not there, and a path outside the prefix, go to the real target.
    let r = c.get(format!("http://{up}/static/none.js")).send().await.unwrap();
    assert!(
        r.text()
            .await
            .unwrap()
            .starts_with("UPSTREAM GET /static/none.js")
    );
    let r = c.get(format!("http://{up}/other")).send().await.unwrap();
    assert!(r.text().await.unwrap().starts_with("UPSTREAM GET /other"));
    // So does a POST: only GET and HEAD are answered from files.
    let r = c.post(format!("http://{up}/static/app.js")).send().await.unwrap();
    assert!(r.text().await.unwrap().starts_with("UPSTREAM POST"));

    h.proxy.flush();
    let flows = h.project.list_flows(&FlowFilter::default()).unwrap();
    let local = flows.iter().find(|f| f.path == "/static/app.js?v=2").unwrap();
    assert_eq!(local.status, Some(200));
    let d = h.project.get_flow(local.id).unwrap().unwrap();
    assert!(String::from_utf8_lossy(d.response.as_ref().unwrap()).contains("console.log('local')"));
}

#[tokio::test]
async fn map_local_refuses_traversal_and_symlinks_through_the_proxy() {
    let up = upstream().await;
    let h = start(&["127.0.0.1"]).await;
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("pub");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(root.path().join("secret.txt"), b"TOP SECRET").unwrap();
    std::fs::write(dir.join("ok.txt"), b"fine").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.path().join("secret.txt"), dir.join("link.txt")).unwrap();
    h.proxy
        .set_map_rules(vec![MapRule {
            directory: dir.to_str().unwrap().into(),
            ..rule(MapKind::MapLocal)
        }])
        .unwrap();
    let c = client(&h);
    assert_eq!(
        c.get(format!("http://{up}/ok.txt"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "fine"
    );
    // reqwest would normalise `..`, so send the encoded forms raw.
    let mut paths = vec![
        "/%2e%2e/secret.txt",
        "/%2E%2E%2Fsecret.txt",
        "/a/%2e%2e/%2e%2e/secret.txt",
    ];
    if cfg!(unix) {
        paths.push("/link.txt");
    }
    for p in paths {
        let mut s = tokio::net::TcpStream::connect(h.addr).await.unwrap();
        let req = format!("GET http://{up}{p} HTTP/1.1\r\nHost: {up}\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        let out = String::from_utf8_lossy(&out);
        assert!(!out.contains("TOP SECRET"), "{p} leaked: {out}");
        assert!(out.starts_with("HTTP/1.1 403"), "{p}: {out}");
    }
}

#[tokio::test]
async fn map_remote_sends_the_request_to_the_new_target() {
    let a = upstream().await;
    let b = upstream().await;
    let h = start(&["127.0.0.1"]).await;
    h.proxy
        .set_map_rules(vec![MapRule {
            path_prefix: "/api".into(),
            target: format!("http://127.0.0.1:{}", b.port()),
            ..rule(MapKind::MapRemote)
        }])
        .unwrap();
    // The gate must agree: the target host is in scope, and a literal IP the scope names may be used.
    h.proxy
        .check_remote_target(
            &bosun_proxy::mapping::parse_target(&format!("http://127.0.0.1:{}", b.port())).unwrap(),
        )
        .unwrap();
    let c = client(&h);
    let body = c
        .get(format!("http://{a}/api/x?q=1"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.starts_with("UPSTREAM GET /api/x?q=1"), "{body}");
    assert!(
        body.contains(&format!("host: 127.0.0.1:{}", b.port())),
        "Host follows the new target: {body}"
    );
    // Outside the prefix the original target is used.
    let body = c
        .get(format!("http://{a}/plain"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains(&format!("host: 127.0.0.1:{}", a.port())), "{body}");

    // The history keeps the target the client asked for.
    h.proxy.flush();
    let flows = h.project.list_flows(&FlowFilter::default()).unwrap();
    let f = flows.iter().find(|f| f.path == "/api/x?q=1").unwrap();
    assert_eq!(f.port, a.port());
}

#[tokio::test]
async fn map_remote_to_an_out_of_scope_target_is_refused() {
    let a = upstream().await;
    let b = upstream().await;
    // Only host `127.0.0.1` on a's port is browsed; the scope has no rule that covers a different host name.
    let h = start(&[]).await;
    h.proxy
        .set_map_rules(vec![MapRule {
            target: format!("http://127.0.0.1:{}", b.port()),
            ..rule(MapKind::MapRemote)
        }])
        .unwrap();
    assert!(
        h.proxy
            .check_remote_target(
                &bosun_proxy::mapping::parse_target(&format!("http://127.0.0.1:{}", b.port())).unwrap()
            )
            .is_err()
    );
    let r = client(&h).get(format!("http://{a}/x")).send().await.unwrap();
    assert_eq!(r.status(), 403);
    let body = r.text().await.unwrap();
    assert!(body.contains("Map Remote refused"), "{body}");
    assert!(!body.contains("UPSTREAM"), "nothing was sent: {body}");

    h.proxy.flush();
    let flows = h.project.list_flows(&FlowFilter::default()).unwrap();
    assert!(
        flows.iter().all(|f| f.error.is_some() || f.status.is_none()),
        "{flows:?}"
    );
}

#[tokio::test]
async fn throttle_adds_latency_and_limits_bandwidth() {
    let up = upstream().await;
    let h = start(&["127.0.0.1"]).await;
    let c = client(&h);
    let t = Instant::now();
    let body = c
        .get(format!("http://{up}/fast"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let plain = t.elapsed();
    let size = body.len();

    h.proxy
        .set_map_rules(vec![MapRule {
            path_prefix: "/slow".into(),
            latency_ms: 400,
            ..rule(MapKind::Throttle)
        }])
        .unwrap();
    let t = Instant::now();
    c.get(format!("http://{up}/slow"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        t.elapsed() >= Duration::from_millis(380),
        "latency {:?}",
        t.elapsed()
    );
    let t = Instant::now();
    c.get(format!("http://{up}/fast"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        t.elapsed() < Duration::from_millis(380),
        "an unmatched path is not delayed"
    );
    assert!(plain < Duration::from_millis(380));

    // The body is about `size + 5` bytes; at size*2 bytes a second that is about half a second.
    h.proxy
        .set_map_rules(vec![MapRule {
            bytes_per_sec: (size as u32) * 2,
            ..rule(MapKind::Throttle)
        }])
        .unwrap();
    let t = Instant::now();
    c.get(format!("http://{up}/fast"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        t.elapsed() >= Duration::from_millis(400),
        "bandwidth {:?}",
        t.elapsed()
    );
}
