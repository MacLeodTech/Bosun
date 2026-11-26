//! Proxy hot path: request latency and throughput through the proxy to a local upstream.
//!
//! Run with `cargo bench -p bosun-proxy`. The upstream answers a GET with `/<n>` as an `n`-byte body and drains a
//! POST body; everything is recorded (the target is in scope), as in normal use.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bosun_ca::CertificateAuthority;
use bosun_proxy::{Proxy, ProxyConfig};
use bosun_scope::{Gate, RuleSpec as ScopeRule, Scope, ScopeSpec};
use bosun_store::Project;
use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

async fn upstream(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let n: usize = req.uri().path().trim_start_matches('/').parse().unwrap_or(2);
    let _ = req.into_body().collect().await;
    Ok(Response::new(Full::new(Bytes::from(vec![b'x'; n]))))
}

async fn setup() -> (SocketAddr, SocketAddr, reqwest::Client) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), service_fn(upstream))
                    .await;
            });
        }
    });
    let ca = Arc::new(CertificateAuthority::ephemeral().unwrap());
    let project = Arc::new(Project::open_in_memory().unwrap());
    let scope = Scope::compile(ScopeSpec {
        include: vec![ScopeRule {
            host: "127.0.0.1".into(),
            ..Default::default()
        }],
        exclude: vec![],
    })
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ProxyConfig {
        listen: addr,
        ..Default::default()
    };
    let proxy = Proxy::new(cfg, ca, Gate::new(scope), project, bosun_proxy::EventBus::new(64)).unwrap();
    tokio::spawn(async move { proxy.serve(listener, std::future::pending()).await });
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{addr}")).unwrap())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    (up, addr, client)
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let (up, _proxy, client) = rt.block_on(setup());

    let mut g = c.benchmark_group("proxy");
    g.sample_size(30);

    g.bench_function("latency_small_get", |b| {
        b.to_async(&rt).iter(|| async {
            client
                .get(format!("http://{up}/2"))
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
        });
    });

    const MIB4: usize = 4 << 20;
    g.throughput(Throughput::Bytes(MIB4 as u64));
    g.bench_function("throughput_download_4mib", |b| {
        b.to_async(&rt).iter(|| async {
            client
                .get(format!("http://{up}/{MIB4}"))
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
        });
    });
    let payload = Bytes::from(vec![b'y'; MIB4]);
    g.bench_function("throughput_upload_4mib", |b| {
        b.to_async(&rt).iter(|| async {
            client
                .post(format!("http://{up}/2"))
                .body(payload.clone())
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
