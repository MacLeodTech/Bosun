#![allow(clippy::unwrap_used)]
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bosun_http::h2::H2Request;
use bosun_http::{Engine, SendError, SendOptions};
use bosun_model::{Scheme, Target};
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, Resolver, RuleSpec, Scope, ScopeSpec};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn engine(path: Option<&str>) -> Engine {
    let scope = Scope::compile(ScopeSpec {
        include: vec![RuleSpec {
            host: "127.0.0.1".into(),
            path: path.map(str::to_string),
            allow_private: true,
            ..Default::default()
        }],
        exclude: vec![],
    })
    .unwrap();
    Engine::new(Gate::new(scope), MemoryBudget::new(256 << 20))
}

fn target(a: SocketAddr) -> Target {
    Target::new(Scheme::Http, "127.0.0.1", a.port())
}

fn reuse() -> SendOptions {
    SendOptions {
        reuse: true,
        ..Default::default()
    }
}

const GET: &[u8] = b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n";

/// An HTTP/1.1 server that keeps connections open and answers every request with `reply`. `close_after` closes
/// the connection after that many answers (0: never).
async fn keepalive_server(reply: &'static [u8], close_after: usize) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], l.local_addr().unwrap().port()));
    let accepted = Arc::new(AtomicUsize::new(0));
    let n = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            n.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut served = 0;
                let mut b = [0u8; 1];
                loop {
                    while !head.ends_with(b"\r\n\r\n") {
                        if s.read(&mut b).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(b[0]);
                    }
                    head.clear();
                    if s.write_all(reply).await.is_err() {
                        return;
                    }
                    served += 1;
                    if close_after != 0 && served >= close_after {
                        return;
                    }
                }
            });
        }
    });
    (addr, accepted)
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

#[tokio::test]
async fn http1_connections_are_reused_when_asked_and_not_otherwise() {
    let (addr, accepted) = keepalive_server(OK, 0).await;
    let e = engine(None);
    let mut seen = Vec::new();
    for _ in 0..3 {
        let ex = e.send(&target(addr), GET, &reuse()).await.unwrap();
        assert_eq!(ex.response, OK);
        seen.push((ex.reused, ex.timings.connect_ms));
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    assert!(!seen[0].0 && seen[1].0 && seen[2].0, "{seen:?}");
    assert_eq!(seen[1].1, 0, "no connect time on a reused connection");
    assert_eq!(e.pooled().0, 1);

    // Off by default: every send gets a connection of its own.
    let (addr, accepted) = keepalive_server(OK, 0).await;
    for _ in 0..3 {
        let ex = e.send(&target(addr), GET, &SendOptions::default()).await.unwrap();
        assert!(!ex.reused);
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
    e.close_idle();
    assert_eq!(e.pooled(), (0, 0));
}

#[tokio::test]
async fn a_connection_is_not_kept_when_the_exchange_does_not_leave_it_clean() {
    // The server says it is closing.
    let (addr, accepted) = keepalive_server(
        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok",
        0,
    )
    .await;
    let e = engine(None);
    for _ in 0..2 {
        e.send(&target(addr), GET, &reuse()).await.unwrap();
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    // The request says it is closing.
    let (addr, accepted) = keepalive_server(OK, 0).await;
    for _ in 0..2 {
        e.send(
            &target(addr),
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            &reuse(),
        )
        .await
        .unwrap();
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    // A close-delimited body has no end but the close.
    let (addr, accepted) = keepalive_server(b"HTTP/1.1 200 OK\r\n\r\nuntil close", 1).await;
    for _ in 0..2 {
        let ex = e.send(&target(addr), GET, &reuse()).await.unwrap();
        assert!(ex.response.ends_with(b"until close"));
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    // More bytes than the framing allows: the connection cannot be trusted.
    let (addr, accepted) = keepalive_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA", 0).await;
    for _ in 0..2 {
        e.send(&target(addr), GET, &reuse()).await.unwrap();
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_connection_the_server_closed_while_idle_is_not_handed_out() {
    // The server closes after each answer without saying so.
    let (addr, accepted) = keepalive_server(OK, 1).await;
    let e = engine(None);
    for _ in 0..3 {
        let ex = e.send(&target(addr), GET, &reuse()).await.unwrap();
        assert_eq!(ex.response, OK);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
}

#[derive(Debug)]
struct Switching(Arc<Mutex<IpAddr>>);
impl Resolver for Switching {
    fn resolve(&self, _: &str, _: u16) -> std::io::Result<Vec<IpAddr>> {
        Ok(vec![*self.0.lock().unwrap()])
    }
}

#[tokio::test]
async fn a_pooled_connection_is_only_used_for_an_address_the_gate_just_pinned() {
    let (addr, accepted) = keepalive_server(OK, 0).await;
    let ip = Arc::new(Mutex::new("127.0.0.1".parse::<IpAddr>().unwrap()));
    let scope = Scope::compile(ScopeSpec {
        include: vec![RuleSpec {
            host: "app.test".into(),
            allow_private: true,
            ..Default::default()
        }],
        exclude: vec![],
    })
    .unwrap();
    let e = Engine::new(
        Gate::with_resolver(scope, Box::new(Switching(ip.clone()))),
        MemoryBudget::new(1 << 20),
    );
    let t = Target::new(Scheme::Http, "app.test", addr.port());
    let first = e.send(&t, GET, &reuse()).await.unwrap();
    assert_eq!(first.peer.ip().to_string(), "127.0.0.1");
    // The name now resolves elsewhere: the idle connection to the old address must not be used.
    *ip.lock().unwrap() = "127.0.0.2".parse().unwrap();
    let second = e.send(&t, GET, &reuse()).await.unwrap();
    assert_eq!(second.peer.ip().to_string(), "127.0.0.2");
    assert!(!second.reused);
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

// ---- HTTP/2 multiplexing ----------------------------------------------------------------------------------

#[derive(Default)]
struct Stats {
    accepted: AtomicUsize,
    inflight: AtomicUsize,
    max_inflight: AtomicUsize,
    cancelled: AtomicUsize,
}

/// hyper's HTTP/2 server (h2c). `/slow` waits 300 ms, `/hang` never answers, `/big` sends 4 MB, `/len` answers with
/// the length of the body it was sent, anything else echoes its path. `goaway_after` asks the first connection to
/// shut down gracefully after that many requests.
async fn h2_server(stats: Arc<Stats>, goaway_after: usize) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let first = stats.accepted.fetch_add(1, Ordering::SeqCst) == 0;
            let stats = stats.clone();
            tokio::spawn(async move {
                let served = Arc::new(AtomicUsize::new(0));
                let (shut_tx, shut_rx) = tokio::sync::oneshot::channel::<()>();
                let shut_tx = Arc::new(Mutex::new(Some(shut_tx)));
                let st = stats.clone();
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let (st, served, shut_tx) = (st.clone(), served.clone(), shut_tx.clone());
                    async move {
                        let now = st.inflight.fetch_add(1, Ordering::SeqCst) + 1;
                        st.max_inflight.fetch_max(now, Ordering::SeqCst);
                        struct Guard(Arc<Stats>, bool);
                        impl Drop for Guard {
                            fn drop(&mut self) {
                                self.0.inflight.fetch_sub(1, Ordering::SeqCst);
                                if !self.1 {
                                    self.0.cancelled.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        }
                        let mut guard = Guard(st.clone(), false);
                        let path = req.uri().path().to_string();
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|b| b.to_bytes().len())
                            .unwrap_or(0);
                        let out: Vec<u8> = match path.as_str() {
                            "/slow" => {
                                tokio::time::sleep(Duration::from_millis(300)).await;
                                b"slow".to_vec()
                            }
                            "/hang" => {
                                tokio::time::sleep(Duration::from_secs(30)).await;
                                Vec::new()
                            }
                            "/big" => vec![b'b'; 4 << 20],
                            "/len" => body.to_string().into_bytes(),
                            p => p.as_bytes().to_vec(),
                        };
                        guard.1 = true;
                        if goaway_after != 0
                            && served.fetch_add(1, Ordering::SeqCst) + 1 == goaway_after
                            && let Some(tx) = shut_tx.lock().unwrap().take()
                        {
                            let _ = tx.send(());
                        }
                        Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from(out))))
                    }
                });
                let b = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                let conn = b.serve_connection(TokioIo::new(s), svc);
                tokio::pin!(conn);
                if first && goaway_after != 0 {
                    tokio::select! {
                        _ = conn.as_mut() => {}
                        _ = shut_rx => {
                            conn.as_mut().graceful_shutdown();
                            let _ = conn.await;
                        }
                    }
                } else {
                    let _ = conn.await;
                }
            });
        }
    });
    addr
}

fn req(path: &str) -> H2Request {
    H2Request::new("GET", "http", "127.0.0.1", path, &[])
}

fn body_of(ex: &bosun_http::Exchange) -> Vec<u8> {
    let i = ex.response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    ex.response[i..].to_vec()
}

#[tokio::test]
async fn many_requests_share_one_connection_and_run_at_the_same_time() {
    let stats = Arc::new(Stats::default());
    let addr = h2_server(stats.clone(), 0).await;
    let e = engine(None);
    let t = target(addr);
    let started = std::time::Instant::now();
    let mut tasks = Vec::new();
    for i in 0..20 {
        let (e, t) = (e.clone(), t.clone());
        tasks.push(tokio::spawn(async move {
            let ex = e
                .send_h2_request(&t, &req(&format!("/slow?{i}")), &SendOptions::default())
                .await
                .unwrap();
            (ex.status, body_of(&ex))
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), (Some(200), b"slow".to_vec()));
    }
    assert_eq!(stats.accepted.load(Ordering::SeqCst), 1, "one connection");
    assert!(
        stats.max_inflight.load(Ordering::SeqCst) > 5,
        "{}",
        stats.max_inflight.load(Ordering::SeqCst)
    );
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "20 x 300 ms ran in parallel: {:?}",
        started.elapsed()
    );
    assert_eq!(e.pooled().1, 1);
    // A later request finds the connection still there.
    let ex = e
        .send_h2_request(&t, &req("/again"), &SendOptions::default())
        .await
        .unwrap();
    assert!(ex.reused && body_of(&ex) == b"/again");
    assert_eq!(ex.h2.unwrap().frames_out.len(), 1);
}

#[tokio::test]
async fn a_batch_goes_out_together_and_comes_back_in_order() {
    let stats = Arc::new(Stats::default());
    let addr = h2_server(stats.clone(), 0).await;
    let e = engine(None);
    let reqs: Vec<H2Request> = (0..6).map(|i| req(&format!("/r{i}"))).collect();
    let out = e
        .send_h2_batch(&target(addr), &reqs, &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(out.len(), 6);
    for (i, ex) in out.iter().enumerate() {
        assert_eq!(body_of(ex), format!("/r{i}").into_bytes());
        // Stream ids are consecutive odd numbers: they were started together.
        assert_eq!(ex.h2.as_ref().unwrap().frames_out[0].stream, 2 * i as u32 + 1);
    }
    assert_eq!(stats.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn bodies_larger_than_the_window_are_sent_and_large_responses_are_received() {
    let stats = Arc::new(Stats::default());
    let addr = h2_server(stats, 0).await;
    let e = engine(None);
    let mut up = H2Request::new("POST", "http", "127.0.0.1", "/len", &[]);
    up.body = vec![7u8; 700_000];
    let ex = e
        .send_h2_request(&target(addr), &up, &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(ex.error, None);
    assert_eq!(body_of(&ex), b"700000");
    // Six responses of 4 MB at once is more than the connection window, so it has to be raised as data is read.
    let opts = SendOptions {
        max_response: 8 << 20,
        ..Default::default()
    };
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let (e, t, o) = (e.clone(), target(addr), opts.clone());
        tasks.push(tokio::spawn(async move {
            e.send_h2_request(&t, &req("/big"), &o).await.unwrap()
        }));
    }
    for t in tasks {
        let ex = t.await.unwrap();
        assert_eq!((ex.error.clone(), ex.truncated), (None, false), "{:?}", ex.error);
        assert_eq!(body_of(&ex).len(), 4 << 20);
    }
}

#[tokio::test]
async fn a_response_over_the_limit_is_cut_off_and_the_connection_goes_on() {
    let stats = Arc::new(Stats::default());
    let addr = h2_server(stats.clone(), 0).await;
    let e = engine(None);
    let opts = SendOptions {
        max_response: 100_000,
        ..Default::default()
    };
    let ex = e
        .send_h2_request(&target(addr), &req("/big"), &opts)
        .await
        .unwrap();
    assert!(ex.truncated);
    assert!(body_of(&ex).len() <= 100_000);
    let ex = e
        .send_h2_request(&target(addr), &req("/after"), &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(body_of(&ex), b"/after");
    assert_eq!(stats.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn giving_up_on_a_request_cancels_its_stream_and_leaves_the_others() {
    let stats = Arc::new(Stats::default());
    let addr = h2_server(stats.clone(), 0).await;
    let e = engine(None);
    let t = target(addr);
    let opts = SendOptions {
        total_timeout: Duration::from_millis(400),
        ..Default::default()
    };
    let hung = e.send_h2_request(&t, &req("/hang"), &opts).await.unwrap();
    assert!(
        hung.error.as_deref().unwrap().contains("timed out"),
        "{:?}",
        hung.error
    );
    // The server was told to stop (its handler future was dropped).
    for _ in 0..40 {
        if stats.cancelled.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(stats.cancelled.load(Ordering::SeqCst), 1);
    let ok = e
        .send_h2_request(&t, &req("/fine"), &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(body_of(&ok), b"/fine");
    assert_eq!(stats.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn after_goaway_the_next_request_opens_a_new_connection() {
    let stats = Arc::new(Stats::default());
    let addr = h2_server(stats.clone(), 1).await;
    let e = engine(None);
    let t = target(addr);
    let first = e
        .send_h2_request(&t, &req("/one"), &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(body_of(&first), b"/one");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let second = e
        .send_h2_request(&t, &req("/two"), &SendOptions::default())
        .await
        .unwrap();
    assert_eq!((second.error.clone(), body_of(&second)), (None, b"/two".to_vec()));
    assert!(!second.reused);
    assert_eq!(stats.accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_gate_is_asked_about_every_path_of_a_batch_before_anything_is_sent() {
    let stats = Arc::new(Stats::default());
    let addr = h2_server(stats.clone(), 0).await;
    let e = engine(Some("^/ok"));
    let r = e
        .send_h2_batch(
            &target(addr),
            &[req("/ok/1"), req("/secret")],
            &SendOptions::default(),
        )
        .await;
    assert!(matches!(r, Err(SendError::Refused(_))), "{r:?}");
    assert_eq!(stats.accepted.load(Ordering::SeqCst), 0);
}
