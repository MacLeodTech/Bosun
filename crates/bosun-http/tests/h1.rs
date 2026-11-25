#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bosun_http::{Engine, SendError, SendOptions};
use bosun_model::{FlowSource, Scheme, Target};
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, OutOfScopePolicy, Resolver, RuleSpec, Scope, ScopeError, ScopeSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// A server that records what each connection sent (until it goes quiet) and answers with `reply`.
struct Server {
    addr: SocketAddr,
    seen: mpsc::UnboundedReceiver<Vec<u8>>,
    accepted: Arc<AtomicUsize>,
}

async fn server(reply: Vec<u8>) -> Server {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, seen) = mpsc::unbounded_channel();
    let accepted = Arc::new(AtomicUsize::new(0));
    let n = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            n.fetch_add(1, Ordering::SeqCst);
            let (tx, reply) = (tx.clone(), reply.clone());
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(150), s.read(&mut buf)).await
                {
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                let _ = tx.send(got);
                let _ = s.write_all(&reply).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Server { addr, seen, accepted }
}

fn rule(host: &str, allow_private: bool) -> RuleSpec {
    RuleSpec {
        host: host.into(),
        allow_private,
        ..Default::default()
    }
}

fn engine_for(hosts: &[&str]) -> Engine {
    let scope = Scope::compile(ScopeSpec {
        include: hosts.iter().map(|h| rule(h, true)).collect(),
        exclude: vec![],
    })
    .unwrap();
    Engine::new(Gate::new(scope), MemoryBudget::new(64 << 20))
}

fn target(addr: SocketAddr) -> Target {
    Target::new(Scheme::Http, addr.ip().to_string(), addr.port())
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

#[tokio::test]
async fn a_malformed_request_arrives_unchanged() {
    let mut srv = server(OK.to_vec()).await;
    let e = engine_for(&["127.0.0.1"]);
    // Odd method, duplicate headers, bare LF line ends, and a Content-Length that is wrong on purpose.
    let raw = b"BREW /pot?x=1 HTTP/1.1\nHost: a\nX-Dup: 1\nx-dup: 2\nContent-Length: 99\n\nbody";
    let ex = e
        .send(&target(srv.addr), raw, &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(srv.seen.recv().await.unwrap(), raw);
    assert_eq!(ex.request, raw);
    assert_eq!(ex.status, Some(200));
    assert_eq!(ex.response, OK);
    assert!(ex.error.is_none() && !ex.truncated);
    assert!(ex.timings.first_byte_ms.is_some() && ex.timings.tls_ms.is_none());
}

#[tokio::test]
async fn content_length_is_only_updated_when_asked() {
    let mut srv = server(OK.to_vec()).await;
    let e = engine_for(&["127.0.0.1"]);
    let raw = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99\r\n\r\nabc";
    let opts = SendOptions {
        update_content_length: true,
        ..Default::default()
    };
    e.send(&target(srv.addr), raw, &opts).await.unwrap();
    assert_eq!(
        srv.seen.recv().await.unwrap(),
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc"
    );
}

#[tokio::test]
async fn out_of_scope_targets_are_refused_and_never_connected_to() {
    let srv = server(OK.to_vec()).await;
    let e = engine_for(&["other.example"]);
    let r = e
        .send(
            &target(srv.addr),
            b"GET / HTTP/1.1\r\n\r\n",
            &SendOptions::default(),
        )
        .await;
    assert!(
        matches!(r, Err(SendError::Refused(ScopeError::OutOfScope(_)))),
        "{r:?}"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(srv.accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_kill_switch_stops_sends() {
    let srv = server(OK.to_vec()).await;
    let gate = Gate::new(
        Scope::compile(ScopeSpec {
            include: vec![rule("127.0.0.1", true)],
            exclude: vec![],
        })
        .unwrap(),
    );
    gate.set_stopped(true);
    let e = Engine::new(gate, MemoryBudget::new(1 << 20));
    let r = e
        .send(
            &target(srv.addr),
            b"GET / HTTP/1.1\r\n\r\n",
            &SendOptions::default(),
        )
        .await;
    assert!(matches!(r, Err(SendError::Refused(ScopeError::Stopped))), "{r:?}");
    assert_eq!(srv.accepted.load(Ordering::SeqCst), 0);
}

#[derive(Debug)]
struct Fixed(IpAddr);
impl Resolver for Fixed {
    fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<IpAddr>> {
        Ok(vec![self.0])
    }
}

#[tokio::test]
async fn the_connection_goes_to_the_pinned_address() {
    let mut srv = server(OK.to_vec()).await;
    // `app.test` is in scope and the resolver says it is 127.0.0.1 (allowed by the rule), so the send connects
    // there, on the target's port, with the name kept in the request.
    let scope = Scope::compile(ScopeSpec {
        include: vec![rule("app.test", true)],
        exclude: vec![],
    })
    .unwrap();
    let gate = Gate::with_resolver(scope, Box::new(Fixed("127.0.0.1".parse().unwrap())));
    let e = Engine::new(gate, MemoryBudget::new(1 << 20));
    let t = Target::new(Scheme::Http, "app.test", srv.addr.port());
    let ex = e
        .send(
            &t,
            b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
            &SendOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(ex.peer, srv.addr);
    assert!(
        srv.seen
            .recv()
            .await
            .unwrap()
            .starts_with(b"GET / HTTP/1.1\r\nHost: app.test")
    );
}

#[tokio::test]
async fn a_name_that_resolves_to_an_internal_address_is_refused() {
    for ip in ["127.0.0.1", "169.254.169.254"] {
        let srv = server(OK.to_vec()).await;
        let scope = Scope::compile(ScopeSpec {
            include: vec![rule("app.test", false)],
            exclude: vec![],
        })
        .unwrap();
        let e = Engine::new(
            Gate::with_resolver(scope, Box::new(Fixed(ip.parse().unwrap()))),
            MemoryBudget::new(1 << 20),
        );
        let t = Target::new(Scheme::Http, "app.test", srv.addr.port());
        let r = e
            .send(&t, b"GET / HTTP/1.1\r\n\r\n", &SendOptions::default())
            .await;
        assert!(
            matches!(r, Err(SendError::Refused(ScopeError::PrivateAddress { .. }))),
            "{ip}: {r:?}"
        );
        assert_eq!(srv.accepted.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn automated_tools_never_get_the_repeater_allow_policy() {
    let srv = server(OK.to_vec()).await;
    // Out of scope: refused by default.
    let gate = Gate::new(
        Scope::compile(ScopeSpec {
            include: vec![rule("elsewhere.test", false)],
            exclude: vec![],
        })
        .unwrap(),
    );
    let e = Engine::new(gate.clone(), MemoryBudget::new(1 << 20));
    let r = e
        .send(
            &target(srv.addr),
            b"GET / HTTP/1.1\r\n\r\n",
            &SendOptions::default(),
        )
        .await;
    assert!(matches!(r, Err(SendError::Refused(_))));
    // Automated tools never get the Allow policy.
    gate.set_repeater_policy(OutOfScopePolicy::Allow);
    let r = e
        .send(
            &target(srv.addr),
            b"GET / HTTP/1.1\r\n\r\n",
            &SendOptions {
                source: FlowSource::Scanner,
                ..Default::default()
            },
        )
        .await;
    assert!(
        matches!(r, Err(SendError::Refused(ScopeError::OutOfScope(_)))),
        "{r:?}"
    );
}

async fn reply_for(reply: &[u8], req: &[u8], opts: SendOptions) -> bosun_http::Exchange {
    let srv = server(reply.to_vec()).await;
    engine_for(&["127.0.0.1"])
        .send(&target(srv.addr), req, &opts)
        .await
        .unwrap()
}

#[tokio::test]
async fn response_framing_is_followed_and_the_bytes_are_kept_raw() {
    let get = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    // Chunked: the chunk framing stays in the stored bytes.
    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let ex = reply_for(chunked, get, SendOptions::default()).await;
    assert_eq!(ex.response, chunked);
    assert!(ex.error.is_none());
    // Close-delimited.
    let close = b"HTTP/1.0 200 OK\r\n\r\nuntil the end";
    let ex = reply_for(close, get, SendOptions::default()).await;
    assert_eq!(ex.response, close);
    assert!(ex.error.is_none());
    // An interim 100 stays in the bytes; the status is the final one.
    let interim = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
    let ex = reply_for(interim, get, SendOptions::default()).await;
    assert_eq!((ex.status, ex.response.as_slice()), (Some(201), &interim[..]));
    // HEAD: Content-Length does not mean a body follows.
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
    let ex = reply_for(
        head,
        b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
        SendOptions::default(),
    )
    .await;
    assert_eq!(ex.response, head);
    assert!(ex.error.is_none());
}

#[tokio::test]
async fn a_short_body_is_reported_with_what_arrived() {
    let short = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nonly this";
    let ex = reply_for(short, b"GET / HTTP/1.1\r\n\r\n", SendOptions::default()).await;
    assert_eq!(ex.response, short);
    assert_eq!(ex.status, Some(200));
    assert!(ex.error.as_deref().unwrap().contains("closed"), "{:?}", ex.error);
}

#[tokio::test]
async fn a_large_response_is_cut_at_the_limit() {
    let mut big = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n".to_vec();
    big.extend(vec![b'x'; 1_000_000]);
    let ex = reply_for(
        &big,
        b"GET / HTTP/1.1\r\n\r\n",
        SendOptions {
            max_response: 100_000,
            ..Default::default()
        },
    )
    .await;
    assert!(ex.truncated);
    assert_eq!(ex.response.len(), 100_000);
}

#[tokio::test]
async fn the_memory_budget_is_respected_and_released() {
    let mut big = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n".to_vec();
    big.extend(vec![b'x'; 1_000_000]);
    let srv = server(big).await;
    let scope = Scope::compile(ScopeSpec {
        include: vec![rule("127.0.0.1", true)],
        exclude: vec![],
    })
    .unwrap();
    let budget = MemoryBudget::new(300 * 1024);
    let e = Engine::new(Gate::new(scope), budget.clone());
    let ex = e
        .send(
            &target(srv.addr),
            b"GET / HTTP/1.1\r\n\r\n",
            &SendOptions::default(),
        )
        .await
        .unwrap();
    assert!(
        ex.truncated && ex.error.as_deref().unwrap().contains("budget"),
        "{:?}",
        ex.error
    );
    assert!(ex.response.len() < 1_000_000);
    assert_eq!(budget.used(), 0, "released afterwards");
}

#[tokio::test]
async fn https_records_the_tls_details_and_checks_certificates_on_request() {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let a = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut s) = a.accept(s).await else { return };
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(OK).await;
                let _ = s.shutdown().await;
            });
        }
    });
    let e = engine_for(&["127.0.0.1"]);
    let t = Target::new(Scheme::Https, "127.0.0.1", addr.port());
    let ex = e
        .send(&t, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(ex.response, OK);
    let tls = ex.tls.expect("tls details");
    assert!(tls.version.contains("TLS"), "{tls:?}");
    // The test server offers no ALPN, so none is negotiated.
    assert_eq!(tls.alpn, None);
    assert_eq!(tls.leaf_der.as_deref(), Some(ck.cert.der().as_ref()));
    assert!(ex.timings.tls_ms.is_some());
    // With checking on, a self-signed certificate is refused.
    let r = e
        .send(
            &t,
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
            &SendOptions {
                verify_tls: true,
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(r, Err(SendError::Tls(..))), "{r:?}");
}

#[tokio::test]
async fn an_exchange_is_stored_as_a_flow_with_the_tools_source() {
    let srv = server(OK.to_vec()).await;
    let ex = engine_for(&["127.0.0.1"])
        .send(
            &target(srv.addr),
            b"GET /a?b=1 HTTP/1.1\r\nHost: x\r\n\r\n",
            &SendOptions::default(),
        )
        .await
        .unwrap();
    let project = bosun_store::project::Project::open_in_memory().unwrap();
    let id = project.next_flow_id();
    project
        .write_batch(&[ex.to_new_flow(id, FlowSource::Repeater)], &[])
        .unwrap();
    let d = project.get_flow(id).unwrap().unwrap();
    assert_eq!(d.summary.source, FlowSource::Repeater);
    assert_eq!(
        (d.summary.method.as_str(), d.summary.path.as_str()),
        ("GET", "/a?b=1")
    );
    assert_eq!(d.summary.status, Some(200));
    assert!(d.summary.in_scope);
    assert_eq!(d.response.as_deref(), Some(OK));
}
