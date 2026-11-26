#![allow(clippy::unwrap_used)]
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bosun_http::{Engine, SendError, SendOptions};
use bosun_model::{Scheme, Target};
use bosun_proxy::budget::MemoryBudget;
use bosun_proxy::{LoopGuard, UpstreamProxy};
use bosun_scope::{Gate, Resolver, RuleSpec, Scope, ScopeSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

/// A server that reads one request per connection (head, plus `Content-Length` bytes) and answers with
/// `route(request)`.
async fn router(route: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static) -> (SocketAddr, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let (route, log) = (Arc::new(route), seen.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let (route, log) = (route.clone(), log.clone());
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(100), s.read(&mut buf)).await
                {
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                log.lock().unwrap().push(got.clone());
                let _ = s.write_all(&route(&got)).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (addr, seen)
}

fn redirect(status: u16, to: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status} Found\r\nLocation: {to}\r\nContent-Length: 0\r\n\r\n").into_bytes()
}

const DONE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone";

fn engine(hosts: &[&str]) -> Engine {
    let scope = Scope::compile(ScopeSpec {
        include: hosts
            .iter()
            .map(|h| RuleSpec {
                host: (*h).into(),
                allow_private: true,
                ..Default::default()
            })
            .collect(),
        exclude: vec![],
    })
    .unwrap();
    Engine::new(Gate::new(scope), MemoryBudget::new(64 << 20))
}

fn target(a: SocketAddr) -> Target {
    Target::new(Scheme::Http, a.ip().to_string(), a.port())
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[tokio::test]
async fn a_chain_is_followed_and_every_hop_is_returned() {
    let (addr, seen) = router(|req| {
        let line = text(req);
        if line.starts_with("GET /a ") {
            redirect(302, "/b?x=1")
        } else if line.starts_with("GET /b?x=1 ") {
            DONE.to_vec()
        } else {
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
        }
    })
    .await;
    let chain = engine(&["127.0.0.1"])
        .send_following(
            &target(addr),
            b"GET /a HTTP/1.1\r\nHost: h\r\nX-Keep: 1\r\n\r\n",
            &SendOptions::default(),
            5,
        )
        .await
        .unwrap();
    assert_eq!(
        chain.iter().map(|e| e.status).collect::<Vec<_>>(),
        [Some(302), Some(200)]
    );
    // The next request is the old one with a new request-target and Host, nothing else touched.
    assert_eq!(
        seen.lock().unwrap()[1],
        format!(
            "GET /b?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Keep: 1\r\n\r\n",
            addr.port()
        )
        .into_bytes()
    );
}

#[tokio::test]
async fn following_is_off_with_zero_and_303_turns_a_post_into_a_get() {
    let (addr, seen) = router(|req| {
        if text(req).starts_with("POST /form ") {
            redirect(303, "/result")
        } else {
            DONE.to_vec()
        }
    })
    .await;
    let post = b"POST /form HTTP/1.1\r\nHost: h\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc";
    let e = engine(&["127.0.0.1"]);
    let one = e
        .send_following(&target(addr), post, &SendOptions::default(), 0)
        .await
        .unwrap();
    assert_eq!(one.len(), 1);
    let chain = e
        .send_following(&target(addr), post, &SendOptions::default(), 3)
        .await
        .unwrap();
    assert_eq!(chain.len(), 2);
    let second = text(&seen.lock().unwrap()[2]);
    assert!(second.starts_with("GET /result HTTP/1.1\r\n"), "{second:?}");
    assert!(
        !second.contains("Content-") && !second.contains("abc"),
        "{second:?}"
    );
}

#[tokio::test]
async fn a_307_keeps_the_method_and_body() {
    let (addr, seen) = router(|req| {
        if text(req).contains(" /old ") {
            redirect(307, "/new")
        } else {
            DONE.to_vec()
        }
    })
    .await;
    let post = b"POST /old HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
    let chain = engine(&["127.0.0.1"])
        .send_following(&target(addr), post, &SendOptions::default(), 3)
        .await
        .unwrap();
    assert_eq!(chain.len(), 2);
    assert!(text(&seen.lock().unwrap()[1]).starts_with("POST /new HTTP/1.1\r\n"));
    assert!(text(&seen.lock().unwrap()[1]).ends_with("\r\n\r\nabc"));
}

#[tokio::test]
async fn a_loop_ends_the_chain_with_an_error() {
    let (addr, _) = router(|req| {
        if text(req).starts_with("GET /a ") {
            redirect(302, "/b")
        } else {
            redirect(302, "/a")
        }
    })
    .await;
    let chain = engine(&["127.0.0.1"])
        .send_following(
            &target(addr),
            b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n",
            &SendOptions::default(),
            20,
        )
        .await
        .unwrap();
    assert!(chain.len() <= 4, "{}", chain.len());
    assert!(chain.last().unwrap().error.as_deref().unwrap().contains("loop"));
}

#[tokio::test]
async fn a_redirect_out_of_scope_is_not_followed_and_credentials_do_not_cross_origins() {
    // Out of scope: only 127.0.0.1 is included, the redirect goes to a name that is not.
    let (addr, _) = router(|_| redirect(302, "http://elsewhere.test/")).await;
    let chain = engine(&["127.0.0.1"])
        .send_following(
            &target(addr),
            b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            &SendOptions::default(),
            5,
        )
        .await
        .unwrap();
    assert_eq!(chain.len(), 1);
    let err = chain[0].error.as_deref().unwrap();
    assert!(
        err.contains("not followed") && err.contains("out of scope"),
        "{err}"
    );

    // In scope on both hosts: the cookie stays on the first and does not go to the second.
    let (addr2, seen2) = router(|_| DONE.to_vec()).await;
    let to = format!("http://localhost:{}/landing", addr2.port());
    let (addr1, _) = router(move |_| redirect(302, &to)).await;
    let chain = engine(&["127.0.0.1", "localhost"])
        .send_following(
            &target(addr1),
            b"GET / HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\nAuthorization: x\r\nX-Other: 1\r\n\r\n",
            &SendOptions::default(),
            5,
        )
        .await
        .unwrap();
    assert_eq!(chain.len(), 2, "{:?}", chain.last().unwrap().error);
    let second = text(&seen2.lock().unwrap()[0]);
    assert!(
        second.contains("X-Other: 1") && !second.contains("Cookie") && !second.contains("Authorization"),
        "{second:?}"
    );
}

#[derive(Debug)]
struct Fixed;
impl Resolver for Fixed {
    fn resolve(&self, _: &str, _: u16) -> std::io::Result<Vec<std::net::IpAddr>> {
        Ok(vec!["127.0.0.1".parse().unwrap()])
    }
}

#[tokio::test]
async fn an_upstream_proxy_is_used_and_is_told_the_pinned_address_not_the_name() {
    let (dest, _) = router(|_| DONE.to_vec()).await;
    // A CONNECT proxy that records the request line and then relays.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = l.local_addr().unwrap();
    let connects: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = connects.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = l.accept().await else { return };
            let log = log.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if c.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let line = text(&head).lines().next().unwrap_or("").to_string();
                let authority = line.split(' ').nth(1).unwrap_or("").to_string();
                log.lock().unwrap().push(line);
                let Ok(mut up) = tokio::net::TcpStream::connect(&authority).await else {
                    return;
                };
                let _ = c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
            });
        }
    });
    let connector = bosun_proxy::upstream::Connector::new(
        Some(&UpstreamProxy::Http {
            addr: proxy_addr.to_string(),
            username: None,
            password: None,
            password_file: None,
        }),
        false,
        false,
        LoopGuard::default(),
        vec![],
    )
    .unwrap();
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
        Gate::with_resolver(scope, Box::new(Fixed)),
        MemoryBudget::new(1 << 20),
    )
    .with_connector(connector);
    let ex = e
        .send(
            &Target::new(Scheme::Http, "app.test", dest.port()),
            b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
            &SendOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(ex.response, DONE);
    assert_eq!(ex.peer, dest, "the peer is the pinned address, not the proxy");
    assert_eq!(
        connects.lock().unwrap().as_slice(),
        [format!("CONNECT {dest} HTTP/1.1")]
    );
}

#[tokio::test]
async fn a_request_pointed_at_our_own_listener_is_refused_by_the_loop_guard() {
    let guard = LoopGuard::default();
    let own: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let connector = bosun_proxy::upstream::Connector::new(None, false, false, guard, vec![own]).unwrap();
    let e = engine(&["127.0.0.1"]).with_connector(connector);
    let r = e
        .send(
            &Target::new(Scheme::Http, "127.0.0.1", 1),
            b"GET / HTTP/1.1\r\n\r\n",
            &SendOptions::default(),
        )
        .await;
    assert!(matches!(r, Err(SendError::Connect(..))), "{r:?}");
}
