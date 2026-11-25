#![allow(clippy::unwrap_used)]
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bosun_http::h2::{Frame, H2Plan, H2Request, decode_plan_headers, flag, parse_frame, ty};
use bosun_http::{Engine, SendError, SendOptions};
use bosun_model::{Scheme, Target};
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, RuleSpec, Scope, ScopeSpec};
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn engine_with(rule_path: Option<&str>) -> Engine {
    let scope = Scope::compile(ScopeSpec {
        include: vec![RuleSpec {
            host: "127.0.0.1".into(),
            path: rule_path.map(str::to_string),
            allow_private: true,
            ..Default::default()
        }],
        exclude: vec![],
    })
    .unwrap();
    Engine::new(Gate::new(scope), MemoryBudget::new(64 << 20))
}

fn target(a: SocketAddr) -> Target {
    Target::new(Scheme::Http, "127.0.0.1", a.port())
}

/// A minimal HTTP/2 server written with the same frame codec: records every frame it receives and answers the
/// first request with `200` and `hi`.
async fn raw_server() -> (SocketAddr, Arc<Mutex<Vec<Frame>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<Frame>>> = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        let Ok((mut s, _)) = l.accept().await else { return };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut preface_seen = false;
        let mut answered = false;
        let _ = s.write_all(&Frame::settings(&[]).encode()).await;
        loop {
            let n = s.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
            if !preface_seen {
                if buf.len() < 24 {
                    continue;
                }
                assert_eq!(&buf[..24], bosun_http::h2::PREFACE);
                buf.drain(..24);
                preface_seen = true;
            }
            while let Ok(Some((f, used))) = parse_frame(&buf, 1 << 20) {
                buf.drain(..used);
                if f.ty == ty::SETTINGS && f.flags & flag::ACK == 0 {
                    let _ = s
                        .write_all(&Frame::new(ty::SETTINGS, flag::ACK, 0, vec![]).encode())
                        .await;
                }
                if f.ty == ty::HEADERS && !answered {
                    answered = true;
                    // 0x88 is the static-table entry for `:status: 200`.
                    let _ = s
                        .write_all(&Frame::new(ty::HEADERS, flag::END_HEADERS, f.stream, vec![0x88]).encode())
                        .await;
                    let _ = s
                        .write_all(&Frame::new(ty::DATA, flag::END_STREAM, f.stream, b"hi".to_vec()).encode())
                        .await;
                }
                log.lock().unwrap().push(f);
            }
        }
    });
    (addr, seen)
}

#[tokio::test]
async fn frames_arrive_as_written_including_things_a_client_library_refuses() {
    let (addr, seen) = raw_server().await;
    // Upper-case and duplicate header names, no :scheme, a path with odd characters, a body.
    let mut req = H2Request::new(
        "BREW",
        "http",
        "127.0.0.1",
        "/pot?a=%00",
        &[("X-Upper-Case", "Yes"), ("x-dup", "1"), ("x-dup", "2")],
    );
    req.headers.retain(|(n, _)| n != b":scheme");
    req.body = b"payload".to_vec();
    let plan = req.clone().into_plan();
    let ex = engine_with(None)
        .send_h2(&target(addr), &plan, &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(ex.status, Some(200));
    let text = String::from_utf8(ex.response.clone()).unwrap();
    assert!(
        text.starts_with("HTTP/2 200\r\n") && text.ends_with("\r\n\r\nhi"),
        "{text:?}"
    );
    assert!(ex.request.starts_with(b"BREW /pot?a=%00 HTTP/2\r\n"));
    // What the server saw, decoded the way the server would.
    let frames = seen.lock().unwrap().clone();
    let ours: Vec<Frame> = frames.iter().filter(|f| f.stream == 1).cloned().collect();
    assert_eq!(ours, plan.frames, "the plan's frames, byte for byte");
    let decoded = decode_plan_headers(&ours).unwrap();
    assert_eq!(decoded[0].1, req.headers);
    // The client acknowledged the server's SETTINGS (it may still be in flight when the response is complete).
    let mut acked = false;
    for _ in 0..50 {
        acked = seen
            .lock()
            .unwrap()
            .iter()
            .any(|f| f.ty == ty::SETTINGS && f.flags & flag::ACK != 0);
        if acked {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(acked);
    let d = ex.h2.unwrap();
    assert_eq!(d.frames_in.iter().filter(|f| f.ty == ty::DATA).count(), 1);
}

#[tokio::test]
async fn a_header_block_split_over_continuations_is_sent_as_written() {
    let (addr, seen) = raw_server().await;
    let mut req = H2Request::new("GET", "http", "127.0.0.1", "/", &[("x-long", &"v".repeat(60))]);
    req.header_chunk = Some(20);
    let mut plan = req.into_plan();
    assert!(plan.frames.iter().any(|f| f.ty == ty::CONTINUATION));
    // A frame the engine does not know about, on a stream that was never opened.
    plan.frames
        .push(Frame::new(0xee, 0xff, 0x8000_0007, vec![1, 2, 3]));
    let ex = engine_with(None)
        .send_h2(&target(addr), &plan, &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(ex.status, Some(200));
    let ours: Vec<Frame> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|f| f.stream == 1 || f.ty == 0xee)
        .cloned()
        .collect();
    assert_eq!(ours, plan.frames);
}

#[tokio::test]
async fn plans_are_checked_against_scope_before_anything_is_sent() {
    let (addr, seen) = raw_server().await;
    let e = engine_with(Some("^/ok"));
    let bad = H2Request::new("GET", "http", "127.0.0.1", "/nope", &[]).into_plan();
    let r = e.send_h2(&target(addr), &bad, &SendOptions::default()).await;
    assert!(matches!(r, Err(SendError::Refused(_))), "{r:?}");
    // A second request on another stream with a path outside scope is refused too.
    let mut two = H2Request::new("GET", "http", "127.0.0.1", "/ok", &[]).into_plan();
    two.frames
        .extend(H2Request::new("GET", "http", "127.0.0.1", "/secret", &[]).frames(3));
    let r = e.send_h2(&target(addr), &two, &SendOptions::default()).await;
    assert!(matches!(r, Err(SendError::Refused(_))), "{r:?}");
    // Header blocks that cannot be decoded cannot be checked, so they are refused.
    let garbage = H2Plan {
        frames: vec![Frame::new(
            ty::HEADERS,
            flag::END_HEADERS,
            1,
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        )],
        ..H2Plan::default()
    };
    let r = e.send_h2(&target(addr), &garbage, &SendOptions::default()).await;
    assert!(matches!(r, Err(SendError::BadRequest(_))), "{r:?}");
    assert!(seen.lock().unwrap().is_empty(), "nothing was sent");
}

/// A real HTTP/2 server (hyper) answering `/big` with 300 KB and everything else with `hello`.
async fn hyper_server(tls: Option<Arc<rustls::ServerConfig>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let tls = tls.clone();
            tokio::spawn(async move {
                let svc = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let body = if req.uri().path() == "/big" {
                        vec![b'z'; 300_000]
                    } else {
                        b"hello".to_vec()
                    };
                    Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from(body))))
                });
                let b = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                match tls {
                    Some(cfg) => {
                        let Ok(s) = tokio_rustls::TlsAcceptor::from(cfg).accept(s).await else {
                            return;
                        };
                        let _ = b.serve_connection(TokioIo::new(s), svc).await;
                    }
                    None => {
                        let _ = b.serve_connection(TokioIo::new(s), svc).await;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn a_real_server_answers_and_large_responses_are_not_stalled_by_flow_control() {
    let addr = hyper_server(None).await;
    let e = engine_with(None);
    let ok = H2Request::new("GET", "http", "127.0.0.1", "/", &[]).into_plan();
    let ex = e
        .send_h2(&target(addr), &ok, &SendOptions::default())
        .await
        .unwrap();
    assert_eq!((ex.status, ex.error), (Some(200), None));
    assert!(ex.response.ends_with(b"\r\n\r\nhello"));
    let big = H2Request::new("GET", "http", "127.0.0.1", "/big", &[]).into_plan();
    let ex = e
        .send_h2(&target(addr), &big, &SendOptions::default())
        .await
        .unwrap();
    assert_eq!((ex.status, ex.error.clone()), (Some(200), None), "{:?}", ex.error);
    assert!(ex.response.len() > 300_000 && ex.response.ends_with(b"zzzz"));
}

#[tokio::test]
async fn a_real_server_rejects_a_malformed_request_and_we_see_how() {
    let addr = hyper_server(None).await;
    // An upper-case header name is a protocol error in HTTP/2.
    let bad = H2Request::new("GET", "http", "127.0.0.1", "/", &[("Upper-Case", "x")]).into_plan();
    let ex = engine_with(None)
        .send_h2(&target(addr), &bad, &SendOptions::default())
        .await
        .unwrap();
    let d = ex.h2.unwrap();
    assert!(
        d.rst.is_some() || d.goaway.is_some(),
        "frames in: {:?}",
        d.frames_in
    );
    assert!(ex.error.is_some());
    assert_eq!(ex.status, None);
}

#[tokio::test]
async fn over_tls_h2_is_negotiated_and_a_server_without_it_is_reported() {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let mut cfg =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![ck.cert.der().clone()], key)
            .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let addr = hyper_server(Some(Arc::new(cfg.clone()))).await;
    let t = Target::new(Scheme::Https, "127.0.0.1", addr.port());
    let plan = H2Request::new("GET", "https", "127.0.0.1", "/", &[]).into_plan();
    let ex = engine_with(None)
        .send_h2(&t, &plan, &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(ex.status, Some(200));
    assert_eq!(ex.tls.unwrap().alpn.as_deref(), Some("h2"));

    // A TLS server that only speaks HTTP/1.1: the handshake offers only h2, so there is nothing to talk.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let _ = acceptor.accept(s).await;
        }
    });
    let r = engine_with(None)
        .send_h2(
            &Target::new(Scheme::Https, "127.0.0.1", port),
            &plan,
            &SendOptions::default(),
        )
        .await;
    assert!(matches!(r, Err(SendError::Tls(..))), "{r:?}");
}
