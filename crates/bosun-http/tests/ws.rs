#![allow(clippy::unwrap_used)]
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bosun_http::ws::{Frame, parse_frame, to_ws_message};
use bosun_http::{Engine, SendError, SendOptions};
use bosun_model::{Direction, Scheme, Target};
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, RuleSpec, Scope, ScopeSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const HANDSHAKE: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const SWITCH: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n";

/// Accepts the upgrade, sends `after_head` right behind the 101 (in the same write), then records every byte the
/// client sends and echoes each parsed frame back as an unmasked frame.
async fn ws_server(after_head: Vec<u8>) -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let Ok((mut s, _)) = l.accept().await else { return };
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if s.read(&mut b).await.unwrap_or(0) == 0 {
                return;
            }
            head.push(b[0]);
        }
        let mut first = SWITCH.to_vec();
        first.extend_from_slice(&after_head);
        let _ = s.write_all(&first).await;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = s.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            log.lock().unwrap().extend_from_slice(&chunk[..n]);
            buf.extend_from_slice(&chunk[..n]);
            while let Ok(Some((f, used))) = parse_frame(&buf, 1 << 20) {
                buf.drain(..used);
                let echo = Frame { mask: None, ..f };
                let _ = s.write_all(&echo.encode()).await;
            }
        }
    });
    (addr, seen)
}

fn engine() -> Engine {
    let scope = Scope::compile(ScopeSpec {
        include: vec![RuleSpec {
            host: "127.0.0.1".into(),
            allow_private: true,
            ..Default::default()
        }],
        exclude: vec![],
    })
    .unwrap();
    Engine::new(Gate::new(scope), MemoryBudget::new(8 << 20))
}

fn target(a: SocketAddr) -> Target {
    Target::new(Scheme::Http, "127.0.0.1", a.port())
}

#[tokio::test]
async fn frames_go_out_as_described_and_come_back_one_by_one() {
    let (addr, seen) = ws_server(Vec::new()).await;
    let mut ws = engine()
        .connect_ws(&target(addr), HANDSHAKE, &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(ws.handshake().status, Some(101));
    // A text frame with a chosen mask key, then one with reserved bits, a reserved opcode and no mask at all.
    let a = Frame {
        mask: Some([9, 8, 7, 6]),
        ..Frame::text("hello")
    };
    let b = Frame {
        fin: false,
        rsv: 0b101,
        opcode: 0xb,
        mask: None,
        payload: b"odd".to_vec(),
    };
    ws.send(&a).await.unwrap();
    ws.send(&b).await.unwrap();
    let got_a = ws.recv(Duration::from_secs(2)).await.unwrap().unwrap();
    let got_b = ws.recv(Duration::from_secs(2)).await.unwrap().unwrap();
    assert_eq!((got_a.opcode, got_a.payload.as_slice()), (1, &b"hello"[..]));
    assert_eq!((got_b.fin, got_b.rsv, got_b.opcode), (false, 0b101, 0xb));
    let mut expected = a.encode();
    expected.extend(b.encode());
    assert_eq!(
        *seen.lock().unwrap(),
        expected,
        "the server saw exactly the bytes described"
    );
    // Nothing more is coming.
    assert_eq!(ws.recv(Duration::from_millis(100)).await.unwrap(), None);
}

#[tokio::test]
async fn raw_bytes_can_be_sent_for_frames_a_frame_cannot_describe() {
    let (addr, seen) = ws_server(Vec::new()).await;
    let mut ws = engine()
        .connect_ws(&target(addr), HANDSHAKE, &SendOptions::default())
        .await
        .unwrap();
    // Length 5 written in the 16-bit form (legal to parse, not what a compliant client writes), unmasked.
    let odd = [0x81, 126, 0, 5, b'h', b'e', b'l', b'l', b'o'];
    ws.send_raw(&odd).await.unwrap();
    let echo = ws.recv(Duration::from_secs(2)).await.unwrap().unwrap();
    assert_eq!(echo.payload, b"hello");
    assert_eq!(*seen.lock().unwrap(), odd);
}

#[tokio::test]
async fn bytes_that_follow_the_101_in_the_same_packet_are_not_lost() {
    let early = Frame {
        mask: None,
        ..Frame::text("welcome")
    };
    let (addr, _) = ws_server(early.encode()).await;
    let mut ws = engine()
        .connect_ws(&target(addr), HANDSHAKE, &SendOptions::default())
        .await
        .unwrap();
    let f = ws.recv(Duration::from_secs(2)).await.unwrap().unwrap();
    assert_eq!(f.payload, b"welcome");
    // And the frame turns into a stored message for the handshake's flow.
    let m = to_ws_message(7, Direction::ServerToClient, &f, 4);
    assert_eq!(
        (m.flow_id, m.opcode, m.payload.as_slice(), m.truncated),
        (7, 1, &b"welc"[..], true)
    );
}

#[tokio::test]
async fn a_server_that_does_not_switch_is_reported_with_its_answer() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut s, _)) = l.accept().await else { return };
        let mut buf = [0u8; 2048];
        let _ = s.read(&mut buf).await;
        let _ = s
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await;
    });
    let r = engine()
        .connect_ws(&target(addr), HANDSHAKE, &SendOptions::default())
        .await;
    match r {
        Err(SendError::NotUpgraded(ex)) => assert_eq!(ex.status, Some(400)),
        other => panic!("{other:?}"),
    }
}
