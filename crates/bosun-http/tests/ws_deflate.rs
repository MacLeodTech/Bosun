#![allow(clippy::unwrap_used)]
use std::time::Duration;

use bosun_http::ws::WsRecorder;
use bosun_http::{Engine, SendOptions};
use bosun_model::{Direction, Scheme, Target};
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, RuleSpec, Scope, ScopeSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const HANDSHAKE: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";

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

/// Answers `101` (with or without the extension), then sends one frame holding `body` deflated.
async fn server(extension: bool) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut b = [0u8; 1024];
        let _ = s.read(&mut b).await;
        let mut c = flate2::Compress::new(flate2::Compression::default(), false);
        let mut z = Vec::with_capacity(256);
        c.compress_vec(b"hello hello hello", &mut z, flate2::FlushCompress::Sync)
            .unwrap();
        z.truncate(z.len() - 4);
        let ext = if extension {
            "sec-websocket-extensions: permessage-deflate\r\n"
        } else {
            ""
        };
        let mut out = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n{ext}\r\n"
        )
        .into_bytes();
        out.extend([0xC1, z.len() as u8]);
        out.extend(&z);
        s.write_all(&out).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    addr
}

async fn first(addr: std::net::SocketAddr) -> (bosun_http::ws::Frame, WsRecorder) {
    let t = Target::new(Scheme::Http, "127.0.0.1", addr.port());
    let mut ws = engine()
        .connect_ws(&t, HANDSHAKE, &SendOptions::default())
        .await
        .unwrap();
    let rec = WsRecorder::new(7, ws.handshake());
    let f = ws.recv(Duration::from_secs(2)).await.unwrap().unwrap();
    (f, rec)
}

#[tokio::test]
async fn deflated_messages_are_recorded_inflated() {
    let (f, mut rec) = first(server(true).await).await;
    assert_eq!(f.rsv, 0b100);
    assert_ne!(f.payload, b"hello hello hello", "the frame itself stays compressed");
    let m = rec.message(Direction::ServerToClient, &f, 1 << 20).unwrap();
    assert_eq!(m.flow_id, 7);
    assert_eq!(m.opcode, 1);
    assert_eq!(m.payload, b"hello hello hello");
    assert!(!m.truncated);
}

#[tokio::test]
async fn without_the_extension_nothing_is_inflated() {
    let (f, mut rec) = first(server(false).await).await;
    let m = rec.message(Direction::ServerToClient, &f, 1 << 20).unwrap();
    assert_eq!(m.payload, f.payload);
}
