#![allow(clippy::unwrap_used)]
use std::sync::{Arc, Mutex};

use bosun_http::{Engine, SendOptions};
use bosun_model::{Scheme, Target};
use bosun_proxy::budget::MemoryBudget;
use bosun_proxy::upstream::{Connector, LoopGuard};
use bosun_scope::{Gate, RuleSpec, Scope, ScopeSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn the_engine_sends_the_sni_override() {
    let cert = rcgen::generate_simple_self_signed(vec!["front.example.net".to_string()]).unwrap();
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
    let names = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
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
                if let Ok(mut tls) = start.into_stream(cfg).await {
                    let mut b = [0u8; 1024];
                    let _ = tls.read(&mut b).await;
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    let scope = Scope::compile(ScopeSpec {
        include: vec![RuleSpec {
            host: "localhost".into(),
            allow_private: true,
            ..Default::default()
        }],
        exclude: vec![],
    })
    .unwrap();
    let mut sni = std::collections::BTreeMap::new();
    sni.insert("LOCALHOST".to_string(), "front.example.net".to_string());
    let connector = Connector::new(None, true, false, LoopGuard::default(), Vec::new())
        .unwrap()
        .with_sni_overrides(&sni);
    let e = Engine::new(Gate::new(scope), MemoryBudget::new(8 << 20)).with_connector(connector);
    let opts = SendOptions {
        verify_tls: false,
        ..Default::default()
    };
    let t = Target::new(Scheme::Https, "localhost", addr.port());
    let ex = e
        .send(&t, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", &opts)
        .await
        .unwrap();
    assert_eq!(ex.status, Some(200), "{:?}", ex.error);
    assert_eq!(names.lock().unwrap()[0].as_deref(), Some("front.example.net"));
}
