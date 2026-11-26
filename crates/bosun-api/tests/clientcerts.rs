#![allow(clippy::unwrap_used)]
//! Client certificates: stored sealed, listed without the key, admin-only, audited, and presented to a target
//! that requires mutual TLS by the Repeater and by the proxy's upstream connector.
mod common;

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::stack;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use reqwest::StatusCode;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Pki {
    client_pem: String,
    key_pem: String,
    port: u16,
}

/// A TLS server that demands a certificate from our test CA and answers `mtls-ok` to those that have one.
async fn mtls_server() -> Pki {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let ca_key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, "test ca");
    let ca = p.self_signed(&ca_key).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let mut cp = CertificateParams::new(vec![]).unwrap();
    cp.distinguished_name.push(DnType::CommonName, "bosun test client");
    let client = cp.signed_by(&client_key, &rcgen::Issuer::new(p, ca_key)).unwrap();
    let server = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(roots.into(), provider.clone())
        .build()
        .unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(server.cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.signing_key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else { return };
            let a = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut s) = a.accept(tcp).await else { return };
                let mut buf = vec![0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nmtls-ok")
                    .await;
                let _ = s.shutdown().await;
            });
        }
    });
    Pki {
        client_pem: client.pem(),
        key_pem: client_key.serialize_pem(),
        port,
    }
}

#[tokio::test]
async fn a_client_certificate_is_sealed_listed_without_its_key_and_presented_by_host() {
    let s = stack(true).await;
    let (c, csrf) = s.admin().await;
    let pki = mtls_server().await;
    let put = |p: &'static str, b: Value| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url(p));
        async move { c.put(url).header("x-csrf-token", csrf).json(&b).send().await.unwrap() }
    };
    let r = put(
        "/scope",
        json!({ "include": [{ "host": "127.0.0.1", "allow_private": true }] }),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let send = || {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url("/repeater/send"));
        let port = pki.port;
        async move {
            let v: Value = c
                .post(url)
                .header("x-csrf-token", csrf)
                .json(&json!({
                    "scheme": "https", "host": "127.0.0.1", "port": port,
                    "request": B64.encode(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
                    "count": 1, "mode": "sequential",
                }))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            v["results"][0].clone()
        }
    };

    // Without a certificate the server hangs up.
    let r = send().await;
    assert!(r["status"].is_null(), "{r}");

    // Bad input is a 400; a certificate whose key does not belong to it too.
    let add = |b: Value| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url("/client-certs"));
        async move { c.post(url).header("x-csrf-token", csrf).json(&b).send().await.unwrap() }
    };
    assert_eq!(add(json!({ "host": "bad host", "pem": "x" })).await.status(), 400);
    assert_eq!(add(json!({ "host": "127.0.0.1" })).await.status(), 400);
    assert_eq!(add(json!({ "host": "127.0.0.1", "pem": "junk" })).await.status(), 400);
    let other = KeyPair::generate().unwrap().serialize_pem();
    let mismatched = format!("{}{other}", pki.client_pem);
    assert_eq!(add(json!({ "host": "127.0.0.1", "pem": mismatched })).await.status(), 400);

    // A certificate for another host is not presented here.
    let pem = format!("{}{}", pki.client_pem, pki.key_pem);
    let r = add(json!({ "host": "other.example", "pem": pem })).await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let other_id = r.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    assert!(send().await["status"].is_null());

    // For this host it is.
    let r = add(json!({ "host": "127.0.0.1", "pem": pem })).await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let created: Value = r.json().await.unwrap();
    assert!(created["subject"].as_str().unwrap().contains("bosun test client"));
    assert_eq!(add(json!({ "host": "127.0.0.1", "pem": pem })).await.status(), 409);
    assert_eq!(send().await["status"], 200);

    // The list has metadata and no key material, and the stored key is sealed.
    let text = c.get(s.url("/client-certs")).send().await.unwrap().text().await.unwrap();
    assert!(!text.contains("PRIVATE") && !text.contains("sealed") && text.contains("127.0.0.1"), "{text}");
    let key_der = KeyPair::from_pem(&pki.key_pem).unwrap().serialize_der();
    let rows = s.project.client_cert_rows().unwrap();
    assert!(
        rows.iter()
            .all(|r| !r.sealed_key.windows(key_der.len()).any(|w| w == &key_der[..]))
    );

    // Through the proxy's upstream connector too (the proxy reaches the server without verifying it).
    let via = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{}", s.proxy)).unwrap())
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let r = via.get(format!("https://127.0.0.1:{}/", pki.port)).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "mtls-ok");

    // Removing it stops it; removing one that is gone is a 404.
    let id = created["id"].as_i64().unwrap();
    let del = |id: i64| {
        let (c, csrf, url) = (c.clone(), csrf.clone(), s.url(&format!("/client-certs/{id}")));
        async move { c.delete(url).header("x-csrf-token", csrf).send().await.unwrap().status() }
    };
    assert_eq!(del(id).await, StatusCode::NO_CONTENT);
    assert_eq!(del(id).await, StatusCode::NOT_FOUND);
    assert!(send().await["status"].is_null());
    assert_eq!(del(other_id).await, StatusCode::NO_CONTENT);

    let audit: Value = c.get(s.url("/audit")).send().await.unwrap().json().await.unwrap();
    let a = audit.to_string();
    assert!(a.contains("clientcert.add") && a.contains("clientcert.remove"), "{a}");
}
