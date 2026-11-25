//! Client TLS for the raw engine: HTTP/1.1 only, with certificate checking switchable.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use crate::TlsInfo;

/// The four client configurations (checking on or off, HTTP/1.1 or HTTP/2 offered), built once.
#[derive(Debug)]
pub struct Configs([Arc<ClientConfig>; 4]);

impl Configs {
    pub fn new() -> Self {
        Self([
            Arc::new(client_config(false, false)),
            Arc::new(client_config(true, false)),
            Arc::new(client_config(false, true)),
            Arc::new(client_config(true, true)),
        ])
    }

    pub fn get(&self, verify: bool, h2: bool) -> Arc<ClientConfig> {
        self.0[usize::from(verify) + 2 * usize::from(h2)].clone()
    }
}

fn client_config(verify: bool, h2: bool) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| panic!("rustls defaults: {e}"));
    let mut cfg = if verify {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
            .with_no_client_auth()
    };
    cfg.alpn_protocols = if h2 {
        vec![b"h2".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    cfg
}

pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_string()).map_err(|e| e.to_string())
}

pub fn info(conn: &rustls::ClientConnection) -> TlsInfo {
    TlsInfo {
        version: conn
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_default(),
        cipher: conn
            .negotiated_cipher_suite()
            .map(|c| format!("{:?}", c.suite()))
            .unwrap_or_default(),
        alpn: conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
        leaf_der: conn
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.as_ref().to_vec()),
    }
}

/// Accepts any chain but still checks the handshake signature against the presented key.
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
