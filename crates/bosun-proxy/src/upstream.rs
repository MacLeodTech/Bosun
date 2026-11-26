//! Connections to targets: direct, or through an upstream HTTP/SOCKS5 proxy, with TLS.
//!
//! Every outbound connection's local address is registered with the [`LoopGuard`] while it is open. When a
//! connection arrives at our own listeners from one of those addresses, it is our own traffic coming back (the
//! user pointed a request at the proxy or the API through the proxy), and it is refused. This catches loops on
//! every interface, which comparing host names to our listen address cannot.

use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::proxy::{SocksV5, Tunnel};
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::UpstreamProxy;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Local addresses of our open outbound connections.
#[derive(Debug, Clone, Default)]
pub struct LoopGuard {
    inner: Arc<Mutex<HashSet<SocketAddr>>>,
    /// Our own listeners (the proxy's and the API's): never valid targets. Shared by every connector.
    selfs: Arc<Mutex<Vec<SocketAddr>>>,
}

impl LoopGuard {
    /// Register our own listener addresses.
    pub fn add_self(&self, addrs: impl IntoIterator<Item = SocketAddr>) {
        let mut v = self.selfs.lock().unwrap_or_else(|e| e.into_inner());
        for a in addrs {
            if !v.contains(&a) {
                v.push(a);
            }
        }
    }

    /// Is `a` one of our own registered listener addresses?
    pub fn is_self(&self, a: &SocketAddr) -> bool {
        self.selfs.lock().unwrap_or_else(|e| e.into_inner()).contains(a)
    }

    pub fn remove_self(&self, a: &SocketAddr) {
        self.selfs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|x| x != a);
    }

    fn add(&self, a: SocketAddr) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).insert(a);
    }

    fn remove(&self, a: &SocketAddr) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).remove(a);
    }

    /// Is `peer` (the remote address of an incoming connection) one of our own outbound connections?
    pub fn is_own(&self, peer: &SocketAddr) -> bool {
        let set = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        set.contains(peer) || {
            // A v4 connection may be reported as a v4-mapped v6 address on dual-stack listeners.
            let canon = SocketAddr::new(peer.ip().to_canonical(), peer.port());
            set.contains(&canon)
        }
    }
}

/// An outbound connection: plain or TLS. Unregisters itself from the loop guard when dropped.
pub struct Conn {
    io: ConnIo,
    h2: bool,
    reg: Registration,
}

/// Keeps a local address registered with the loop guard for as long as it lives.
pub struct Registration {
    local: Option<SocketAddr>,
    guard: LoopGuard,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(a) = self.local {
            self.guard.remove(&a);
        }
    }
}

enum ConnIo {
    Plain(TokioIo<TcpStream>),
    Tls(Box<TokioIo<tokio_rustls::client::TlsStream<TcpStream>>>),
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("h2", &self.h2)
            .field("local", &self.reg.local)
            .finish_non_exhaustive()
    }
}

impl Connection for Conn {
    fn connected(&self) -> Connected {
        let c = Connected::new();
        if self.h2 { c.negotiated_h2() } else { c }
    }
}

impl Read for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().io {
            ConnIo::Plain(s) => Pin::new(s).poll_read(cx, buf),
            ConnIo::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl Write for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match &mut self.get_mut().io {
            ConnIo::Plain(s) => Pin::new(s).poll_write(cx, buf),
            ConnIo::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().io {
            ConnIo::Plain(s) => Pin::new(s).poll_flush(cx),
            ConnIo::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().io {
            ConnIo::Plain(s) => Pin::new(s).poll_shutdown(cx),
            ConnIo::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[derive(Clone)]
enum Route {
    Direct(HttpConnector),
    Http(Tunnel<HttpConnector>),
    Socks(SocksV5<HttpConnector>),
}

/// The hyper connector used by the proxy's upstream client.
#[derive(Clone)]
pub struct Connector {
    route: Route,
    cfg: Arc<ClientConfig>,
    certs: crate::clientcert::ClientCerts,
    guard: LoopGuard,
    /// Lower-cased target host -> server name to send instead.
    sni: Arc<std::collections::BTreeMap<String, String>>,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector").finish_non_exhaustive()
    }
}

impl Connector {
    pub fn new(
        upstream: Option<&UpstreamProxy>,
        verify_tls: bool,
        alpn_h2: bool,
        guard: LoopGuard,
        self_addrs: Vec<SocketAddr>,
    ) -> Result<Self, String> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        http.set_connect_timeout(Some(Duration::from_secs(15)));
        let route = match upstream {
            None => Route::Direct(http),
            Some(UpstreamProxy::Http {
                addr,
                username,
                password,
                ..
            }) => {
                let uri: Uri = format!("http://{addr}")
                    .parse()
                    .map_err(|e| format!("upstream proxy: {e}"))?;
                let mut t = Tunnel::new(uri, http);
                if let Some(u) = username {
                    use base64::Engine;
                    let token = base64::engine::general_purpose::STANDARD
                        .encode(format!("{u}:{}", password.as_deref().unwrap_or("")));
                    let v =
                        http::HeaderValue::from_str(&format!("Basic {token}")).map_err(|e| e.to_string())?;
                    t = t.with_auth(v);
                }
                Route::Http(t)
            }
            Some(UpstreamProxy::Socks5 {
                addr,
                username,
                password,
                local_dns,
                ..
            }) => {
                let uri: Uri = format!("socks5://{addr}")
                    .parse()
                    .map_err(|e| format!("upstream proxy: {e}"))?;
                let mut s = SocksV5::new(uri, http).local_dns(*local_dns);
                if let Some(u) = username {
                    s = s.with_auth(u.clone(), password.clone().unwrap_or_default());
                }
                Route::Socks(s)
            }
        };
        guard.add_self(self_addrs);
        Ok(Self {
            route,
            cfg: Arc::new(client_tls(verify_tls, alpn_h2)),
            certs: crate::clientcert::ClientCerts::default(),
            guard,
            sni: Arc::default(),
        })
    }

    /// Present client certificates from this shared registry to the hosts they are configured for.
    #[must_use]
    pub fn with_client_certs(mut self, certs: crate::clientcert::ClientCerts) -> Self {
        self.certs = certs;
        self
    }

    pub fn client_certs(&self) -> &crate::clientcert::ClientCerts {
        &self.certs
    }

    /// Send a different TLS server name (SNI) to some targets: `host -> name`, hosts matched exactly and
    /// case-insensitively. The certificate is verified against the name sent, when verification is on.
    #[must_use]
    pub fn with_sni_overrides(mut self, map: &std::collections::BTreeMap<String, String>) -> Self {
        self.sni = Arc::new(map.iter().map(|(h, n)| (h.to_ascii_lowercase(), n.clone())).collect());
        self
    }

    /// The TLS server name to send for `host`: the override if one is set, else the host itself.
    pub fn sni_for(&self, host: &str) -> String {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        self.sni.get(&bare.to_ascii_lowercase()).cloned().unwrap_or_else(|| bare.to_string())
    }

    /// Open a TCP connection to `host:port` the way every outbound connection is opened: the self-target check,
    /// then the configured upstream (direct, HTTP CONNECT or SOCKS5), with the local address registered with the
    /// loop guard for as long as the returned [`Registration`] lives. No TLS.
    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<(TcpStream, Registration), BoxError> {
        if self.targets_self(host, port) {
            return Err(Box::new(SelfTarget(format!("{host}:{port}"))) as BoxError);
        }
        // The tunnel and SOCKS connectors expect the target scheme; HttpConnector needs http(s) only for the
        // default port, which we have already resolved.
        let tcp_uri: Uri = format!("http://{}:{port}", bracket(host)).parse()?;
        let io = match self.route.clone() {
            Route::Direct(mut c) => tower_service::Service::call(&mut c, tcp_uri).await?,
            Route::Http(mut c) => tower_service::Service::call(&mut c, tcp_uri).await?,
            Route::Socks(mut c) => tower_service::Service::call(&mut c, tcp_uri).await?,
        };
        let tcp = io.into_inner();
        let local = tcp.local_addr().ok();
        if let Some(a) = local {
            self.guard.add(a);
        }
        Ok((
            tcp,
            Registration {
                local,
                guard: self.guard.clone(),
            },
        ))
    }

    /// Cheap pre-check for obvious loops: a loopback/unspecified target on one of our own ports.
    fn targets_self(&self, host: &str, port: u16) -> bool {
        let selfs = self.guard.selfs.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let local_name =
            host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost");
        let local_ip = host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified());
        (local_name || local_ip)
            && selfs
                .iter()
                .any(|a| a.port() == port && (a.ip().is_loopback() || a.ip().is_unspecified()))
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| selfs.iter().any(|a| a.ip() == ip && a.port() == port))
    }
}

/// Our own listeners and the proxy itself are not valid targets.
#[derive(Debug, thiserror::Error)]
#[error("refusing to connect to Bosun's own listener {0}")]
pub struct SelfTarget(pub String);

impl tower_service::Service<Uri> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Conn, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let https = dst.scheme_str() == Some("https");
            let host = dst.host().ok_or("missing host")?.to_string();
            let port = dst.port_u16().unwrap_or(if https { 443 } else { 80 });
            let (tcp, reg) = this.connect_tcp(&host, port).await?;
            let conn = if https {
                let bare = host.trim_start_matches('[').trim_end_matches(']').to_string();
                let sni = this.sni.get(&bare.to_ascii_lowercase()).cloned().unwrap_or_else(|| bare.clone());
                let name = ServerName::try_from(sni)?;
                let cfg = this.certs.apply(&bare, this.cfg.clone());
                let tls = TlsConnector::from(cfg).connect(name, tcp).await?;
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                Conn {
                    io: ConnIo::Tls(Box::new(TokioIo::new(tls))),
                    h2,
                    reg,
                }
            } else {
                Conn {
                    io: ConnIo::Plain(TokioIo::new(tcp)),
                    h2: false,
                    reg,
                }
            };
            Ok(conn)
        })
    }
}

fn bracket(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn client_tls(verify: bool, alpn_h2: bool) -> ClientConfig {
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
    cfg.alpn_protocols = if alpn_h2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    cfg
}

/// Accepts any certificate chain, but still checks the handshake signature with the presented key, so the
/// connection is at least bound to the certificate the server showed.
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
