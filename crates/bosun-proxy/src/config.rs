use std::net::SocketAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Upstream proxy to chain through (corporate proxy, Tor, another tool).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UpstreamProxy {
    /// An HTTP proxy, used with CONNECT for every target.
    Http {
        addr: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default, skip_serializing)]
        password: Option<String>,
    },
    Socks5 {
        addr: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default, skip_serializing)]
        password: Option<String>,
        /// Resolve names locally instead of at the SOCKS server.
        #[serde(default)]
        local_dns: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Listener address. Loopback by default; anything else requires `auth` or `allow_clients`.
    pub listen: SocketAddr,
    /// Basic credentials clients must send as `Proxy-Authorization`.
    pub auth: Option<ProxyAuth>,
    /// Only these client networks may use the proxy (empty: anyone who can reach the listener).
    pub allow_clients: Vec<IpNet>,
    pub upstream: Option<UpstreamProxy>,
    /// Verify target certificates. Off by default, like other interception tools: test targets often use
    /// self-signed certificates, and the tool must reach them. Turn it on when the network between you and
    /// the target is not trusted.
    pub verify_upstream_tls: bool,
    /// Offer HTTP/2 to clients (browsers) over ALPN.
    pub http2: bool,
    /// Requests whose body is larger than this are refused with 413.
    pub max_request_body: usize,
    /// Responses are streamed to the client; only this much of each body is recorded.
    pub record_body_limit: usize,
    /// When a response must be buffered (response intercept, body rules), bodies larger than this fail.
    pub max_buffered_response: usize,
    /// Hosts whose TLS is tunnelled untouched (certificate-pinned apps, banking, OS update services).
    /// Same pattern syntax as scope host rules.
    pub tls_passthrough: Vec<String>,
    /// Accept origin-form requests (`GET /path` with a Host header) as if they were proxied: for clients
    /// that cannot be configured to use a proxy and are redirected to the listener instead.
    pub invisible: bool,
    /// Record traffic to hosts that are out of scope.
    pub record_out_of_scope: bool,
    /// Seconds to wait for an upstream response head.
    pub upstream_timeout_secs: u64,
    /// Most client connections at once (each tunnelled request also holds an upstream socket, so keep this
    /// well under half the process's open-file limit). Further connections are closed immediately.
    pub max_connections: usize,
    /// Bytes all buffered traffic may use at once (bodies being read, responses held for editing, history
    /// waiting to be written). Default: half the container's memory limit when there is one, else 1 GiB.
    /// Past it, requests get 503 and recorded bodies are dropped.
    pub memory_budget_mib: Option<usize>,
    /// Most messages held in the intercept queue; further ones are refused with 503.
    pub max_intercept_items: usize,
    /// Most bytes held in the intercept queue.
    pub max_intercept_bytes: usize,
    /// Seconds a client may take to send a request's headers (also bounds idle keep-alive connections).
    pub header_timeout_secs: u64,
    /// Our own API listener(s), refused as proxy targets.
    #[serde(skip)]
    pub self_addrs: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            auth: None,
            allow_clients: Vec::new(),
            upstream: None,
            verify_upstream_tls: false,
            http2: true,
            max_request_body: 64 * 1024 * 1024,
            record_body_limit: 16 * 1024 * 1024,
            max_buffered_response: 64 * 1024 * 1024,
            tls_passthrough: Vec::new(),
            invisible: false,
            record_out_of_scope: true,
            upstream_timeout_secs: 120,
            max_connections: 1024,
            header_timeout_secs: 30,
            memory_budget_mib: None,
            max_intercept_items: 256,
            max_intercept_bytes: 128 * 1024 * 1024,
            self_addrs: Vec::new(),
        }
    }
}

impl ProxyConfig {
    /// Refuse configurations that would make an open proxy.
    pub fn validate(&self) -> Result<(), String> {
        if !self.listen.ip().is_loopback() && self.auth.is_none() && self.allow_clients.is_empty() {
            return Err(format!(
                "the proxy listener {} is not on loopback: set proxy credentials (proxy.auth) or a client \
                 allowlist (proxy.allow_clients) so it cannot be used as an open proxy",
                self.listen
            ));
        }
        if let Some(a) = &self.auth
            && (a.username.is_empty() || a.password.len() < 12)
        {
            return Err("proxy.auth needs a username and a password of at least 12 characters".into());
        }
        Ok(())
    }
}
