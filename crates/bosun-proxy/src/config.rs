use std::net::SocketAddr;
use std::path::{Path, PathBuf};

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
        /// File holding the password (container secrets); read at start-up, and instead of `password`.
        #[serde(default)]
        password_file: Option<PathBuf>,
    },
    Socks5 {
        addr: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default, skip_serializing)]
        password: Option<String>,
        /// File holding the password (container secrets); read at start-up, and instead of `password`.
        #[serde(default)]
        password_file: Option<PathBuf>,
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
    /// Host name to send as the TLS server name (SNI) to that target instead of its own name, keyed by target
    /// host (exact, case-insensitive). With `verify_upstream_tls` the certificate is checked against the
    /// override. The `Host` header is not changed.
    pub upstream_sni: std::collections::BTreeMap<String, String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProxyAuth {
    pub username: String,
    #[serde(default, skip_serializing)]
    pub password: String,
    /// File holding the password (container secrets); read at start-up, and instead of `password`.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub password_file: Option<PathBuf>,
}

/// Read a secret from a file: the contents without the trailing newline.
pub fn read_secret_file(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read the secret file {}: {e}", path.display()))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_string())
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            auth: None,
            allow_clients: Vec::new(),
            upstream: None,
            verify_upstream_tls: false,
            upstream_sni: std::collections::BTreeMap::new(),
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
    /// Load every `password_file` into its `password`. Setting both a password and its file is an error.
    pub fn resolve_secrets(&mut self) -> Result<(), String> {
        if let Some(a) = &mut self.auth
            && let Some(f) = &a.password_file
        {
            if !a.password.is_empty() {
                return Err("proxy.auth: set password or password_file, not both".into());
            }
            a.password = read_secret_file(f)?;
        }
        match &mut self.upstream {
            Some(
                UpstreamProxy::Http {
                    password,
                    password_file,
                    ..
                }
                | UpstreamProxy::Socks5 {
                    password,
                    password_file,
                    ..
                },
            ) => {
                if let Some(f) = password_file {
                    if password.is_some() {
                        return Err("proxy.upstream: set password or password_file, not both".into());
                    }
                    *password = Some(read_secret_file(f)?);
                }
            }
            None => {}
        }
        Ok(())
    }

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
        for (host, sni) in &self.upstream_sni {
            if host.is_empty() || rustls::pki_types::ServerName::try_from(sni.as_str()).is_err() {
                return Err(format!(
                    "proxy.upstream_sni: \"{host}\" -> \"{sni}\" is not a host name to send as the server name"
                ));
            }
        }
        Ok(())
    }
}

/// One proxy listener and the options that belong to it. The first listener comes from the `proxy` section of the
/// config file; others are added while running. Everything here changes live (a new address means a new bind).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ListenerSpec {
    /// Address to listen on, for example `127.0.0.1:8081`. Loopback unless `auth` or `allow_clients` is set.
    #[schema(value_type = String)]
    pub addr: SocketAddr,
    /// Accept origin-form requests (`GET /path` with a Host header) as if they were proxied.
    #[serde(default)]
    pub invisible: bool,
    /// Hosts whose TLS this listener tunnels untouched (scope host pattern syntax).
    #[serde(default)]
    pub tls_passthrough: Vec<String>,
    /// Basic credentials clients must send as `Proxy-Authorization`. The password is never returned.
    #[serde(default)]
    pub auth: Option<ProxyAuth>,
    /// Only these client networks may use this listener (empty: anyone who can reach it).
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub allow_clients: Vec<IpNet>,
}

impl ListenerSpec {
    pub fn validate(&self) -> Result<(), String> {
        if !self.addr.ip().is_loopback() && self.auth.is_none() && self.allow_clients.is_empty() {
            return Err(format!(
                "the proxy listener {} is not on loopback: set credentials (auth) or a client allowlist \
                 (allow_clients) so it cannot be used as an open proxy",
                self.addr
            ));
        }
        if let Some(a) = &self.auth
            && (a.username.is_empty() || a.password.len() < 12)
        {
            return Err("auth needs a username and a password of at least 12 characters".into());
        }
        if self.tls_passthrough.len() > 1000 || self.allow_clients.len() > 1000 {
            return Err("too many pass-through hosts or client networks".into());
        }
        Ok(())
    }
}

impl ProxyConfig {
    /// The listener the `proxy` section describes.
    pub fn listener_spec(&self) -> ListenerSpec {
        ListenerSpec {
            addr: self.listen,
            invisible: self.invisible,
            tls_passthrough: self.tls_passthrough.clone(),
            auth: self.auth.clone(),
            allow_clients: self.allow_clients.clone(),
        }
    }
}

/// Settings that change while running, without a restart. Everything else in the `proxy` section needs one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveSettings {
    /// Requests whose body is larger than this are refused with 413.
    pub max_request_body: usize,
    /// Only this much of each body is recorded.
    pub record_body_limit: usize,
    /// Buffered responses (response intercept, body rules) larger than this fail.
    pub max_buffered_response: usize,
    /// Record traffic to hosts that are out of scope.
    pub record_out_of_scope: bool,
    /// Seconds to wait for an upstream response head.
    pub upstream_timeout_secs: u64,
    /// Seconds a client may take to send a request's headers (applies to new connections).
    pub header_timeout_secs: u64,
    /// Offer HTTP/2 to clients over ALPN (applies to new connections).
    pub http2: bool,
    /// Most client connections at once, summed over all listeners.
    pub max_connections: usize,
}

impl LiveSettings {
    pub fn from_config(c: &ProxyConfig) -> Self {
        Self {
            max_request_body: c.max_request_body,
            record_body_limit: c.record_body_limit,
            max_buffered_response: c.max_buffered_response,
            record_out_of_scope: c.record_out_of_scope,
            upstream_timeout_secs: c.upstream_timeout_secs,
            header_timeout_secs: c.header_timeout_secs,
            http2: c.http2,
            max_connections: c.max_connections,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_connections == 0 || self.max_connections > 1_000_000 {
            return Err("max_connections must be between 1 and 1000000".into());
        }
        if self.upstream_timeout_secs == 0 || self.header_timeout_secs == 0 {
            return Err("timeouts must be at least 1 second".into());
        }
        if self.record_body_limit == 0 || self.max_request_body == 0 || self.max_buffered_response == 0 {
            return Err("body limits must be above zero".into());
        }
        Ok(())
    }
}

/// `proxy` settings that cannot change while running. A change to one of these needs a restart.
pub const RESTART_ONLY: &[&str] = &[
    "upstream",
    "verify_upstream_tls",
    "upstream_sni",
    "memory_budget_mib",
    "max_intercept_items",
    "max_intercept_bytes",
    "listen",
];
