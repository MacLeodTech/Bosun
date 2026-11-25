//! Scope rules and the outbound-traffic gate.
//!
//! Scope answers "is this request part of the engagement?". The proxy uses it to label (and optionally hide or
//! not intercept) traffic. Every *active* tool (repeater, intruder, scanner, crawler, plugins) must go through
//! [`Gate::check`] before sending anything, and out-of-scope targets are refused unless the user turns that
//! protection off for a specific tool. Testing a host you are not allowed to test is the most damaging mistake a
//! DAST user can make, so the default is to refuse.
//!
//! The gate also stops a scoped *name* from being turned against the machine Bosun runs on. It resolves the name
//! itself and returns the addresses the tool must connect to ([`Pinned`]); tools never resolve again, so a DNS
//! answer that changes between the check and the connection (rebinding) gets them nowhere. Loopback, link-local
//! (which includes the cloud metadata address), unspecified and the host's own networks are refused unless an
//! include rule names that address, or sets `allow_private`.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bosun_model::{FlowSource, Scheme};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("invalid host pattern {0:?}: {1}")]
    BadHost(String, String),
    #[error("invalid path regex {0:?}: {1}")]
    BadPath(String, String),
    #[error("{0} is out of scope")]
    OutOfScope(String),
    #[error("all outbound tool traffic is stopped (kill switch)")]
    Stopped,
    #[error(
        "{host} resolves to {addr}, which is a local or internal address; add a scope rule with allow_private"
    )]
    PrivateAddress { host: String, addr: IpAddr },
    #[error("could not resolve {0}: {1}")]
    Unresolvable(String, String),
    #[error("too many requests to {0}: the per-host rate limit is {1} a second")]
    RateLimited(String, u32),
    #[error("invalid network {0:?}: expected an address and prefix such as 10.0.0.0/8")]
    BadNetwork(String),
}

/// One include or exclude rule, as the user writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
#[schema(as = ScopeRule)]
pub struct RuleSpec {
    /// `http`, `https`, or empty for both.
    #[serde(default)]
    pub scheme: Option<Scheme>,
    /// Host glob, case-insensitive. `example.com` matches that host only; `*.example.com` matches one level of
    /// sub-domain (`*` never crosses a dot), so add a rule per level you want. IP addresses work as literals.
    pub host: String,
    /// Port, or empty for any.
    #[serde(default)]
    pub port: Option<u16>,
    /// Regex matched against the path (without the query), or empty for any path.
    #[serde(default)]
    pub path: Option<String>,
    /// Let this rule reach loopback, link-local and the host's own networks. Off by default, so a public name
    /// that is made to resolve to `127.0.0.1` or `169.254.169.254` is refused.
    #[serde(default)]
    pub allow_private: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct ScopeSpec {
    #[serde(default)]
    pub include: Vec<RuleSpec>,
    #[serde(default)]
    pub exclude: Vec<RuleSpec>,
}

#[derive(Debug)]
struct Rule {
    scheme: Option<Scheme>,
    host: Regex,
    port: Option<u16>,
    path: Option<Regex>,
    allow_private: bool,
    /// The host pattern is one literal name with no `*`.
    literal: Option<String>,
}

impl Rule {
    fn compile(spec: &RuleSpec) -> Result<Self, ScopeError> {
        let host_pat = spec.host.trim().to_ascii_lowercase();
        if host_pat.is_empty() {
            return Err(ScopeError::BadHost(spec.host.clone(), "empty".into()));
        }
        if !host_pat
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.*:[]".contains(&b))
        {
            return Err(ScopeError::BadHost(
                spec.host.clone(),
                "only letters, digits, '-', '_', '.', ':' and '*' are allowed".into(),
            ));
        }
        // `*` matches within one label only, so `*.example.com` never matches `a.b.example.com`.
        let host_pat = host_pat.trim_start_matches('[').trim_end_matches(']');
        let re = format!("^{}$", regex::escape(host_pat).replace(r"\*", "[^.]*"));
        let host = Regex::new(&re).map_err(|e| ScopeError::BadHost(spec.host.clone(), e.to_string()))?;
        let path = match spec.path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
            Some(p) => Some(Regex::new(p).map_err(|e| ScopeError::BadPath(p.to_string(), e.to_string()))?),
            None => None,
        };
        let literal = (!host_pat.contains('*')).then(|| host_pat.trim_end_matches('.').to_string());
        Ok(Self {
            scheme: spec.scheme,
            host,
            port: spec.port,
            path,
            allow_private: spec.allow_private,
            literal,
        })
    }

    fn matches(&self, scheme: Scheme, host: &str, port: u16, path: &str) -> bool {
        self.scheme.is_none_or(|s| s == scheme)
            && self.port.is_none_or(|p| p == port)
            && self.host.is_match(host)
            && self.path.as_ref().is_none_or(|r| r.is_match(path))
    }
}

/// Compiled scope. An empty include list means "nothing is in scope" (not "everything"): the user has to say
/// what they are testing.
#[derive(Debug, Default)]
pub struct Scope {
    spec: ScopeSpec,
    include: Vec<Rule>,
    exclude: Vec<Rule>,
}

impl Scope {
    pub fn compile(spec: ScopeSpec) -> Result<Self, ScopeError> {
        let include = spec.include.iter().map(Rule::compile).collect::<Result<_, _>>()?;
        let exclude = spec.exclude.iter().map(Rule::compile).collect::<Result<_, _>>()?;
        Ok(Self {
            spec,
            include,
            exclude,
        })
    }

    pub fn spec(&self) -> &ScopeSpec {
        &self.spec
    }

    pub fn is_empty(&self) -> bool {
        self.include.is_empty()
    }

    /// `path` may include a query string; it is cut off before matching.
    pub fn contains(&self, scheme: Scheme, host: &str, port: u16, path: &str) -> bool {
        self.matching(scheme, host, port, path).is_some()
    }

    /// The include rules that cover this target, or `None` when it is out of scope.
    fn matching(&self, scheme: Scheme, host: &str, port: u16, path: &str) -> Option<Vec<&Rule>> {
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let path = path.split(['?', '#']).next().unwrap_or("");
        let path = if path.is_empty() { "/" } else { path };
        if self.exclude.iter().any(|r| r.matches(scheme, &host, port, path)) {
            return None;
        }
        let hits: Vec<&Rule> = self
            .include
            .iter()
            .filter(|r| r.matches(scheme, &host, port, path))
            .collect();
        (!hits.is_empty()).then_some(hits)
    }
}

/// Per-tool policy for out-of-scope targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutOfScopePolicy {
    /// Refuse to send (the default for every active tool).
    #[default]
    Refuse,
    /// Send anyway. Only for manual tools, and only when the user explicitly chose it.
    Allow,
}

/// Where the gate looks names up. Replaceable so tests (and a future DNS-over-HTTPS or pinned-hosts file) do not
/// need the network.
pub trait Resolver: Send + Sync + std::fmt::Debug {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>>;
}

/// The operating system's resolver. Blocking: call the gate from `spawn_blocking`.
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>> {
        Ok((host, port).to_socket_addrs()?.map(|a| a.ip()).collect())
    }
}

/// A network in CIDR form, for the "host's own networks" list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl Network {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, normalise(ip)) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                mask_eq(u32::from(n).into(), u32::from(i).into(), 32, self.prefix)
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => mask_eq(u128::from(n), u128::from(i), 128, self.prefix),
            _ => false,
        }
    }
}

fn mask_eq(a: u128, b: u128, bits: u32, prefix: u8) -> bool {
    let prefix = u32::from(prefix).min(bits);
    if prefix == 0 {
        return true;
    }
    let shift = bits - prefix;
    (a >> shift) == (b >> shift)
}

impl FromStr for Network {
    type Err = ScopeError;
    fn from_str(s: &str) -> Result<Self, ScopeError> {
        let bad = || ScopeError::BadNetwork(s.to_string());
        let (addr, prefix) = s.split_once('/').ok_or_else(bad)?;
        let addr: IpAddr = addr.trim().parse().map_err(|_| bad())?;
        let prefix: u8 = prefix.trim().parse().map_err(|_| bad())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(bad());
        }
        Ok(Self {
            addr: normalise(addr),
            prefix,
        })
    }
}

/// `::ffff:127.0.0.1` is loopback too.
fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// Addresses a tool must not reach by default: this machine, the link-local range (cloud metadata lives there),
/// and anything that is not a real destination.
pub fn is_internal(ip: IpAddr) -> bool {
    match normalise(ip) {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4 == Ipv4Addr::new(100, 100, 100, 200) // Alibaba Cloud metadata
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254) // AWS IPv6 metadata
        }
    }
}

/// A checked target: connect to `addrs` and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    pub scheme: Scheme,
    /// The name as written, for the `Host` header and TLS server name.
    pub host: String,
    pub port: u16,
    pub addrs: Vec<SocketAddr>,
}

/// The single choke point for outbound tool traffic. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Gate {
    inner: Arc<GateInner>,
}

#[derive(Debug)]
struct GateInner {
    scope: RwLock<Arc<Scope>>,
    stopped: AtomicBool,
    repeater_policy: RwLock<OutOfScopePolicy>,
    resolver: Box<dyn Resolver>,
    /// The host's own networks (server and container mode), refused like loopback.
    protected: RwLock<Vec<Network>>,
    /// Requests a second to any one host; 0 is unlimited.
    rate_limit: AtomicU32,
    recent: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl Default for Gate {
    fn default() -> Self {
        Self::with_resolver(Scope::default(), Box::new(SystemResolver))
    }
}

impl Gate {
    pub fn new(scope: Scope) -> Self {
        Self::with_resolver(scope, Box::new(SystemResolver))
    }

    pub fn with_resolver(scope: Scope, resolver: Box<dyn Resolver>) -> Self {
        Self {
            inner: Arc::new(GateInner {
                scope: RwLock::new(Arc::new(scope)),
                stopped: AtomicBool::new(false),
                repeater_policy: RwLock::new(OutOfScopePolicy::default()),
                resolver,
                protected: RwLock::new(Vec::new()),
                rate_limit: AtomicU32::new(0),
                recent: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn scope(&self) -> Arc<Scope> {
        self.inner.scope.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_scope(&self, scope: Scope) {
        *self.inner.scope.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(scope);
    }

    /// Stop (or resume) all outbound tool traffic. Proxied browser traffic is not affected: the user is
    /// driving that by hand.
    pub fn set_stopped(&self, stopped: bool) {
        self.inner.stopped.store(stopped, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::SeqCst)
    }

    pub fn repeater_policy(&self) -> OutOfScopePolicy {
        *self.inner.repeater_policy.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_repeater_policy(&self, p: OutOfScopePolicy) {
        *self
            .inner
            .repeater_policy
            .write()
            .unwrap_or_else(|e| e.into_inner()) = p;
    }

    /// Networks the machine itself sits on (Docker bridges, the LAN of a server). Treated like loopback.
    pub fn set_protected_networks(&self, nets: Vec<Network>) {
        *self.inner.protected.write().unwrap_or_else(|e| e.into_inner()) = nets;
    }

    /// At most `per_second` requests a second to any one host; `0` removes the limit.
    pub fn set_rate_limit(&self, per_second: u32) {
        self.inner.rate_limit.store(per_second, Ordering::SeqCst);
    }

    /// May `source` send a request to this target now? On success, the addresses to connect to.
    ///
    /// Resolves the name, so it can block: call it from `spawn_blocking`. Traffic from the proxy is the user's own
    /// browsing and is not checked (and not resolved: the proxy connects as before).
    pub fn check(
        &self,
        source: FlowSource,
        scheme: Scheme,
        host: &str,
        port: u16,
        path: &str,
    ) -> Result<Pinned, ScopeError> {
        let bare = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.');
        if source == FlowSource::Proxy {
            return Ok(Pinned {
                scheme,
                host: bare.to_string(),
                port,
                addrs: Vec::new(),
            });
        }
        if self.is_stopped() {
            return Err(ScopeError::Stopped);
        }
        let scope = self.scope();
        let hits = scope.matching(scheme, host, port, path);
        if hits.is_none() {
            let policy = match source {
                FlowSource::Repeater => *self
                    .inner
                    .repeater_policy
                    .read()
                    .unwrap_or_else(|e| e.into_inner()),
                // Automated tools never leave scope.
                _ => OutOfScopePolicy::Refuse,
            };
            if policy == OutOfScopePolicy::Refuse {
                return Err(ScopeError::OutOfScope(format!(
                    "{}://{}:{}{}",
                    scheme.as_str(),
                    host,
                    port,
                    path
                )));
            }
        }
        // Leaving scope on purpose (the Repeater policy) does not lift the address checks: a rule with
        // `allow_private` is the only way to reach this machine.
        let lower = bare.to_ascii_lowercase();
        let literal_ip = lower.parse::<IpAddr>().ok();
        let named = |r: &&Rule| r.literal.as_deref() == Some(lower.as_str());
        let private_ok = hits.as_ref().is_some_and(|rules| {
            rules
                .iter()
                .any(|r| r.allow_private || (literal_ip.is_some() && named(r)))
        });

        let ips = match literal_ip {
            Some(ip) => vec![ip],
            None => self
                .inner
                .resolver
                .resolve(&lower, port)
                .map_err(|e| ScopeError::Unresolvable(bare.to_string(), e.to_string()))?,
        };
        if ips.is_empty() {
            return Err(ScopeError::Unresolvable(bare.to_string(), "no addresses".into()));
        }
        if !private_ok {
            let protected = self.inner.protected.read().unwrap_or_else(|e| e.into_inner());
            // One bad answer refuses the lot: a rebinding trick mixes public and internal addresses.
            if let Some(bad) = ips
                .iter()
                .find(|ip| is_internal(**ip) || protected.iter().any(|n| n.contains(**ip)))
            {
                return Err(ScopeError::PrivateAddress {
                    host: bare.to_string(),
                    addr: *bad,
                });
            }
        }
        self.take_rate_token(&lower)?;
        Ok(Pinned {
            scheme,
            host: bare.to_string(),
            port,
            addrs: ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect(),
        })
    }

    fn take_rate_token(&self, host: &str) -> Result<(), ScopeError> {
        let limit = self.inner.rate_limit.load(Ordering::SeqCst);
        if limit == 0 {
            return Ok(());
        }
        let now = Instant::now();
        let mut recent = self.inner.recent.lock().unwrap_or_else(|e| e.into_inner());
        let q = recent.entry(host.to_string()).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(1))
        {
            q.pop_front();
        }
        if q.len() >= limit as usize {
            return Err(ScopeError::RateLimited(host.to_string(), limit));
        }
        q.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(host: &str) -> RuleSpec {
        RuleSpec {
            host: host.into(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_scope_contains_nothing() {
        let s = Scope::compile(ScopeSpec::default()).unwrap();
        assert!(!s.contains(Scheme::Https, "example.com", 443, "/"));
    }

    #[test]
    fn host_globs_ports_paths_and_excludes() {
        let s = Scope::compile(ScopeSpec {
            include: vec![
                rule("example.com"),
                rule("*.example.com"),
                RuleSpec {
                    scheme: Some(Scheme::Https),
                    port: Some(8443),
                    ..rule("api.test")
                },
            ],
            exclude: vec![RuleSpec {
                path: Some("^/logout".into()),
                ..rule("*example.com")
            }],
        })
        .unwrap();
        assert!(s.contains(Scheme::Https, "EXAMPLE.com.", 443, "/a?x=1"));
        assert!(s.contains(Scheme::Http, "a.example.com", 80, "/"));
        assert!(
            !s.contains(Scheme::Http, "a.b.example.com", 80, "/"),
            "* does not cross dots"
        );
        assert!(!s.contains(Scheme::Http, "notexample.com", 80, "/"));
        assert!(!s.contains(Scheme::Https, "example.com", 443, "/logout?all"));
        assert!(s.contains(Scheme::Https, "api.test", 8443, "/"));
        assert!(!s.contains(Scheme::Http, "api.test", 8443, "/"));
        assert!(!s.contains(Scheme::Https, "api.test", 443, "/"));
    }

    /// Answers from a table, so the tests never touch DNS.
    #[derive(Debug, Default)]
    struct Fake(std::sync::Mutex<HashMap<String, Vec<IpAddr>>>);

    impl Fake {
        fn with(entries: &[(&str, &[&str])]) -> Box<Self> {
            let f = Self::default();
            for (h, ips) in entries {
                f.0.lock()
                    .unwrap()
                    .insert((*h).into(), ips.iter().map(|i| i.parse().unwrap()).collect());
            }
            Box::new(f)
        }
    }

    impl Resolver for Fake {
        fn resolve(&self, host: &str, _port: u16) -> std::io::Result<Vec<IpAddr>> {
            self.0
                .lock()
                .unwrap()
                .get(host)
                .cloned()
                .ok_or_else(|| std::io::Error::other("no such host"))
        }
    }

    fn gate(include: Vec<RuleSpec>) -> Gate {
        Gate::with_resolver(
            Scope::compile(ScopeSpec {
                include,
                exclude: vec![],
            })
            .unwrap(),
            Fake::with(&[
                ("in.test", &["93.184.216.34"]),
                ("out.test", &["93.184.216.35"]),
                ("rebind.test", &["127.0.0.1"]),
                ("meta.test", &["169.254.169.254"]),
                ("mixed.test", &["93.184.216.34", "10.0.0.1", "::1"]),
                ("lan.test", &["192.168.1.20"]),
                ("v6.test", &["::ffff:127.0.0.1"]),
            ]),
        )
    }

    #[test]
    fn gate_refuses_out_of_scope_for_tools_and_honours_kill_switch() {
        let g = gate(vec![rule("in.test")]);
        let check = |src, host: &str| g.check(src, Scheme::Http, host, 80, "/");
        assert!(check(FlowSource::Scanner, "in.test").is_ok());
        assert!(check(FlowSource::Scanner, "out.test").is_err());
        assert!(check(FlowSource::Proxy, "out.test").is_ok());
        assert!(check(FlowSource::Repeater, "out.test").is_err());
        g.set_repeater_policy(OutOfScopePolicy::Allow);
        assert!(check(FlowSource::Repeater, "out.test").is_ok());
        assert!(check(FlowSource::Intruder, "out.test").is_err());
        g.set_stopped(true);
        assert!(matches!(
            check(FlowSource::Scanner, "in.test"),
            Err(ScopeError::Stopped)
        ));
    }

    #[test]
    fn the_pinned_addresses_are_what_the_name_resolved_to() {
        let g = gate(vec![rule("in.test")]);
        let p = g
            .check(FlowSource::Scanner, Scheme::Https, "IN.test.", 8443, "/")
            .unwrap();
        assert_eq!(p.host, "IN.test");
        assert_eq!(p.addrs, vec!["93.184.216.34:8443".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn a_scoped_name_that_resolves_inside_is_refused() {
        let g = gate(vec![
            rule("rebind.test"),
            rule("meta.test"),
            rule("mixed.test"),
            rule("v6.test"),
        ]);
        for host in ["rebind.test", "meta.test", "mixed.test", "v6.test"] {
            let r = g.check(FlowSource::Scanner, Scheme::Http, host, 80, "/");
            assert!(
                matches!(r, Err(ScopeError::PrivateAddress { .. })),
                "{host}: {r:?}"
            );
        }
        // Another tool, same answer; a Repeater that may leave scope is no exception.
        g.set_repeater_policy(OutOfScopePolicy::Allow);
        assert!(
            g.check(FlowSource::Repeater, Scheme::Http, "rebind.test", 80, "/")
                .is_err()
        );
    }

    #[test]
    fn address_literals_are_refused_unless_a_rule_names_them() {
        let g = gate(vec![rule("*.test")]);
        // `*` never covers an IP literal in these tests, so scope the literals explicitly.
        let g2 = gate(vec![rule("127.0.0.1"), rule("169.254.169.254"), rule("[::1]")]);
        assert!(
            g.check(FlowSource::Scanner, Scheme::Http, "127.0.0.1", 80, "/")
                .is_err()
        );
        let p = g2
            .check(FlowSource::Scanner, Scheme::Http, "127.0.0.1", 80, "/")
            .unwrap();
        assert_eq!(p.addrs[0].ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(
            g2.check(FlowSource::Scanner, Scheme::Http, "169.254.169.254", 80, "/")
                .is_ok()
        );
        assert!(
            g2.check(FlowSource::Scanner, Scheme::Http, "[::1]", 80, "/")
                .is_ok()
        );
        // A wildcard host rule that happens to match an address does not count as naming it.
        let g3 = gate(vec![rule("127.*")]);
        assert!(
            g3.check(FlowSource::Scanner, Scheme::Http, "127.0.0.1", 80, "/")
                .is_err()
        );
    }

    #[test]
    fn allow_private_opens_one_rule_only() {
        let g = gate(vec![
            RuleSpec {
                allow_private: true,
                ..rule("rebind.test")
            },
            rule("meta.test"),
        ]);
        assert!(
            g.check(FlowSource::Scanner, Scheme::Http, "rebind.test", 80, "/")
                .is_ok()
        );
        assert!(
            g.check(FlowSource::Scanner, Scheme::Http, "meta.test", 80, "/")
                .is_err()
        );
    }

    #[test]
    fn the_hosts_own_networks_are_refused_like_loopback() {
        let g = gate(vec![rule("lan.test"), rule("in.test")]);
        // Private ranges are ordinary targets until the server says they are its own.
        assert!(
            g.check(FlowSource::Scanner, Scheme::Http, "lan.test", 80, "/")
                .is_ok()
        );
        g.set_protected_networks(vec!["192.168.1.0/24".parse().unwrap()]);
        assert!(matches!(
            g.check(FlowSource::Scanner, Scheme::Http, "lan.test", 80, "/"),
            Err(ScopeError::PrivateAddress { .. })
        ));
        assert!(
            g.check(FlowSource::Scanner, Scheme::Http, "in.test", 80, "/")
                .is_ok()
        );
    }

    #[test]
    fn networks_parse_and_match() {
        let n: Network = "10.1.0.0/16".parse().unwrap();
        assert!(n.contains("10.1.200.3".parse().unwrap()));
        assert!(!n.contains("10.2.0.1".parse().unwrap()));
        assert!(!n.contains("fe80::1".parse().unwrap()));
        let n6: Network = "fd00::/8".parse().unwrap();
        assert!(n6.contains("fd12::1".parse().unwrap()));
        let all: Network = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
        for bad in ["10.0.0.0", "10.0.0.0/33", "x/8", "::/129"] {
            assert!(bad.parse::<Network>().is_err(), "{bad}");
        }
    }

    #[test]
    fn unresolvable_names_and_rate_limits() {
        let g = gate(vec![rule("in.test"), rule("nowhere.test")]);
        assert!(matches!(
            g.check(FlowSource::Scanner, Scheme::Http, "nowhere.test", 80, "/"),
            Err(ScopeError::Unresolvable(..))
        ));
        g.set_rate_limit(2);
        let go = |h| g.check(FlowSource::Scanner, Scheme::Http, h, 80, "/");
        assert!(go("in.test").is_ok());
        assert!(go("in.test").is_ok());
        assert!(matches!(go("in.test"), Err(ScopeError::RateLimited(..))));
        g.set_rate_limit(0);
        assert!(go("in.test").is_ok());
    }

    #[test]
    fn internal_address_classes() {
        for ip in [
            "127.0.0.1",
            "127.8.8.8",
            "0.0.0.0",
            "169.254.169.254",
            "169.254.1.1",
            "100.100.100.200",
            "::1",
            "::",
            "fe80::1",
            "fd00:ec2::254",
            "::ffff:169.254.169.254",
            "224.0.0.1",
        ] {
            assert!(is_internal(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "10.0.0.1",
            "192.168.0.1",
            "172.16.5.5",
            "2606:4700::1111",
            "fc00::1",
        ] {
            assert!(!is_internal(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn bad_patterns_are_errors() {
        assert!(
            Scope::compile(ScopeSpec {
                include: vec![rule("")],
                exclude: vec![]
            })
            .is_err()
        );
        assert!(
            Scope::compile(ScopeSpec {
                include: vec![RuleSpec {
                    path: Some("(".into()),
                    ..rule("a")
                }],
                exclude: vec![]
            })
            .is_err()
        );
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        fn label() -> impl Strategy<Value = String> {
            "[a-z0-9]{1,8}"
        }

        fn host() -> impl Strategy<Value = String> {
            proptest::collection::vec(label(), 1..4).prop_map(|l| l.join("."))
        }

        fn scheme() -> impl Strategy<Value = Scheme> {
            prop_oneof![Just(Scheme::Http), Just(Scheme::Https)]
        }

        fn scope_with(include: &[&str], exclude: &[&str]) -> Scope {
            Scope::compile(ScopeSpec {
                include: include.iter().map(|h| rule(h)).collect(),
                exclude: exclude.iter().map(|h| rule(h)).collect(),
            })
            .unwrap()
        }

        proptest! {
            /// Whatever a hostile page puts in a URL, matching never panics.
            #[test]
            fn contains_never_panics(h in ".{0,60}", path in ".{0,80}", port in any::<u16>(), s in scheme()) {
                let scope = scope_with(&["example.com", "*.example.com"], &["admin.example.com"]);
                let _ = scope.contains(s, &h, port, &path);
            }

            /// Compiling arbitrary user patterns returns an error or a working scope, never a panic.
            #[test]
            fn compile_never_panics(h in ".{0,40}", p in ".{0,40}") {
                let spec = RuleSpec { host: h, path: Some(p), ..Default::default() };
                let _ = Scope::compile(ScopeSpec { include: vec![spec], exclude: vec![] });
            }

            /// An empty include list means nothing is in scope, whatever the target.
            #[test]
            fn empty_scope_contains_nothing(h in host(), port in any::<u16>(), s in scheme(), path in "/[a-z/]{0,20}") {
                let scope = Scope::compile(ScopeSpec::default()).unwrap();
                prop_assert!(!scope.contains(s, &h, port, &path));
            }

            /// A literal host rule matches that host in any letter case, with or without a trailing dot.
            #[test]
            fn literal_hosts_match_in_any_case(h in host(), port in any::<u16>(), s in scheme()) {
                let scope = scope_with(&[&h], &[]);
                let upper = h.to_ascii_uppercase();
                let dotted = format!("{h}.");
                prop_assert!(scope.contains(s, &upper, port, "/"));
                prop_assert!(scope.contains(s, &dotted, port, "/"));
            }

            /// Exclusion always wins: a target that matches an exclude rule is never in scope.
            #[test]
            fn excludes_beat_includes(h in host(), port in any::<u16>(), s in scheme(), path in "/[a-z/]{0,20}") {
                let scope = scope_with(&[&h], &[&h]);
                prop_assert!(!scope.contains(s, &h, port, &path));
            }

            /// `*.example.com` covers exactly one extra label, never the apex and never two levels.
            #[test]
            fn wildcard_covers_one_label(a in label(), b in label()) {
                let scope = scope_with(&["*.example.com"], &[]);
                let one = format!("{a}.example.com");
                let two = format!("{a}.{b}.example.com");
                let lookalike = format!("{a}example.com.evil.test");
                prop_assert!(scope.contains(Scheme::Https, &one, 443, "/"));
                prop_assert!(!scope.contains(Scheme::Https, "example.com", 443, "/"));
                prop_assert!(!scope.contains(Scheme::Https, &two, 443, "/"));
                // A look-alike suffix is not a sub-domain.
                prop_assert!(!scope.contains(Scheme::Https, &lookalike, 443, "/"));
            }

            /// The query string and fragment never change the answer.
            #[test]
            fn query_and_fragment_are_ignored(path in "/[a-z/]{0,20}", q in "[ -~]{0,30}") {
                let spec = RuleSpec { host: "example.com".into(), path: Some("^/api/".into()), ..Default::default() };
                let scope = Scope::compile(ScopeSpec { include: vec![spec], exclude: vec![] }).unwrap();
                let base = scope.contains(Scheme::Https, "example.com", 443, &path);
                let with_query = format!("{path}?{q}");
                let with_fragment = format!("{path}#{q}");
                prop_assert_eq!(base, scope.contains(Scheme::Https, "example.com", 443, &with_query));
                prop_assert_eq!(base, scope.contains(Scheme::Https, "example.com", 443, &with_fragment));
            }

            /// A port or scheme restriction is honoured exactly.
            #[test]
            fn port_and_scheme_restrictions_hold(port in any::<u16>(), other in any::<u16>()) {
                let spec = RuleSpec { host: "example.com".into(), scheme: Some(Scheme::Https), port: Some(port), path: None, allow_private: false };
                let scope = Scope::compile(ScopeSpec { include: vec![spec], exclude: vec![] }).unwrap();
                prop_assert!(scope.contains(Scheme::Https, "example.com", port, "/"));
                prop_assert!(!scope.contains(Scheme::Http, "example.com", port, "/"));
                prop_assert_eq!(other == port, scope.contains(Scheme::Https, "example.com", other, "/"));
            }
        }
    }
}
