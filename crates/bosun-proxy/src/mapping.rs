//! Map Local, Map Remote and throttle rules, applied to proxied requests next to match-and-replace.
//!
//! - **Map Local** answers a matching GET or HEAD from a file under a directory the user picked. The directory is
//!   canonicalised, the requested path is percent-decoded and refused if it has a `..` component, and the file's own
//!   canonical path must still be inside the directory, so neither traversal nor a symlink can reach outside it.
//! - **Map Remote** sends a matching request to another origin. The new target is checked by the proxy against
//!   the scope gate (`Gate::check`) before anything is sent.
//! - **Throttle** adds latency and/or limits the response's bandwidth.
//!
//! Rules are tried in list order: the first enabled Map Local or Map Remote rule that matches decides the request,
//! and the first enabled throttle rule that matches shapes it.

use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bosun_model::Scheme;
use bytes::Bytes;
use http_body::{Body, Frame};
use serde::{Deserialize, Serialize};

use crate::server::RespBody;
use crate::upstream::BoxError;

pub const MAX_MAP_RULES: usize = 200;
/// The longest latency one rule may add.
pub const MAX_LATENCY_MS: u32 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MapKind {
    MapLocal,
    MapRemote,
    Throttle,
}

/// One rule as saved. The fields a kind does not use are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MapRule {
    #[serde(default = "yes")]
    pub enabled: bool,
    pub kind: MapKind,
    /// Host to match: `api.example.com`, `*.example.com` for every name under it, or empty for any host.
    #[serde(default)]
    pub host: String,
    /// Match requests whose path (without the query) starts with this. Empty matches every path.
    #[serde(default)]
    pub path_prefix: String,
    /// Map Local: the directory files are served from.
    #[serde(default)]
    pub directory: String,
    /// Map Remote: the origin to send the request to, for example `https://staging.example.com:8443`.
    #[serde(default)]
    pub target: String,
    /// Throttle: milliseconds added before the request is sent.
    #[serde(default)]
    pub latency_ms: u32,
    /// Throttle: response bytes a second; 0 is unlimited.
    #[serde(default)]
    pub bytes_per_sec: u32,
    #[serde(default)]
    pub comment: String,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTarget {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Throttle {
    pub latency_ms: u32,
    pub bytes_per_sec: u32,
}

#[derive(Debug, Clone)]
pub struct LocalRule {
    dir: PathBuf,
    prefix: String,
}

#[derive(Debug, Clone)]
pub enum MapAction {
    Local(LocalRule),
    Remote(RemoteTarget),
}

/// What the rules say about one request.
#[derive(Debug, Clone, Default)]
pub struct MapDecision {
    pub action: Option<MapAction>,
    pub throttle: Option<Throttle>,
}

#[derive(Debug, Clone)]
struct Compiled {
    host: String,
    prefix: String,
    kind: Kind,
}

#[derive(Debug, Clone)]
enum Kind {
    Local(LocalRule),
    Remote(RemoteTarget),
    Throttle(Throttle),
}

#[derive(Debug, Default)]
pub struct MapRules {
    specs: Vec<MapRule>,
    rules: Vec<Compiled>,
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() {
        return true;
    }
    match pattern.strip_prefix("*.") {
        Some(rest) => {
            host.len() > rest.len() + 1
                && host.ends_with(rest)
                && host[..host.len() - rest.len()].ends_with('.')
        }
        None => host == pattern,
    }
}

fn compile_one(i: usize, s: &MapRule) -> Result<Compiled, String> {
    let n = i + 1;
    let host = s.host.trim().to_ascii_lowercase();
    if host.contains(['/', ':', ' '])
        || (host.contains('*') && !host.starts_with("*."))
        || host.matches('*').count() > 1
    {
        return Err(format!(
            "rule {n}: the host must be a name or `*.name`, without a port or path"
        ));
    }
    if !s.path_prefix.is_empty() && !s.path_prefix.starts_with('/') {
        return Err(format!("rule {n}: the path prefix must start with `/`"));
    }
    let kind = match s.kind {
        MapKind::MapLocal => {
            let dir = std::fs::canonicalize(&s.directory)
                .map_err(|e| format!("rule {n}: cannot use the directory `{}`: {e}", s.directory))?;
            if !dir.is_dir() {
                return Err(format!("rule {n}: `{}` is not a directory", s.directory));
            }
            Kind::Local(LocalRule {
                dir,
                prefix: s.path_prefix.clone(),
            })
        }
        MapKind::MapRemote => Kind::Remote(parse_target(&s.target).map_err(|e| format!("rule {n}: {e}"))?),
        MapKind::Throttle => {
            if s.latency_ms > MAX_LATENCY_MS {
                return Err(format!("rule {n}: latency is at most {MAX_LATENCY_MS} ms"));
            }
            if s.latency_ms == 0 && s.bytes_per_sec == 0 {
                return Err(format!(
                    "rule {n}: a throttle rule needs a latency or a bandwidth"
                ));
            }
            Kind::Throttle(Throttle {
                latency_ms: s.latency_ms,
                bytes_per_sec: s.bytes_per_sec,
            })
        }
    };
    Ok(Compiled {
        host,
        prefix: s.path_prefix.clone(),
        kind,
    })
}

/// `http(s)://host[:port]`, nothing after it.
pub fn parse_target(t: &str) -> Result<RemoteTarget, String> {
    let t = t.trim();
    let (scheme, rest) = t
        .split_once("://")
        .ok_or("the Map Remote target must be an origin such as https://staging.example.com")?;
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        _ => return Err("the Map Remote target must start with http:// or https://".into()),
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
        return Err("the Map Remote target is an origin only: no path, query or credentials".into());
    }
    let (host, port) = if let Some(r) = rest.strip_prefix('[') {
        let (h, tail) = r
            .split_once(']')
            .ok_or("the Map Remote target has an unclosed `[`")?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(
                p.parse::<u16>()
                    .map_err(|_| "the Map Remote port is not a number")?,
            ),
            None if tail.is_empty() => None,
            None => return Err("the Map Remote target is not valid".into()),
        };
        (h, port)
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => (
                h,
                Some(
                    p.parse::<u16>()
                        .map_err(|_| "the Map Remote port is not a number")?,
                ),
            ),
            None => (rest, None),
        }
    };
    if host.is_empty() {
        return Err("the Map Remote target has no host".into());
    }
    Ok(RemoteTarget {
        scheme,
        host: host.to_ascii_lowercase(),
        port: port.unwrap_or(scheme.default_port()),
    })
}

impl MapRules {
    /// Compile every enabled rule; the first problem is an error.
    pub fn compile(specs: Vec<MapRule>) -> Result<Self, String> {
        if specs.len() > MAX_MAP_RULES {
            return Err("too many rules".into());
        }
        let mut rules = Vec::new();
        for (i, s) in specs.iter().enumerate() {
            if s.enabled {
                rules.push(compile_one(i, s)?);
            }
        }
        Ok(Self { specs, rules })
    }

    /// Like `compile`, but a rule that cannot be used (its directory is gone, say) is left out, and counted.
    /// For loading saved rules, so one stale rule does not switch the others off.
    pub fn compile_lossy(specs: Vec<MapRule>) -> (Self, usize) {
        let mut rules = Vec::new();
        let mut skipped = 0;
        for (i, s) in specs.iter().take(MAX_MAP_RULES).enumerate() {
            if s.enabled {
                match compile_one(i, s) {
                    Ok(c) => rules.push(c),
                    Err(_) => skipped += 1,
                }
            }
        }
        (Self { specs, rules }, skipped)
    }

    pub fn specs(&self) -> &[MapRule] {
        &self.specs
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// `path` is the request target; the query is ignored.
    pub fn decide(&self, host: &str, method: &str, path: &str) -> MapDecision {
        let mut d = MapDecision::default();
        let p = path.split(['?', '#']).next().unwrap_or("");
        for r in &self.rules {
            if !host_matches(&r.host, host) || !p.starts_with(&r.prefix) {
                continue;
            }
            match &r.kind {
                Kind::Local(l) if d.action.is_none() && matches!(method, "GET" | "HEAD") => {
                    d.action = Some(MapAction::Local(l.clone()));
                }
                Kind::Remote(t) if d.action.is_none() => d.action = Some(MapAction::Remote(t.clone())),
                Kind::Throttle(t) if d.throttle.is_none() => d.throttle = Some(*t),
                _ => {}
            }
        }
        d
    }
}

/// What reading a local file came to.
#[derive(Debug, PartialEq, Eq)]
pub enum LocalOutcome {
    File {
        bytes: Vec<u8>,
        content_type: &'static str,
    },
    /// No such file: the request goes on to its real target.
    NotFound,
    /// The path leads outside the directory (traversal or a symlink), or is not a plain file: refused.
    Forbidden,
    TooBig,
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

impl LocalRule {
    /// Resolve the file for `path` (the request target). Blocking: call from `spawn_blocking`.
    pub fn resolve(&self, path: &str) -> Result<PathBuf, LocalOutcome> {
        let raw = path.split(['?', '#']).next().unwrap_or("");
        let rest = raw.strip_prefix(self.prefix.as_str()).unwrap_or(raw);
        let Some(decoded) = percent_decode(rest) else {
            return Err(LocalOutcome::Forbidden);
        };
        if decoded.contains(['\0', '\\']) {
            return Err(LocalOutcome::Forbidden);
        }
        let mut rel = decoded.trim_start_matches('/').to_string();
        if rel.is_empty() || rel.ends_with('/') {
            rel.push_str("index.html");
        }
        let rel = Path::new(&rel);
        if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(LocalOutcome::Forbidden);
        }
        // The directory is canonicalised again: it may have been replaced by a symlink since the rule was saved.
        let Ok(dir) = std::fs::canonicalize(&self.dir) else {
            return Err(LocalOutcome::NotFound);
        };
        let Ok(file) = std::fs::canonicalize(dir.join(rel)) else {
            return Err(LocalOutcome::NotFound);
        };
        if !file.starts_with(&dir) || !file.is_file() {
            return Err(LocalOutcome::Forbidden);
        }
        Ok(file)
    }

    pub fn read(&self, path: &str, max_bytes: usize) -> LocalOutcome {
        let file = match self.resolve(path) {
            Ok(f) => f,
            Err(o) => return o,
        };
        match std::fs::metadata(&file) {
            Ok(m) if m.len() as usize > max_bytes => return LocalOutcome::TooBig,
            Ok(_) => {}
            Err(_) => return LocalOutcome::NotFound,
        }
        match std::fs::read(&file) {
            Ok(bytes) => LocalOutcome::File {
                bytes,
                content_type: content_type(&file),
            },
            Err(_) => LocalOutcome::NotFound,
        }
    }
}

fn content_type(p: &Path) -> &'static str {
    match p
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// Delays each data frame so the body flows at about `bytes_per_sec`.
pub struct ThrottleBody {
    inner: RespBody,
    bytes_per_sec: u64,
    held: Option<Frame<Bytes>>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl ThrottleBody {
    pub fn new(inner: RespBody, bytes_per_sec: u32) -> Self {
        Self {
            inner,
            bytes_per_sec: u64::from(bytes_per_sec.max(1)),
            held: None,
            sleep: None,
        }
    }
}

impl Body for ThrottleBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        loop {
            if let Some(s) = self.sleep.as_mut() {
                if s.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.sleep = None;
                if let Some(f) = self.held.take() {
                    return Poll::Ready(Some(Ok(f)));
                }
            }
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    let n = frame.data_ref().map_or(0, Bytes::len) as u64;
                    if n == 0 {
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    let wait = Duration::from_micros(n.saturating_mul(1_000_000) / self.bytes_per_sec);
                    self.held = Some(frame);
                    self.sleep = Some(Box::pin(tokio::time::sleep(wait)));
                }
                other => return other,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.held.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: MapKind) -> MapRule {
        MapRule {
            enabled: true,
            kind,
            host: String::new(),
            path_prefix: String::new(),
            directory: String::new(),
            target: String::new(),
            latency_ms: 0,
            bytes_per_sec: 0,
            comment: String::new(),
        }
    }

    fn local(dir: &Path, prefix: &str) -> LocalRule {
        LocalRule {
            dir: std::fs::canonicalize(dir).unwrap(),
            prefix: prefix.into(),
        }
    }

    #[test]
    fn host_patterns() {
        assert!(host_matches("", "anything.test"));
        assert!(host_matches("a.test", "A.test."));
        assert!(!host_matches("a.test", "b.a.test"));
        assert!(host_matches("*.a.test", "b.a.test"));
        assert!(!host_matches("*.a.test", "a.test"));
        assert!(!host_matches("*.a.test", "xa.test"));
    }

    #[test]
    fn targets_are_origins() {
        let t = parse_target("https://Staging.example.com:8443/").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.scheme),
            ("staging.example.com", 8443, Scheme::Https)
        );
        assert_eq!(parse_target("http://x.test").unwrap().port, 80);
        assert_eq!(parse_target("http://[::1]:9").unwrap().host, "::1");
        for bad in [
            "x.test",
            "ftp://x.test",
            "http://x.test/p",
            "http://u@x.test",
            "http://",
            "http://x:abc",
        ] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn compile_checks_each_kind() {
        let mut r = spec(MapKind::Throttle);
        assert!(
            MapRules::compile(vec![r.clone()]).is_err(),
            "needs a latency or bandwidth"
        );
        r.latency_ms = MAX_LATENCY_MS + 1;
        assert!(MapRules::compile(vec![r.clone()]).is_err());
        r.latency_ms = 10;
        assert!(MapRules::compile(vec![r]).is_ok());
        let mut l = spec(MapKind::MapLocal);
        l.directory = "/nonexistent/dir/for/bosun".into();
        assert!(MapRules::compile(vec![l.clone()]).is_err());
        let (set, skipped) = MapRules::compile_lossy(vec![l]);
        assert_eq!((set.is_empty(), skipped), (true, 1));
        let mut m = spec(MapKind::MapRemote);
        m.target = "nope".into();
        assert!(MapRules::compile(vec![m]).is_err());
        let mut h = spec(MapKind::Throttle);
        h.latency_ms = 1;
        h.host = "a*b".into();
        assert!(MapRules::compile(vec![h]).is_err());
    }

    #[test]
    fn first_matching_rule_decides() {
        let mut a = spec(MapKind::MapRemote);
        a.host = "a.test".into();
        a.path_prefix = "/api".into();
        a.target = "http://other.test".into();
        let mut t = spec(MapKind::Throttle);
        t.latency_ms = 5;
        let set = MapRules::compile(vec![a, t]).unwrap();
        let d = set.decide("a.test", "GET", "/api/x?q=1");
        assert!(matches!(d.action, Some(MapAction::Remote(_))));
        assert_eq!(d.throttle.unwrap().latency_ms, 5);
        let d = set.decide("a.test", "GET", "/other");
        assert!(d.action.is_none() && d.throttle.is_some());
        assert!(set.decide("b.test", "GET", "/api").action.is_none());
    }

    #[test]
    fn local_serves_files_and_index() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/a.json"), b"{}").unwrap();
        std::fs::write(d.path().join("index.html"), b"hi").unwrap();
        let l = local(d.path(), "/static");
        assert_eq!(
            l.read("/static/sub/a.json?x=1", 100),
            LocalOutcome::File {
                bytes: b"{}".to_vec(),
                content_type: "application/json"
            }
        );
        assert!(matches!(l.read("/static/", 100), LocalOutcome::File { .. }));
        assert_eq!(l.read("/static/missing", 100), LocalOutcome::NotFound);
        assert_eq!(
            l.read("/static/sub", 100),
            LocalOutcome::Forbidden,
            "a directory is not a file"
        );
        assert_eq!(l.read("/static/sub/a.json", 1), LocalOutcome::TooBig);
    }

    #[test]
    fn local_refuses_traversal() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("pub");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(root.path().join("secret.txt"), b"secret").unwrap();
        std::fs::write(dir.join("ok.txt"), b"ok").unwrap();
        let l = local(&dir, "");
        for p in [
            "/../secret.txt",
            "/%2e%2e/secret.txt",
            "/%2E%2E%2Fsecret.txt",
            "/sub/../../secret.txt",
            "/..%5csecret.txt",
            "/ok.txt%00.png",
            "//etc/passwd",
            "/%zz",
        ] {
            let o = l.read(p, 1000);
            assert!(
                matches!(o, LocalOutcome::Forbidden | LocalOutcome::NotFound),
                "{p} gave {o:?}"
            );
            assert!(!matches!(o, LocalOutcome::File { .. }), "{p} leaked a file");
        }
        assert_eq!(l.read("/../secret.txt", 1000), LocalOutcome::Forbidden);
        assert!(matches!(l.read("/ok.txt", 1000), LocalOutcome::File { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn local_refuses_a_symlink_out_of_the_directory() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("pub");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(root.path().join("secret.txt"), b"secret").unwrap();
        std::os::unix::fs::symlink(root.path().join("secret.txt"), dir.join("link.txt")).unwrap();
        std::os::unix::fs::symlink(root.path(), dir.join("up")).unwrap();
        std::fs::write(dir.join("real.txt"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.join("real.txt"), dir.join("inside.txt")).unwrap();
        let l = local(&dir, "");
        assert_eq!(l.read("/link.txt", 1000), LocalOutcome::Forbidden);
        assert_eq!(l.read("/up/secret.txt", 1000), LocalOutcome::Forbidden);
        assert!(
            matches!(l.read("/inside.txt", 1000), LocalOutcome::File { .. }),
            "a link that stays inside is fine"
        );
    }
}
