//! Following redirects with a raw request: work out where `Location` points, and rewrite the request bytes for
//! the next hop (request line, `Host`, and nothing else beyond what the redirect rules require).

use bosun_model::Scheme;

/// Where a redirect points.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Url {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// Path and query, always starting with `/`.
    pub path: String,
}

impl Url {
    /// `host` or `host:port`, as it goes in a `Host` header.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.scheme.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Resolve `location` against the request that was just sent (`base` is its scheme, host and port; `target` is its
/// request-target). `None` if it is not an http(s) URL we can follow.
pub fn resolve(base: &bosun_model::Target, target: &str, location: &str) -> Option<Url> {
    let loc = location.trim().split('#').next().unwrap_or("");
    if loc.is_empty() {
        return None;
    }
    // The path the request was sent to, without an absolute-form prefix.
    let base_path = {
        let t = match target.find("://") {
            Some(i) => target[i + 3..].find('/').map_or("/", |j| &target[i + 3 + j..]),
            None => target,
        };
        if t.starts_with('/') { t } else { "/" }
    };
    let origin = |path: String| Url {
        scheme: base.scheme,
        host: base.host.clone(),
        port: base.port,
        path,
    };
    if let Some((scheme, rest)) = loc.split_once("://") {
        let scheme = Scheme::parse(&scheme.to_ascii_lowercase())?;
        return with_authority(scheme, rest);
    }
    if let Some(rest) = loc.strip_prefix("//") {
        return with_authority(base.scheme, rest);
    }
    if loc.starts_with('/') {
        return Some(origin(normalise(loc)));
    }
    if loc.starts_with('?') {
        let path = base_path.split('?').next().unwrap_or("/");
        return Some(origin(format!("{path}{loc}")));
    }
    // Relative to the directory of the current path.
    let path = base_path.split('?').next().unwrap_or("/");
    let dir = &path[..=path.rfind('/').unwrap_or(0)];
    Some(origin(normalise(&format!("{dir}{loc}"))))
}

fn with_authority(scheme: Scheme, rest: &str) -> Option<Url> {
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (auth, tail) = rest.split_at(end);
    let auth = auth.rsplit('@').next().unwrap_or(auth);
    let (host, port) = if let Some(v6) = auth.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        (h.to_string(), after.strip_prefix(':').filter(|p| !p.is_empty()))
    } else {
        match auth.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p).filter(|p| !p.is_empty())),
            None => (auth.to_string(), None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        Some(p) => p.parse().ok()?,
        None => scheme.default_port(),
    };
    let path = if tail.starts_with('/') {
        normalise(tail)
    } else if tail.is_empty() {
        "/".to_string()
    } else {
        format!("/{tail}")
    };
    Some(Url {
        scheme,
        host,
        port,
        path,
    })
}

/// Remove `.` and `..` segments from the path part (the query is left alone).
fn normalise(p: &str) -> String {
    let (path, query) = match p.split_once('?') {
        Some((a, b)) => (a, Some(b)),
        None => (p, None),
    };
    let mut out: Vec<&str> = Vec::new();
    let segs: Vec<&str> = path.split('/').collect();
    for (i, seg) in segs.iter().enumerate() {
        match *seg {
            "." => {}
            ".." => {
                if out.len() > 1 {
                    out.pop();
                }
            }
            s => out.push(s),
        }
        // A trailing dot segment leaves a trailing slash.
        if i + 1 == segs.len() && matches!(*seg, "." | "..") {
            out.push("");
        }
    }
    let mut joined = out.join("/");
    if !joined.starts_with('/') {
        joined.insert(0, '/');
    }
    match query {
        Some(q) => format!("{joined}?{q}"),
        None => joined,
    }
}

/// Rewrite a raw request for the next hop: new request-target (and method, if given), `Host` set to the new
/// authority. With `drop_body` the body and the headers that describe it go; with `cross_origin` credentials
/// (`Authorization`, `Cookie`, `Proxy-Authorization`) go too. Everything else, including header order, case and
/// duplicates, is copied as written.
pub fn rewrite_request(
    raw: &[u8],
    method: Option<&str>,
    url: &Url,
    cross_origin: bool,
    drop_body: bool,
) -> Vec<u8> {
    let Some(end) = crate::wire::head_end(raw) else {
        return raw.to_vec();
    };
    let head = &raw[..end];
    let mut out = Vec::with_capacity(raw.len());
    let mut pos = 0;
    let mut first = true;
    let mut host_done = false;
    while pos < head.len() {
        let line_end = head[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(head.len(), |p| pos + p + 1);
        let line = &head[pos..line_end];
        pos = line_end;
        let (content, eol) = split_eol(line);
        if first {
            first = false;
            let text = String::from_utf8_lossy(content);
            let mut it = text.splitn(3, ' ');
            let old_method = it.next().unwrap_or("");
            let _old_target = it.next();
            let version = it.next().unwrap_or("HTTP/1.1");
            out.extend_from_slice(
                format!("{} {} {}", method.unwrap_or(old_method), url.path, version).as_bytes(),
            );
            out.extend_from_slice(eol);
            continue;
        }
        if content.is_empty() {
            out.extend_from_slice(line);
            continue;
        }
        let name = content
            .iter()
            .position(|&b| b == b':')
            .map(|i| &content[..i])
            .unwrap_or(&[]);
        let is = |n: &str| name.eq_ignore_ascii_case(n.as_bytes());
        if is("host") && !host_done {
            host_done = true;
            out.extend_from_slice(&content[..name.len()]);
            out.extend_from_slice(format!(": {}", url.authority()).as_bytes());
            out.extend_from_slice(eol);
            continue;
        }
        let drop = (drop_body
            && (is("content-length")
                || is("content-type")
                || is("content-encoding")
                || is("transfer-encoding")))
            || (cross_origin && (is("authorization") || is("cookie") || is("proxy-authorization")));
        if !drop {
            out.extend_from_slice(line);
        }
    }
    if !drop_body {
        out.extend_from_slice(&raw[end..]);
    }
    out
}

fn split_eol(line: &[u8]) -> (&[u8], &[u8]) {
    if let Some(c) = line.strip_suffix(b"\r\n") {
        (c, b"\r\n")
    } else if let Some(c) = line.strip_suffix(b"\n") {
        (c, b"\n")
    } else {
        (line, b"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bosun_model::Target;

    fn base() -> Target {
        Target::new(Scheme::Https, "a.test", 443)
    }

    fn url(loc: &str) -> Option<String> {
        resolve(&base(), "/x/y/z?q=1", loc)
            .map(|u| format!("{}://{}{}", u.scheme.as_str(), u.authority(), u.path))
    }

    #[test]
    fn locations_resolve_like_a_browser() {
        assert_eq!(
            url("http://b.test:8080/p?x#f").as_deref(),
            Some("http://b.test:8080/p?x")
        );
        assert_eq!(url("//c.test/q").as_deref(), Some("https://c.test/q"));
        assert_eq!(url("/abs").as_deref(), Some("https://a.test/abs"));
        assert_eq!(url("rel").as_deref(), Some("https://a.test/x/y/rel"));
        assert_eq!(url("../up").as_deref(), Some("https://a.test/x/up"));
        assert_eq!(url("?n=2").as_deref(), Some("https://a.test/x/y/z?n=2"));
        assert_eq!(url("http://[::1]:9/").as_deref(), Some("http://[::1]:9/"));
        assert_eq!(url("http://u:p@d.test").as_deref(), Some("http://d.test/"));
        assert_eq!(url("ftp://nope/"), None);
        assert_eq!(url(""), None);
    }

    #[test]
    fn the_next_request_keeps_everything_but_what_the_redirect_changes() {
        let raw = b"POST /old HTTP/1.1\r\nhost: a.test\r\nCookie: s=1\r\nX-A: 1\r\nx-a: 2\r\nContent-Length: 3\r\n\r\nabc";
        let u = Url {
            scheme: Scheme::Http,
            host: "b.test".into(),
            port: 8080,
            path: "/new?x=1".into(),
        };
        // Same method (307): body kept, credentials kept for the same origin.
        assert_eq!(
            rewrite_request(raw, None, &u, false, false),
            b"POST /new?x=1 HTTP/1.1\r\nhost: b.test:8080\r\nCookie: s=1\r\nX-A: 1\r\nx-a: 2\r\nContent-Length: 3\r\n\r\nabc"
        );
        // To another origin as GET (303): no body, no credentials.
        assert_eq!(
            rewrite_request(raw, Some("GET"), &u, true, true),
            b"GET /new?x=1 HTTP/1.1\r\nhost: b.test:8080\r\nX-A: 1\r\nx-a: 2\r\n\r\n"
        );
    }
}
