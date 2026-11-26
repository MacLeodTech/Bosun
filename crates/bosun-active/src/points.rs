//! Requests as parts that can be changed, and the insertion points in them.

use bosun_model::Scheme;
use serde_json::Value;

use crate::{ScanError, Strength, Target};

/// Most points one request gets, so a huge JSON body cannot make a huge scan.
const MAX_POINTS: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Point {
    Query(usize),
    Form(usize),
    /// A JSON pointer to a string or number value.
    Json(String),
    Cookie(usize),
    Header(String),
    /// The last path segment.
    Path,
    /// The request as a whole: carries the checks that need no value changed (CORS, Host header). Never returned
    /// by [`Req::points`]; the scan adds one per target.
    Whole,
}

#[derive(Debug, Clone)]
enum Body {
    None,
    Form(Vec<(String, String)>),
    Json(Value),
    Raw(Vec<u8>),
}

/// A request taken apart.
#[derive(Debug, Clone)]
pub struct Req {
    method: String,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    authority: String,
    /// The path without the query, as written (still percent-encoded).
    path: String,
    query: Option<Vec<(String, String)>>,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    body: Body,
}

pub(crate) fn clean_header(k: &str, v: &str) -> bool {
    let clean = |s: &str| !s.contains(['\r', '\n', '\0']);
    clean(k) && clean(v) && !k.is_empty() && !k.contains([':', ' '])
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn dec(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if b
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) =>
            {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(b'?'));
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (dec(k), dec(v))
        })
        .collect()
}

fn join_pairs(p: &[(String, String)]) -> String {
    p.iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn leaves(v: &Value, at: &str, out: &mut Vec<String>) {
    match v {
        Value::String(_) | Value::Number(_) => out.push(at.to_string()),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                leaves(x, &format!("{at}/{i}"), out);
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                leaves(
                    x,
                    &format!("{at}/{}", k.replace('~', "~0").replace('/', "~1")),
                    out,
                );
            }
        }
        _ => {}
    }
}

impl Req {
    pub fn from_target(t: &Target, extra: &[(String, String)]) -> Result<Self, ScanError> {
        let bad = |m: &str| ScanError::BadTarget(format!("{}: {m}", t.url));
        let u = bosun_crawl::parse_url(&t.url).ok_or_else(|| bad("not an absolute http or https URL"))?;
        let method = t
            .method
            .clone()
            .unwrap_or_else(|| "GET".into())
            .to_ascii_uppercase();
        if method.is_empty() || !method.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(bad("bad method"));
        }
        let (path, query) = match u.path.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(pairs(q))),
            None => (u.path.clone(), None),
        };
        let mut headers: Vec<(String, String)> = extra.to_vec();
        for (k, v) in &t.headers {
            if !clean_header(k, v) {
                return Err(bad("headers must be single lines"));
            }
            headers.retain(|(h, _)| !h.eq_ignore_ascii_case(k));
            headers.push((k.clone(), v.clone()));
        }
        let mut cookies = Vec::new();
        headers.retain(|(k, v)| {
            if k.eq_ignore_ascii_case("cookie") {
                for c in v.split(';') {
                    if let Some((n, val)) = c.trim().split_once('=') {
                        cookies.push((n.to_string(), val.to_string()));
                    }
                }
                false
            } else {
                !(k.eq_ignore_ascii_case("host")
                    || k.eq_ignore_ascii_case("content-length")
                    || k.eq_ignore_ascii_case("content-type"))
            }
        });
        let ct = t.content_type.clone().unwrap_or_default().to_ascii_lowercase();
        let body = match &t.body {
            None => Body::None,
            Some(b) if ct.starts_with("application/json") => {
                serde_json::from_str(b).map_or_else(|_| Body::Raw(b.clone().into_bytes()), Body::Json)
            }
            Some(b) if ct.is_empty() || ct.starts_with("application/x-www-form-urlencoded") => {
                Body::Form(pairs(b))
            }
            Some(b) => Body::Raw(b.clone().into_bytes()),
        };
        let raw_ct = match (&body, &t.content_type) {
            (_, Some(c)) => Some(c.clone()),
            (Body::Form(_), None) => Some("application/x-www-form-urlencoded".into()),
            _ => None,
        };
        if let Some(c) = raw_ct {
            if !clean_header("Content-Type", &c) {
                return Err(bad("bad content type"));
            }
            headers.push(("Content-Type".into(), c));
        }
        Ok(Self {
            method,
            scheme: u.scheme,
            host: u.host.clone(),
            port: u.port,
            authority: u.authority(),
            path,
            query,
            headers,
            cookies,
            body,
        })
    }

    /// The URL without a query, for reports and the refused list.
    pub fn base_url(&self) -> String {
        format!("{}://{}{}", self.scheme.as_str(), self.authority, self.path)
    }

    /// The insertion points this strength tests.
    pub fn points(&self, s: Strength) -> Vec<Point> {
        let mut out = Vec::new();
        if let Some(q) = &self.query {
            out.extend((0..q.len()).map(Point::Query));
        }
        match &self.body {
            Body::Form(f) => out.extend((0..f.len()).map(Point::Form)),
            Body::Json(v) => {
                let mut l = Vec::new();
                leaves(v, "", &mut l);
                out.extend(l.into_iter().map(Point::Json));
            }
            _ => {}
        }
        if s != Strength::Low {
            out.extend((0..self.cookies.len()).map(Point::Cookie));
            let seg = self.path.rsplit('/').next().unwrap_or("");
            if !seg.is_empty() && self.path.matches('/').count() >= 2 {
                out.push(Point::Path);
            }
        }
        if s == Strength::High {
            out.push(Point::Header("User-Agent".into()));
            out.push(Point::Header("Referer".into()));
        }
        out.truncate(MAX_POINTS);
        out
    }

    /// The value now at `p`.
    pub fn value(&self, p: &Point) -> String {
        match p {
            Point::Query(i) => self.query.as_ref().and_then(|q| q.get(*i)).map(|x| x.1.clone()),
            Point::Form(i) => match &self.body {
                Body::Form(f) => f.get(*i).map(|x| x.1.clone()),
                _ => None,
            },
            Point::Json(ptr) => match &self.body {
                Body::Json(v) => v.pointer(ptr).map(|x| match x {
                    Value::String(s) => s.clone(),
                    o => o.to_string(),
                }),
                _ => None,
            },
            Point::Cookie(i) => self.cookies.get(*i).map(|x| x.1.clone()),
            Point::Header(h) => self
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(h))
                .map(|x| x.1.clone()),
            Point::Path => self.path.rsplit('/').next().map(dec),
            Point::Whole => None,
        }
        .unwrap_or_default()
    }

    /// A readable name, e.g. `query:q`.
    pub fn label(&self, p: &Point) -> String {
        match p {
            Point::Query(i) => format!(
                "query:{}",
                self.query.as_ref().and_then(|q| q.get(*i)).map_or("", |x| &x.0)
            ),
            Point::Form(i) => format!(
                "form:{}",
                match &self.body {
                    Body::Form(f) => f.get(*i).map_or("", |x| &x.0),
                    _ => "",
                }
            ),
            Point::Json(ptr) => format!("json:{ptr}"),
            Point::Cookie(i) => format!("cookie:{}", self.cookies.get(*i).map_or("", |x| &x.0)),
            Point::Header(h) => format!("header:{h}"),
            Point::Path => "path:last-segment".into(),
            Point::Whole => "request".into(),
        }
    }

    /// The request as bytes with `value` at `p` (`None` is the request unchanged).
    pub fn bytes(&self, at: Option<(&Point, &str)>) -> Vec<u8> {
        let mut path = self.path.clone();
        let mut query = self.query.clone();
        let mut headers = self.headers.clone();
        let mut cookies = self.cookies.clone();
        let mut body = self.body.clone();
        if let Some((p, v)) = at {
            match p {
                Point::Query(i) => {
                    if let Some(x) = query.as_mut().and_then(|q| q.get_mut(*i)) {
                        x.1 = v.into();
                    }
                }
                Point::Form(i) => {
                    if let Body::Form(f) = &mut body
                        && let Some(x) = f.get_mut(*i)
                    {
                        x.1 = v.into();
                    }
                }
                Point::Json(ptr) => {
                    if let Body::Json(j) = &mut body
                        && let Some(x) = j.pointer_mut(ptr)
                    {
                        *x = Value::String(v.into());
                    }
                }
                Point::Cookie(i) => {
                    if let Some(x) = cookies.get_mut(*i) {
                        // A cookie value may not hold `;` or whitespace to stay one cookie.
                        x.1 = v.replace(';', "%3B");
                    }
                }
                Point::Header(h) => {
                    let v = v.replace(['\r', '\n'], "");
                    match headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(h)) {
                        Some(x) => x.1 = v,
                        None => headers.push((h.clone(), v)),
                    }
                }
                Point::Path => {
                    if let Some((head, _)) = path.rsplit_once('/') {
                        path = format!("{head}/{}", enc(v));
                    }
                }
                Point::Whole => {}
            }
        }
        let body_bytes: Vec<u8> = match &body {
            Body::None => Vec::new(),
            Body::Form(f) => join_pairs(f).into_bytes(),
            Body::Json(j) => j.to_string().into_bytes(),
            Body::Raw(r) => r.clone(),
        };
        let target = match &query {
            Some(q) => format!("{path}?{}", join_pairs(q)),
            None => path,
        };
        let mut out = format!(
            "{} {target} HTTP/1.1\r\nHost: {}\r\n",
            self.method, self.authority
        );
        for (k, v) in &headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("user-agent")) {
            out.push_str("User-Agent: bosun-active\r\n");
        }
        if !cookies.is_empty() {
            let c: Vec<String> = cookies.iter().map(|(k, v)| format!("{k}={v}")).collect();
            out.push_str(&format!("Cookie: {}\r\n", c.join("; ")));
        }
        out.push_str("Accept-Encoding: identity\r\nConnection: close\r\n");
        if !matches!(body, Body::None) {
            out.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
        }
        out.push_str("\r\n");
        let mut b = out.into_bytes();
        b.extend_from_slice(&body_bytes);
        b
    }

    /// This request as a plain `GET` of the same path without query or body (or of `path` when given): how the
    /// stored-XSS check reads a page back without sending the payload again.
    pub fn page(&self, path: Option<&str>) -> Req {
        let mut r = self.clone();
        r.method = "GET".into();
        r.body = Body::None;
        r.query = None;
        r.headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("content-type") && !k.eq_ignore_ascii_case("origin"));
        if let Some(p) = path {
            r.path = p.to_string();
        }
        r
    }

    /// The request unchanged, but with `host` as the `Host` header (the connection still goes to the target's own
    /// address) and `extra` headers added right after it.
    pub fn bytes_with(&self, host: Option<&str>, extra: &[(&str, &str)]) -> Vec<u8> {
        let b = self.bytes(None);
        let text_end = b
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(b.len(), |p| p + 2);
        let head = String::from_utf8_lossy(&b[..text_end]).into_owned();
        let mut out = String::new();
        for (i, line) in head.split("\r\n").filter(|l| !l.is_empty()).enumerate() {
            if i == 1 {
                out.push_str(&format!("Host: {}\r\n", host.unwrap_or(&self.authority)));
                for (k, v) in extra {
                    if clean_header(k, v) {
                        out.push_str(&format!("{k}: {v}\r\n"));
                    }
                }
            } else {
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
        let mut res = out.into_bytes();
        res.extend_from_slice(&b[text_end..]);
        res
    }
}
