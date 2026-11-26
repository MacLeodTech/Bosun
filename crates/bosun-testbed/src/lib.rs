//! The testbed: a tiny HTTP server with planted vulnerabilities and matching safe twins, so tests of the crawler and
//! the active scanner have exact answers. It holds no data.
//!
//! Planted (the scanner must find these):
//! - `GET /search?q=` reflects `q` into HTML unescaped (reflected XSS);
//! - `GET /item?id=` answers a database error page when `id` holds a quote (SQL injection, error based);
//! - `POST /comment` (form field `text`) and `POST /api/echo` (JSON `{"name": ...}`) reflect unescaped;
//! - `GET /prefs` reflects the `theme` cookie unescaped;
//! - `GET /files/<name>` reflects the last path segment unescaped.
//!
//! Safe twins (the scanner must stay quiet): `GET /greet?name=` escapes, `GET /safe?id=` never errors.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// What a running testbed lets the test see.
#[derive(Clone)]
pub struct Testbed {
    pub addr: SocketAddr,
    hits: Arc<Mutex<Vec<String>>>,
}

impl Testbed {
    /// Every request line the server has seen, `METHOD target`, in order.
    pub fn hits(&self) -> Vec<String> {
        self.hits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Start the testbed on `bind` (use `127.0.0.1:0` for a free port). `external` is a URL the home page links to,
/// for testing that a crawl or scan does not leave the scope.
pub async fn start(bind: &str, external: Option<String>) -> std::io::Result<Testbed> {
    let l = TcpListener::bind(bind).await?;
    let addr = l.local_addr()?;
    let hits: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(conn(s, log.clone(), external.clone()));
        }
    });
    Ok(Testbed { addr, hits })
}

fn decode(s: &str) -> String {
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

fn param(q: &str, name: &str) -> String {
    q.split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| decode(k) == name)
        .map(|(_, v)| decode(v))
        .unwrap_or_default()
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Pull `"name":"value"` out of a flat JSON object (enough for the testbed; only `\"` and `\\` are unescaped).
fn json_name(body: &str) -> String {
    let Some((_, r)) = body.split_once("\"name\"") else {
        return String::new();
    };
    let Some((_, r)) = r.split_once('"') else {
        return String::new();
    };
    let mut out = String::new();
    let mut it = r.chars();
    while let Some(c) = it.next() {
        match c {
            '"' => break,
            '\\' => out.extend(it.next()),
            c => out.push(c),
        }
    }
    out
}

type Reply = (u16, &'static str, String);

fn html(body: &str) -> Reply {
    (200, "text/html", format!("<html><body>{body}</body></html>"))
}

fn route(method: &str, target: &str, cookie: &str, body: &str, external: Option<&str>) -> Reply {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match (method, path) {
        ("GET", "/") => html(&format!(
            "<title>Testbed</title><a href=\"/search?q=boat\">search</a><a href=\"/item?id=1\">item</a>\
             <a href=\"/greet?name=sam\">greet</a><a href=\"/safe?id=1\">safe</a><a href=\"/prefs\">prefs</a>\
             <a href=\"/files/readme.txt\">file</a><a href=\"/about\">about</a>{}\
             <form action=\"/comment\" method=\"post\"><input name=\"text\" value=\"hi\"></form>",
            external.map_or(String::new(), |e| format!(
                "<a href=\"{e}/outside\">elsewhere</a>"
            ))
        )),
        ("GET", "/about") => html("<a href=\"/\">home</a><a href=\"/about/team\">team</a>"),
        ("GET", "/about/team") => html("the crew"),
        ("GET", "/search") => html(&format!("Results for {}", param(query, "q"))),
        ("GET", "/greet") => html(&format!("Hello {}", escape(&param(query, "name")))),
        ("GET", "/item") => {
            // An odd number of quotes breaks the "query"; a doubled quote is an escaped quote and does not.
            let id = param(query, "id");
            if id.matches('\'').count() % 2 == 1 || id.matches('"').count() % 2 == 1 {
                (
                    500,
                    "text/html",
                    "<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL \
                     server version for the right syntax to use near ''' at line 1</html>"
                        .into(),
                )
            } else {
                html(&format!("Item {}", escape(&param(query, "id"))))
            }
        }
        ("GET", "/safe") => html(&format!("Item {}", escape(&param(query, "id")))),
        ("GET", "/prefs") => {
            let theme = cookie
                .split(';')
                .filter_map(|c| c.trim().split_once('='))
                .find(|(k, _)| *k == "theme")
                .map_or("light", |(_, v)| v);
            html(&format!("Theme: {theme}"))
        }
        ("GET", p) if p.starts_with("/files/") => html(&format!("File {}", decode(&p[7..]))),
        ("POST", "/comment") => html(&format!("Thanks: {}", param(body, "text"))),
        ("POST", "/api/echo") => html(&format!("Hello {}", json_name(body))),
        _ => (404, "text/html", "not found".into()),
    }
}

async fn conn(mut s: tokio::net::TcpStream, log: Arc<Mutex<Vec<String>>>, external: Option<String>) {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        if let Some(p) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if got.len() > 64 * 1024 {
            return;
        }
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    };
    let head = String::from_utf8_lossy(&got[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, target) = (first.next().unwrap_or(""), first.next().unwrap_or("/"));
    let header = |name: &str| {
        lines
            .clone()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    let want: usize = header("content-length").parse().unwrap_or(0).min(1 << 20);
    while got.len() < head_end + want {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    let body = String::from_utf8_lossy(&got[head_end..]).into_owned();
    log.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(format!("{method} {target}"));
    let (status, ct, out) = route(method, target, &header("cookie"), &body, external.as_deref());
    let reply = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
        out.len()
    );
    let _ = s.write_all(reply.as_bytes()).await;
    let _ = s.shutdown().await;
}
