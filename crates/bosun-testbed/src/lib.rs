//! The testbed: a tiny HTTP server with planted vulnerabilities and matching safe twins, so tests of the crawler and
//! the active scanner have exact answers. It holds no data.
//!
//! Planted (the scanner must find these):
//! - `GET /search?q=` reflects `q` into HTML unescaped (reflected XSS);
//! - `GET /item?id=` answers a database error page when `id` holds a quote (SQL injection, error based);
//! - `POST /comment` (form field `text`) and `POST /api/echo` (JSON `{"name": ...}`) reflect unescaped;
//! - `GET /prefs` reflects the `theme` cookie unescaped;
//! - `GET /files/<name>` reflects the last path segment unescaped;
//! - `GET /user?id=` evaluates `AND a=b` conditions in the id (SQL injection, boolean blind);
//! - `GET /report?id=` sleeps for `SLEEP(n)`, `pg_sleep(n)` or `WAITFOR DELAY '0:0:n'` in the id (SQL injection, time);
//! - `GET`/`POST /guestbook` (form field `msg`) stores unescaped and lists everything (stored XSS);
//! - `GET /render?name=` evaluates `{{a*b}}` and `${a*b}` (template injection);
//! - `GET /ping?host=` runs `;`, `|`, `&` and `$(..)` commands, `echo` and `sleep` (OS command injection); and `/ping-blind` runs them but prints nothing (only the delay shows);
//! - `GET /download?file=` reads from a virtual file system without checking `..` (path traversal);
//! - `GET /go?url=` redirects anywhere (open redirect);
//! - `GET /lang?set=` writes the value into a `Set-Cookie` header as it is (CRLF injection);
//! - `GET /api/profile` reflects `Origin` and allows credentials (CORS);
//! - `GET /reset` builds a link from `X-Forwarded-Host` or `Host` (Host header attack).
//!
//! Safe twins (the scanner must stay quiet): `GET /greet?name=` escapes, `GET /safe?id=` never errors, and
//! `/user-safe`, `/report-safe`, `/notes`, `/render-safe`, `/ping-safe`, `/download-safe`, `/go-safe`, `/lang-safe`,
//! `/api/profile-safe` (allow list), `/api/public` (`*` without credentials) and `/reset-safe`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    let state: Arc<State> = Arc::default();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(conn(s, log.clone(), external.clone(), state.clone()));
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

/// What the testbed remembers between requests: the two guest books.
#[derive(Default)]
struct State {
    guestbook: Mutex<Vec<String>>,
    notes: Mutex<Vec<String>>,
}

struct Reply {
    status: u16,
    ct: &'static str,
    body: String,
    /// Extra header lines, written as they are (so a value with a line break splits the response).
    headers: Vec<String>,
    delay: Duration,
}

impl Reply {
    fn new(status: u16, ct: &'static str, body: impl Into<String>) -> Self {
        Self {
            status,
            ct,
            body: body.into(),
            headers: Vec::new(),
            delay: Duration::ZERO,
        }
    }

    fn header(mut self, line: impl Into<String>) -> Self {
        self.headers.push(line.into());
        self
    }
}

fn html(body: &str) -> Reply {
    Reply::new(200, "text/html", format!("<html><body>{body}</body></html>"))
}

struct Rq<'a> {
    method: &'a str,
    target: &'a str,
    headers: &'a [(String, String)],
    body: &'a str,
}

impl Rq<'_> {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map_or("", |(_, v)| v)
    }
}

/// `a=b` conditions joined by AND after a number, as a query `WHERE id = <id>` would evaluate them. `None` when the
/// text is not valid SQL for it.
fn sql_true(id: &str) -> Option<bool> {
    let id = id.split("-- ").next().unwrap_or(id);
    let mut parts = id.split(" AND ");
    let first = parts.next()?.trim().trim_end_matches(['\'', '"']);
    first.parse::<u32>().ok()?;
    let mut ok = true;
    for c in parts {
        let (l, r) = c.split_once('=')?;
        let q = |x: &str| x.trim().trim_matches(['\'', '"']).to_string();
        ok &= q(l) == q(r);
    }
    Some(ok)
}

/// `a*b` of two whole numbers (empty when it is anything else).
fn arith(e: &str) -> String {
    match e.split_once('*') {
        Some((a, b)) => match (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
            (Ok(a), Ok(b)) => (a * b).to_string(),
            _ => String::new(),
        },
        None => String::new(),
    }
}

/// Replace `{{a*b}}` and `${a*b}` with the product, like a template engine that is handed the user's text.
fn template(s: &str) -> String {
    let mut out = s.to_string();
    for (open, close) in [("{{", "}}"), ("${", "}")] {
        while let Some(i) = out.find(open) {
            let Some(j) = out[i + open.len()..].find(close) else {
                break;
            };
            let inner = out[i + open.len()..i + open.len() + j].to_string();
            let r = arith(&inner);
            if r.is_empty() {
                break;
            }
            out.replace_range(i..i + open.len() + j + close.len(), &r);
        }
    }
    out
}

/// A pretend shell: expands `$((a*b))` and `$(cmd)`, runs `echo` and `sleep` (the sleeps add up in `delay`).
fn expand(s: &str, delay: &mut u64) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        if rest.starts_with("$((")
            && let Some(j) = rest.find("))")
        {
            out.push_str(&arith(&rest[3..j]));
            i += j + 2;
        } else if rest.starts_with("$(") {
            let mut depth = 0;
            let mut end = None;
            for (k, c) in rest.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(k);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(end) = end else { break };
            out.push_str(&run(&rest[2..end], delay));
            i += end + 1;
        } else {
            let c = rest.chars().next().unwrap_or(' ');
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

fn run(cmd: &str, delay: &mut u64) -> String {
    let cmd = expand(cmd.trim(), delay);
    if let Some(a) = cmd.strip_prefix("echo ") {
        a.trim().to_string()
    } else if let Some(n) = cmd.strip_prefix("sleep ") {
        *delay += n.trim().parse::<u64>().unwrap_or(0).min(10);
        String::new()
    } else {
        String::new()
    }
}

/// The virtual file system `/download` reads: the directory it serves, and a system file.
fn read_file(base: &str, name: &str) -> Option<&'static str> {
    let full = if name.starts_with('/') {
        name.to_string()
    } else {
        format!("{base}/{name}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for p in full.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    match parts.join("/").as_str() {
        "var/www/docs/report.txt" => Some("Quarterly report\n"),
        "var/www/docs/notes.txt" => Some("Meeting notes\n"),
        "etc/passwd" => {
            Some("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
        }
        _ => None,
    }
}

fn user(id: &str, eval: fn(&str) -> Option<bool>) -> Reply {
    // The page never repeats the id, so it changes only with the condition.
    match eval(id) {
        Some(true) if id.trim_start().starts_with('1') => html("User: alice"),
        _ => html("No such user"),
    }
}

fn download(content: Option<&'static str>) -> Reply {
    match content {
        Some(c) => Reply::new(200, "text/plain", c),
        None => Reply::new(404, "text/plain", "no such file"),
    }
}

fn guestbook(store: &Mutex<Vec<String>>, method: &str, body: &str, show: fn(&str) -> String) -> Reply {
    let mut g = store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if method == "POST" {
        g.push(param(body, "msg"));
        return html("Saved");
    }
    let items: String = g.iter().map(|m| format!("<li>{}</li>", show(m))).collect();
    html(&format!("<ul>{items}</ul>"))
}

fn sleep_secs(id: &str) -> u64 {
    let id = id.to_ascii_lowercase();
    let digits = |r: &str| r.chars().take_while(char::is_ascii_digit).collect::<String>();
    id.split_once("sleep(")
        .map(|(_, r)| digits(r))
        .or_else(|| id.split_once("delay '0:0:").map(|(_, r)| digits(r)))
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0)
        .min(10)
}

fn ping(host: &str) -> Reply {
    let mut delay = 0;
    let mut segs = host.split([';', '|', '&', '\n']);
    let mut out = format!("PING {}\n", expand(segs.next().unwrap_or(""), &mut delay));
    for c in segs {
        let o = run(c, &mut delay);
        if !o.is_empty() {
            out.push_str(&o);
            out.push('\n');
        }
    }
    let mut r = html(&format!("<pre>{}</pre>", escape(&out)));
    r.delay = Duration::from_secs(delay);
    r
}

fn route(rq: &Rq<'_>, st: &State, external: Option<&str>) -> Reply {
    let (method, body) = (rq.method, rq.body);
    let cookie = rq.header("cookie");
    let (path, query) = rq.target.split_once('?').unwrap_or((rq.target, ""));
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
                Reply::new(
                    500,
                    "text/html",
                    "<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL \
                     server version for the right syntax to use near ''' at line 1</html>",
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

        ("GET", "/user") => user(&param(query, "id"), sql_true),
        ("GET", "/user-safe") => {
            let id: String = param(query, "id")
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            user(&id, |i| i.parse::<u32>().ok().map(|_| true))
        }
        ("GET", "/report") => {
            let mut r = html("Report 1");
            r.delay = Duration::from_secs(sleep_secs(&param(query, "id")));
            r
        }
        ("GET", "/report-safe") => html("Report 1"),
        ("GET" | "POST", "/guestbook") => guestbook(&st.guestbook, method, body, ToString::to_string),
        ("GET" | "POST", "/notes") => guestbook(&st.notes, method, body, escape),
        ("GET", "/render") => html(&format!("Hello {}", escape(&template(&param(query, "name"))))),
        ("GET", "/render-safe") => html(&format!("Hello {}", escape(&param(query, "name")))),
        ("GET", "/ping") => ping(&param(query, "host")),
        ("GET", "/ping-blind") => {
            // Runs the command but shows nothing of it.
            let mut r = html("queued");
            r.delay = ping(&param(query, "host")).delay;
            r
        }
        ("GET", "/ping-safe") => {
            let host = param(query, "host");
            if !host.is_empty()
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                html(&format!("<pre>PING {host}</pre>"))
            } else {
                Reply::new(400, "text/html", "<html>invalid host</html>")
            }
        }
        ("GET", "/download") => download(read_file("/var/www/docs", &param(query, "file"))),
        ("GET", "/download-safe") => {
            let f = param(query, "file");
            let listed = ["report.txt", "notes.txt"].contains(&f.as_str());
            download(read_file("/var/www/docs", &f).filter(|_| listed))
        }
        ("GET", "/go") => Reply::new(302, "text/html", "").header(format!(
            "Location: {}",
            param(query, "url").replace(['\r', '\n'], "")
        )),
        ("GET", "/go-safe") => {
            let u = param(query, "url");
            let ok = u.starts_with('/') && !u.starts_with("//") && !u.contains(['\\', '\r', '\n']);
            Reply::new(302, "text/html", "").header(format!("Location: {}", if ok { u } else { "/".into() }))
        }
        ("GET", "/lang") => html("ok").header(format!("Set-Cookie: lang={}", param(query, "set"))),
        ("GET", "/lang-safe") => html("ok").header(format!(
            "Set-Cookie: lang={}",
            param(query, "set").replace(['\r', '\n'], "")
        )),
        ("GET", "/api/profile") => {
            let o = rq.header("origin");
            let mut r = Reply::new(200, "application/json", "{\"user\":\"alice\"}");
            if !o.is_empty() {
                r = r
                    .header(format!("Access-Control-Allow-Origin: {o}"))
                    .header("Access-Control-Allow-Credentials: true");
            }
            r
        }
        ("GET", "/api/profile-safe") => {
            let mut r = Reply::new(200, "application/json", "{\"user\":\"alice\"}");
            if rq.header("origin") == "https://app.example" {
                r = r
                    .header("Access-Control-Allow-Origin: https://app.example")
                    .header("Access-Control-Allow-Credentials: true");
            }
            r
        }
        ("GET", "/api/public") => {
            Reply::new(200, "application/json", "{\"build\":\"1\"}").header("Access-Control-Allow-Origin: *")
        }
        ("GET", "/reset") => {
            let fwd = rq.header("x-forwarded-host");
            let host = if fwd.is_empty() { rq.header("host") } else { fwd };
            html(&format!(
                "<a href=\"http://{}/reset/confirm?token=abc123\">Reset your password</a>",
                escape(host)
            ))
        }
        ("GET", "/reset-safe") => {
            html("<a href=\"https://testbed.example/reset/confirm?token=abc123\">Reset your password</a>")
        }
        _ => Reply::new(404, "text/html", "not found"),
    }
}

async fn conn(
    mut s: tokio::net::TcpStream,
    log: Arc<Mutex<Vec<String>>>,
    external: Option<String>,
    st: Arc<State>,
) {
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
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_string(), v.trim().to_string()))
        .collect();
    let want: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0)
        .min(1 << 20);
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
    let rq = Rq {
        method,
        target,
        headers: &headers,
        body: &body,
    };
    let r = route(&rq, &st, external.as_deref());
    if !r.delay.is_zero() {
        tokio::time::sleep(r.delay).await;
    }
    let extra: String = r.headers.iter().map(|h| format!("{h}\r\n")).collect();
    let reply = format!(
        "HTTP/1.1 {} X\r\nContent-Type: {}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        r.status,
        r.ct,
        r.body.len(),
        r.body
    );
    let _ = s.write_all(reply.as_bytes()).await;
    let _ = s.shutdown().await;
}
