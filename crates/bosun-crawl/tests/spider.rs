#![allow(clippy::unwrap_used)]
//! The spider against a local site: every linked page is found, nothing outside the scope is requested, and
//! robots, sitemaps, forms, depth, the page limit, the rate limit and the stop switch behave.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bosun_crawl::{Options, Report, Sink, Stop, crawl};
use bosun_http::{Engine, Exchange};
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, RuleSpec, Scope, ScopeSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type Hits = Arc<Mutex<Vec<String>>>;

/// `(status, content type, extra headers, body)` for a request line `METHOD target`.
fn site(port: u16, other: u16, req: &str) -> (u16, &'static str, String, String) {
    let html = "text/html";
    let page = |b: &str| (200, html, String::new(), b.to_string());
    match req {
        "GET /" => page(&format!(
            "<title>Home</title><a href=/a>a</a><a href='b/c.html'>c</a><a href=\"/a#frag\">dup</a>\
             <a href=mailto:x@y>m</a><a href=\"http://127.0.0.1:{other}/outside\">out</a>\
             <a href=\"http://localhost:{port}/other-host\">name</a><script src=/app.js></script>\
             <a href=/old>old</a><a href=/secret>s</a><a href=/chunked>ch</a>\
             <form action=/search><input name=q value=hello><input type=submit></form>\
             <form action=/post method=post><input name=p value=1></form>"
        )),
        "GET /a" => page("<a href=/a/deep>deep</a><a href=/>home</a>"),
        "GET /a/deep" => page("<a href=/a/deeper>deeper</a>"),
        "GET /a/deeper" => page("the end"),
        "GET /b/c.html" => page("<a href=../a>up</a><a href=d.html>d</a>"),
        "GET /b/d.html" => page("leaf"),
        "GET /app.js" => (
            200,
            "application/javascript",
            String::new(),
            "var a='<a href=/nope>'".into(),
        ),
        "GET /old" => (301, html, "Location: /new\r\n".into(), String::new()),
        "GET /new" => page("moved here"),
        "GET /chunked" => (200, html, "Transfer-Encoding: chunked\r\n".into(), "chunk".into()),
        "GET /search?q=hello" => page("results <a href=/found-by-form>f</a>"),
        "GET /found-by-form" => page("form result"),
        "GET /only-in-sitemap" => page("<a href=/from-sitemap-page>x</a>"),
        "GET /from-sitemap-page" => page("deeper"),
        "GET /secret" => page("secret"),
        "GET /private/x" => page("private"),
        "GET /robots.txt" => (
            200,
            "text/plain",
            String::new(),
            format!(
                "User-agent: *\nDisallow: /secret\nDisallow: /private/\nSitemap: http://127.0.0.1:{port}/sitemap.xml\n"
            ),
        ),
        "GET /sitemap.xml" => (
            200,
            "application/xml",
            String::new(),
            format!("<urlset><url><loc>http://127.0.0.1:{port}/only-in-sitemap</loc></url></urlset>"),
        ),
        _ => (404, html, String::new(), "not found".into()),
    }
}

async fn serve(other: Option<u16>) -> (SocketAddr, Hits) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits: Hits = Arc::default();
    let log = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let log = log.clone();
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&got).to_string();
                let mut it = text.split(' ');
                let req = format!("{} {}", it.next().unwrap_or(""), it.next().unwrap_or(""));
                log.lock().unwrap().push(req.clone());
                let (status, ct, extra, body) = match other {
                    Some(o) => site(addr.port(), o, &req),
                    // The second server: anything it is asked is a leak.
                    None => (200, "text/html", String::new(), "outside".into()),
                };
                let framed = if extra.contains("chunked") {
                    format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len())
                } else {
                    body
                };
                let len = if extra.contains("chunked") {
                    String::new()
                } else {
                    format!("Content-Length: {}\r\n", framed.len())
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: {ct}\r\n{extra}{len}Connection: close\r\n\r\n{framed}"
                );
                let _ = s.write_all(reply.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (addr, hits)
}

fn engine(port: u16) -> Engine {
    let rule = RuleSpec {
        scheme: None,
        host: "127.0.0.1".into(),
        port: Some(port),
        path: None,
        allow_private: true,
    };
    let scope = Scope::compile(ScopeSpec {
        include: vec![rule],
        exclude: vec![],
    })
    .unwrap();
    Engine::new(Gate::new(scope), MemoryBudget::new(64 << 20))
}

fn opts(port: u16) -> Options {
    Options {
        start: vec![format!("http://127.0.0.1:{port}/")],
        ..Options::default()
    }
}

fn urls(r: &Report) -> Vec<String> {
    let mut v: Vec<String> = r
        .pages
        .iter()
        .map(|p| {
            let rest = p.url.split_once("://").map_or(p.url.as_str(), |x| x.1);
            rest.find('/').map_or(String::new(), |i| rest[i..].to_string())
        })
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn finds_every_linked_page_and_never_leaves_scope() {
    let (outside, outside_hits) = serve(None).await;
    let (addr, hits) = serve(Some(outside.port())).await;
    let r = crawl(&engine(addr.port()), &opts(addr.port()), &(), &Stop::new())
        .await
        .unwrap();

    let got = urls(&r);
    for want in [
        "/",
        "/a",
        "/a/deep",
        "/a/deeper",
        "/b/c.html",
        "/b/d.html",
        "/app.js",
        "/old",
        "/new",
        "/chunked",
        "/search?q=hello",
        "/found-by-form",
        "/only-in-sitemap",
        "/from-sitemap-page",
    ] {
        assert!(got.contains(&want.to_string()), "missing {want} in {got:?}");
    }
    // The fragment duplicate, mailto and the script's string are not pages; robots-blocked ones are not fetched.
    assert!(
        !got.iter()
            .any(|u| u == "/nope" || u == "/secret" || u.starts_with("/post"))
    );
    assert_eq!(got.iter().filter(|u| *u == "/a").count(), 1);
    assert_eq!(r.robots_blocked.len(), 1);
    assert!(r.robots_blocked[0].ends_with("/secret"));
    assert!(r.robots_paths.iter().any(|p| p.ends_with("/private/")));
    assert_eq!(r.sitemap_urls.len(), 1);
    assert!(r.pages.iter().any(|p| p.title.as_deref() == Some("Home")));
    let chunked = r.pages.iter().find(|p| p.url.ends_with("/chunked")).unwrap();
    assert_eq!(chunked.bytes, 5);
    let old = r.pages.iter().find(|p| p.url.ends_with("/old")).unwrap();
    assert_eq!(old.status, Some(301));
    assert!(old.location.as_deref().unwrap().ends_with("/new"));
    // Forms are listed; the POST one was not sent.
    assert_eq!(r.forms.len(), 2);
    assert!(!hits.lock().unwrap().iter().any(|h| h.starts_with("POST")));

    // Nothing outside the scope was requested, by port or by name.
    assert!(outside_hits.lock().unwrap().is_empty());
    assert!(!hits.lock().unwrap().iter().any(|h| h.contains("other-host")));
    assert!(
        r.out_of_scope
            .iter()
            .any(|u| u.contains(&format!(":{}/outside", outside.port())))
    );
    assert!(r.out_of_scope.iter().any(|u| u.contains("localhost")));
    assert!(!r.stopped && !r.truncated);
}

#[tokio::test]
async fn depth_page_limit_and_robots_option() {
    let (outside, _) = serve(None).await;
    let (addr, hits) = serve(Some(outside.port())).await;
    let e = engine(addr.port());

    let o = Options {
        max_depth: 1,
        use_sitemap: false,
        ..opts(addr.port())
    };
    let got = urls(&crawl(&e, &o, &(), &Stop::new()).await.unwrap());
    assert!(got.contains(&"/a".to_string()) && !got.contains(&"/a/deep".to_string()));

    let o = Options {
        max_depth: 0,
        use_sitemap: false,
        ..opts(addr.port())
    };
    assert_eq!(crawl(&e, &o, &(), &Stop::new()).await.unwrap().pages.len(), 1);

    let o = Options {
        max_pages: 3,
        ..opts(addr.port())
    };
    let r = crawl(&e, &o, &(), &Stop::new()).await.unwrap();
    assert_eq!(r.pages.len(), 3);
    assert!(r.truncated);

    let o = Options {
        respect_robots: false,
        ..opts(addr.port())
    };
    let r = crawl(&e, &o, &(), &Stop::new()).await.unwrap();
    assert!(urls(&r).contains(&"/secret".to_string()));
    assert!(hits.lock().unwrap().iter().any(|h| h == "GET /secret"));
}

#[tokio::test]
async fn posts_forms_only_when_asked() {
    let (outside, _) = serve(None).await;
    let (addr, hits) = serve(Some(outside.port())).await;
    let o = Options {
        submit_post_forms: true,
        max_depth: 1,
        ..opts(addr.port())
    };
    let r = crawl(&engine(addr.port()), &o, &(), &Stop::new()).await.unwrap();
    assert!(hits.lock().unwrap().iter().any(|h| h == "POST /post"));
    assert!(r.pages.iter().any(|p| p.method == "POST"));
}

#[derive(Default)]
struct Flows(Mutex<HashMap<String, usize>>);
impl Sink for Flows {
    fn exchange(&self, ex: &Exchange) {
        let (_, path, _) = bosun_http_request_line(&ex.request);
        *self.0.lock().unwrap().entry(path).or_default() += 1;
    }
}
fn bosun_http_request_line(raw: &[u8]) -> (String, String, String) {
    let line = String::from_utf8_lossy(raw);
    let mut p = line.lines().next().unwrap_or("").split(' ');
    (
        p.next().unwrap_or("").into(),
        p.next().unwrap_or("").into(),
        p.next().unwrap_or("").into(),
    )
}

#[tokio::test]
async fn reports_every_exchange_and_obeys_the_gate_limits() {
    let (outside, _) = serve(None).await;
    let (addr, _) = serve(Some(outside.port())).await;
    let e = engine(addr.port());
    let flows = Flows::default();
    let r = crawl(&e, &opts(addr.port()), &flows, &Stop::new()).await.unwrap();
    // Pages, plus robots.txt and the sitemap.
    assert_eq!(flows.0.lock().unwrap().values().sum::<usize>() as u64, r.requests);
    assert!(flows.0.lock().unwrap().contains_key("/robots.txt"));

    // The rate limit slows the crawl down rather than failing it.
    e.gate().set_rate_limit(50);
    let o = Options {
        max_depth: 1,
        use_sitemap: false,
        ..opts(addr.port())
    };
    let r = crawl(&e, &o, &(), &Stop::new()).await.unwrap();
    assert!(r.pages.len() > 5 && r.pages.iter().all(|p| p.error.is_none()));
    e.gate().set_rate_limit(0);

    // The kill switch ends it.
    e.gate().set_stopped(true);
    let r = crawl(&e, &opts(addr.port()), &(), &Stop::new()).await.unwrap();
    assert!(r.stopped && r.pages.is_empty());
    e.gate().set_stopped(false);

    // So does the crawl's own stop.
    let stop = Stop::new();
    stop.stop();
    assert!(crawl(&e, &opts(addr.port()), &(), &stop).await.unwrap().stopped);
}

#[tokio::test]
async fn an_empty_scope_refuses_everything() {
    let (outside, _) = serve(None).await;
    let (addr, hits) = serve(Some(outside.port())).await;
    let e = Engine::new(Gate::default(), MemoryBudget::new(1 << 20));
    let r = crawl(&e, &opts(addr.port()), &(), &Stop::new()).await.unwrap();
    assert!(r.pages.is_empty() && !r.out_of_scope.is_empty());
    assert!(hits.lock().unwrap().is_empty());
}
