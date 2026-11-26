//! The spider reads HTML, robots.txt and sitemaps from the target: none of it may panic or hang.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let doc = bosun_crawl::scan(&text);
    if let Some(base) = bosun_crawl::parse_url("http://h.test/a/b?x=1") {
        for l in &doc.links {
            let _ = bosun_crawl::join(&base, &l.target);
        }
    }
    let _ = bosun_crawl::sitemap_locs(&text);
    let r = bosun_crawl::Robots::parse(&text);
    let _ = r.allowed("/a/b.pdf?x=1");
    let _ = r.disallowed_paths();
});
