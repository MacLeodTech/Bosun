//! The engagement scanners and the CSRF page builder on arbitrary text: no panic, bounded results, offsets inside the
//! text, and a proof of concept that holds no markup of its own besides the tags the builder writes.
#![no_main]
use bosun_codec::engage::{MAX_FINDINGS, PocInput, csrf_poc, find_in_html, find_urls, parameters};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [sel, rest @ ..] = data else { return };
    let text = String::from_utf8_lossy(rest);
    for f in find_in_html(&text).into_iter().chain(find_urls(&text)) {
        assert!(f.offset <= text.len());
    }
    assert!(find_in_html(&text).len() <= MAX_FINDINGS);
    let ct = ["application/x-www-form-urlencoded", "application/json", "multipart/form-data; boundary=XX", "text/plain"][usize::from(*sel) % 4];
    let _ = parameters(&text, Some(ct), rest);
    let method = if sel & 4 == 0 { "POST" } else { "GET" };
    if let Ok(html) = csrf_poc(&PocInput { method, url: "https://t.test/p?a=1", content_type: Some(ct), body: rest, auto_submit: sel & 8 != 0 }) {
        // Nothing from the request may open a tag: every '<' is one of ours.
        let ours = ["<!doctype", "<meta", "<title>", "</title>", "<!--", "<h1>", "</h1>", "<p>", "</p>", "<form ", "</form>", "<input ", "<button ", "</button>", "<script>", "</script>"];
        let tags = html.matches('<').count();
        let known: usize = ours.iter().map(|t| html.matches(t).count()).sum();
        assert_eq!(tags, known);
    }
});
