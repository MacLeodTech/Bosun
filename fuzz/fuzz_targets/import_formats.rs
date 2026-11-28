//! The importers (OpenAPI/Swagger JSON and YAML, GraphQL introspection, Postman, HAR, URL lists, Burp XML) on
//! arbitrary bytes: no panic, and whatever comes out is an absolute http(s) request with header lines that cannot
//! be split, written as HTTP/1.1 text that holds exactly one request head.
#![no_main]
use bosun_import::{Format, Options, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [sel, rest @ ..] = data else { return };
    let format = Format::ALL[usize::from(*sel) % Format::ALL.len()];
    let opts = Options { base_url: (sel & 0x80 != 0).then(|| "https://fuzz.test/api".to_string()) };
    if let Ok(r) = parse(format, rest, &opts) {
        assert!(r.items.len() <= bosun_import::MAX_ITEMS);
        for i in r.items {
            assert!(i.url.starts_with("http://") || i.url.starts_with("https://"));
            assert!(i.body.len() <= bosun_import::MAX_BODY);
            let raw = i.raw().expect("a stored item is always writable");
            let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("a head ends in a blank line");
            // No bare line feed inside the head: every line break is CRLF.
            let head = &raw[..head_end];
            assert!(!head.windows(2).any(|w| w[1] == b'\n' && w[0] != b'\r'));
            assert!(!head.contains(&0));
        }
    }
});
