//! The raw engine's parsers on arbitrary input. None may panic, and:
//! - the chunked scanner gives the same answer however the bytes are split across reads;
//! - an HTTP/1.1 request converted to HTTP/2 encodes to a header block that decodes;
//! - rewriting `Content-Length` twice is the same as once;
//! - WebSocket and HTTP/2 frames that parse encode back to something that parses to the same frame;
//! - header blocks from HTTP/2 frames decode (or fail) without panicking;
//! - redirect targets resolve (or not) and the rewritten request is still a request.
#![no_main]
use bosun_http::h2;
use bosun_http::redirect;
use bosun_http::wire::{ChunkScanner, head_end, update_content_length};
use bosun_http::ws;
use bosun_model::{Scheme, Target};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(end) = head_end(data) {
        assert!(end <= data.len());
    }
    // Converting a request to HTTP/2 never panics, and what it makes encodes to a header block that decodes again.
    if let Ok(r) = h2::H2Request::from_http1(data, "http") {
        let frames = r.frames(1);
        assert!(h2::decode_plan_headers(&frames).is_ok());
    }
    let once = update_content_length(data);
    assert_eq!(update_content_length(&once), once);

    let whole = ChunkScanner::default().advance(data);
    // Feed the same bytes in two reads at a split taken from the input itself.
    let split = data.first().map_or(0, |b| *b as usize % (data.len() + 1));
    let mut s = ChunkScanner::default();
    let first = s.advance(&data[..split]);
    let second = if matches!(first, Ok(None)) { s.advance(data) } else { first };
    assert_eq!(whole, second);

    if let Ok(Some((f, used))) = ws::parse_frame(data, 1 << 20) {
        assert!(used <= data.len());
        assert_eq!(ws::parse_frame(&f.encode(), 1 << 20).map(|r| r.map(|x| x.0)), Ok(Some(f)));
    }

    let mut frames = Vec::new();
    let mut rest = data;
    while let Ok(Some((f, used))) = h2::parse_frame(rest, 1 << 16) {
        assert_eq!(h2::parse_frame(&f.encode(), 1 << 16), Ok(Some((f.clone(), used))));
        frames.push(f);
        rest = &rest[used..];
    }
    let _ = h2::decode_plan_headers(&frames);

    if let Ok(text) = std::str::from_utf8(data) {
        let base = Target::new(Scheme::Https, "a.test", 443);
        if let Some(url) = redirect::resolve(&base, "/x/y?z", text) {
            assert!(url.path.starts_with('/') && !url.host.is_empty());
            let out = redirect::rewrite_request(b"POST /p HTTP/1.1\r\nHost: a\r\nCookie: c\r\n\r\nbody", None, &url, true, false);
            assert!(out.starts_with(b"POST /"));
        }
    }
});
