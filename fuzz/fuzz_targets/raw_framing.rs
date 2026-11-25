//! The raw engine's byte-level helpers on arbitrary input: no panics; the chunked scanner gives the same answer
//! however the bytes are split across reads; rewriting `Content-Length` twice is the same as once.
#![no_main]
use bosun_http::wire::{ChunkScanner, head_end, update_content_length};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(end) = head_end(data) {
        assert!(end <= data.len());
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
});
