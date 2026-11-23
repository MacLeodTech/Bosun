//! Stored bodies from a project file: decompression must stay within the limit whatever the bytes say.
#![no_main]
use bosun_store::project::bounded_decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [limit, rest @ ..] = data else { return };
    let limit = u64::from(*limit) * 64;
    if let Ok(out) = bounded_decode(rest, limit, None) {
        assert!(out.len() as u64 <= limit);
    }
    // A claimed size that is wrong must be refused, never trusted.
    if let Ok(out) = bounded_decode(rest, limit, Some(limit / 2)) {
        assert_eq!(out.len() as u64, limit / 2);
    }
});
