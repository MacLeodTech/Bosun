//! The Sequencer on arbitrary tokens and responses: no panic, finite bounded numbers, and extraction that returns
//! at most 1 024 characters. The first byte picks the token source; the rest is split into lines (tokens) and
//! also used as a raw response.
#![no_main]
use bosun_sequencer::{Extractor, MAX_TOKEN_CHARS, TokenSource, analyze, fips_140_2};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [sel, rest @ ..] = data else { return };
    let text = String::from_utf8_lossy(rest);
    let src = match sel % 3 {
        0 => TokenSource::Header { name: "x-token".into() },
        1 => TokenSource::Cookie { name: "sid".into() },
        _ => TokenSource::Regex { pattern: "([A-Za-z0-9]+)".into() },
    };
    if let Ok(e) = Extractor::new(&src) {
        if let Some(t) = e.extract(rest) {
            assert!(t.chars().count() <= MAX_TOKEN_CHARS);
        }
    }
    // The pattern itself is untrusted too.
    let _ = Extractor::new(&TokenSource::Regex { pattern: text.chars().take(600).collect() });

    // Tokens: one per line, repeated to reach the minimum count.
    let mut toks: Vec<&str> = text.lines().collect();
    if toks.is_empty() {
        return;
    }
    let base = toks.clone();
    while toks.len() < 40 {
        toks.extend_from_slice(&base);
    }
    if let Ok(a) = analyze(&toks) {
        assert!(a.entropy_bits.is_finite() && a.entropy_bits >= 0.0);
        assert!(a.entropy_bits <= a.capacity_bits + 1e-6);
        assert!(a.unique <= a.tokens);
        assert!(a.positions.len() == a.max_length);
    }
    let bits: Vec<u8> = rest.iter().flat_map(|b| (0..8).map(move |i| (b >> i) & 1)).collect();
    let _ = fips_140_2(&bits);
});
