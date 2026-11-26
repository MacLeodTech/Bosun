#![allow(clippy::unwrap_used)]
use proptest::prelude::*;
use sha2::{Digest, Sha256};

use super::*;

/// Deterministic random-looking bytes: SHA-256 in counter mode.
fn rand_bytes(seed: u32, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0u32;
    while out.len() < n {
        let mut h = Sha256::new();
        h.update(seed.to_be_bytes());
        h.update(i.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        i += 1;
    }
    out.truncate(n);
    out
}

fn from_alphabet(alphabet: &str, len: usize, count: usize) -> Vec<String> {
    let a: Vec<char> = alphabet.chars().collect();
    (0..count)
        .map(|i| {
            // Rejection sampling keeps the choice uniform.
            let bytes = rand_bytes(i as u32, len * 4);
            let limit = 256 - 256 % a.len();
            bytes
                .iter()
                .filter(|b| usize::from(**b) < limit)
                .take(len)
                .map(|b| a[usize::from(*b) % a.len()])
                .collect()
        })
        .collect()
}

const HEX: &str = "0123456789abcdef";
const ALNUM: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[test]
fn good_tokens_are_excellent() {
    for (alpha, len) in [(HEX, 32), (ALNUM, 24), (HEX, 64)] {
        let t = from_alphabet(alpha, len, 1000);
        let a = analyze(&t).unwrap();
        assert_eq!(
            a.verdict,
            Verdict::Excellent,
            "{alpha} {len}: {:?} {}",
            a.reasons,
            a.entropy_bits
        );
        assert!(a.reliable);
        let f = a.fips.as_ref().expect("enough bits");
        assert_eq!(f.blocks_passed, f.blocks.len(), "{:?}", a.reasons);
        assert!(a.entropy_bits <= a.capacity_bits + 1e-9);
    }
}

#[test]
fn a_uuid_with_fixed_nibbles_is_still_excellent() {
    let t: Vec<String> = (0..600u32)
        .map(|i| {
            let h: String = rand_bytes(i, 16).iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "{}-{}-4{}-a{}-{}",
                &h[0..8],
                &h[8..12],
                &h[13..16],
                &h[17..20],
                &h[20..32]
            )
        })
        .collect();
    let a = analyze(&t).unwrap();
    assert_eq!(
        a.verdict,
        Verdict::Excellent,
        "{:?} {}",
        a.reasons,
        a.entropy_bits
    );
}

#[test]
fn a_medium_token_is_good() {
    // 12 characters of base 62 is about 71 bits.
    let a = analyze(&from_alphabet(ALNUM, 12, 1000)).unwrap();
    assert_eq!(a.verdict, Verdict::Good, "{:?} {}", a.reasons, a.entropy_bits);
}

#[test]
fn short_random_tokens_are_poor() {
    let a = analyze(&from_alphabet("0123456789", 6, 2000)).unwrap();
    assert_eq!(a.verdict, Verdict::Poor, "{:?}", a.reasons);
    let a = analyze(&from_alphabet("abc", 20, 500)).unwrap();
    assert_eq!(a.verdict, Verdict::Poor, "{:?}", a.reasons);
}

#[test]
fn counters_are_not_random() {
    let dec: Vec<String> = (1000..1500).map(|i| i.to_string()).collect();
    let a = analyze(&dec).unwrap();
    assert_eq!(a.verdict, Verdict::NotRandom, "{:?}", a.reasons);
    assert!(a.sequential_share > 0.9);
    let hex: Vec<String> = (0..500u64)
        .map(|i| format!("{:032x}", 0xdead_beef_0000u64 + i * 7))
        .collect();
    assert_eq!(analyze(&hex).unwrap().verdict, Verdict::NotRandom);
    let pre: Vec<String> = (0..300)
        .map(|i| format!("sess-{:08}", 5_000_000 + i * 3))
        .collect();
    assert_eq!(analyze(&pre).unwrap().verdict, Verdict::NotRandom);
}

#[test]
fn constant_and_repeating_tokens_are_not_random() {
    let c = vec!["abcdef0123456789abcdef0123456789".to_string(); 200];
    let a = analyze(&c).unwrap();
    assert_eq!(a.verdict, Verdict::NotRandom);
    assert_eq!(a.entropy_bits, 0.0);
    // Random tokens drawn from only ten values.
    let ten = from_alphabet(HEX, 32, 10);
    let rep: Vec<String> = (0..300).map(|i| ten[(i * 7) % 10].clone()).collect();
    assert_eq!(analyze(&rep).unwrap().verdict, Verdict::NotRandom);
}

#[test]
fn skewed_bits_fail_fips() {
    // Hex characters, but biased towards low values: the bit stream is far from balanced.
    let t: Vec<String> = (0..1500u32)
        .map(|i| {
            rand_bytes(i, 32)
                .iter()
                .map(|b| HEX.as_bytes()[usize::from(b % 16 / 2 + b % 3 % 2 * 8)] as char)
                .collect()
        })
        .collect();
    let a = analyze(&t).unwrap();
    assert!(a.verdict <= Verdict::Poor, "{:?}", a.reasons);
}

#[test]
fn a_small_sample_is_flagged() {
    let a = analyze(&from_alphabet(HEX, 32, 30)).unwrap();
    assert!(!a.reliable);
    assert!(a.fips.is_none());
}

#[test]
fn limits() {
    assert_eq!(analyze::<&str>(&[]).unwrap_err(), Error::TooFew(0));
    let many = vec!["x"; MAX_TOKENS + 1];
    assert_eq!(analyze(&many).unwrap_err(), Error::TooMany(MAX_TOKENS + 1));
    let long = vec!["x".repeat(MAX_TOKEN_CHARS + 1); 30];
    assert_eq!(analyze(&long).unwrap_err(), Error::TokenTooLong);
}

#[test]
fn fips_known_vectors() {
    // All zeros fails everything.
    let z = vec![0u8; FIPS_BLOCK_BITS];
    let r = fips_140_2(&z).unwrap();
    let b = &r.blocks[0];
    assert!(!b.monobit.pass && !b.poker.pass && !b.runs.pass && !b.long_run.pass);
    assert!(fips_140_2(&z[..19_999]).is_none());
    // A 25-bit run inside random bits is fine, a 26-bit one is not.
    let bits: Vec<u8> = rand_bytes(7, 2500)
        .iter()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1))
        .collect();
    assert_eq!(bits.len(), FIPS_BLOCK_BITS);
    assert!(fips_140_2(&bits).unwrap().blocks[0].passed());
    let mut long = bits.clone();
    long[100..126].fill(1);
    assert!(!fips_140_2(&long).unwrap().blocks[0].long_run.pass);
    // Alternating bits: balanced and the poker/runs tests catch it.
    let alt: Vec<u8> = (0..FIPS_BLOCK_BITS).map(|i| (i % 2) as u8).collect();
    let b = &fips_140_2(&alt).unwrap().blocks[0];
    assert!(b.monobit.pass && !b.runs.pass && !b.poker.pass);
}

#[test]
fn entropy_estimate() {
    assert_eq!(entropy_mm(&[]), 0.0);
    assert_eq!(entropy_mm(&[10]), 0.0);
    let e = entropy_mm(&[1000, 1000]);
    assert!((e - 1.0).abs() < 0.01, "{e}");
    assert!(entropy_mm(&[1, 1, 1, 1]) <= 2.0);
}

#[test]
fn extraction() {
    let resp = b"HTTP/1.1 200 OK\r\nX-Token: abc123\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: sid=XYZ; HttpOnly\r\n\r\n{\"csrf\":\"tok-9\"}";
    let get = |s: TokenSource| Extractor::new(&s).unwrap().extract(resp);
    assert_eq!(
        get(TokenSource::Header {
            name: "x-token".into()
        })
        .as_deref(),
        Some("abc123")
    );
    assert_eq!(
        get(TokenSource::Cookie { name: "sid".into() }).as_deref(),
        Some("XYZ")
    );
    assert_eq!(
        get(TokenSource::Cookie { name: "a".into() }).as_deref(),
        Some("1")
    );
    assert_eq!(get(TokenSource::Cookie { name: "nope".into() }), None);
    assert_eq!(
        get(TokenSource::Regex {
            pattern: r#""csrf":"([^"]+)""#.into()
        })
        .as_deref(),
        Some("tok-9")
    );
    // A pattern is looked for in the body only.
    assert_eq!(
        get(TokenSource::Regex {
            pattern: "abc123".into()
        }),
        None
    );
    assert!(Extractor::new(&TokenSource::Regex { pattern: "(".into() }).is_err());
    assert!(
        Extractor::new(&TokenSource::Regex {
            pattern: "a".repeat(MAX_PATTERN + 1)
        })
        .is_err()
    );
    assert!(Extractor::new(&TokenSource::Header { name: String::new() }).is_err());
}

proptest! {
    #[test]
    fn any_tokens_give_a_bounded_result(toks in proptest::collection::vec("\\PC{0,40}", 20..60)) {
        let a = analyze(&toks).unwrap();
        prop_assert!(a.entropy_bits.is_finite() && a.entropy_bits >= 0.0);
        prop_assert!(a.entropy_bits <= a.capacity_bits + 1e-9);
        prop_assert!(a.unique <= a.tokens);
        prop_assert!(a.positions.len() == a.max_length);
        prop_assert!((0.0..=1.0).contains(&a.sequential_share));
        prop_assert_eq!(analyze(&toks).unwrap().verdict, a.verdict);
    }

    #[test]
    fn extraction_never_panics(resp in proptest::collection::vec(any::<u8>(), 0..400)) {
        for s in [
            TokenSource::Header { name: "x".into() },
            TokenSource::Cookie { name: "x".into() },
            TokenSource::Regex { pattern: "(.+)".into() },
        ] {
            if let Some(t) = Extractor::new(&s).unwrap().extract(&resp) {
                prop_assert!(t.chars().count() <= MAX_TOKEN_CHARS);
            }
        }
    }
}
