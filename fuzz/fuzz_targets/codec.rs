//! The Decoder and Comparer on arbitrary bytes: no panic, no output over the limit, and a diff that rebuilds both
//! sides. The first byte picks the decoder and the limit; the rest is the input (split in two for the diff).
#![no_main]
use bosun_codec::{DiffKind, DiffLevel, Op, apply, diff, smart_decode};
use libfuzzer_sys::fuzz_target;

const OPS: [Op; 20] = [
    Op::UrlEncode, Op::UrlDecode, Op::UrlDecodeForm, Op::HtmlEncode, Op::HtmlDecode, Op::Base64Encode,
    Op::Base64Decode, Op::Base64urlEncode, Op::Base64urlDecode, Op::HexEncode, Op::HexDecode, Op::GzipDecode,
    Op::DeflateDecode, Op::BrotliDecode, Op::ZstdDecode, Op::JwtDecode, Op::UnicodeEscape, Op::UnicodeUnescape,
    Op::Sha256, Op::Sha512,
];

fuzz_target!(|data: &[u8]| {
    let [sel, lim, rest @ ..] = data else { return };
    let limit = usize::from(*lim) * 64;
    let op = OPS[usize::from(*sel) % OPS.len()];
    if let Ok(out) = apply(op, rest, limit) {
        assert!(out.len() <= limit);
    }
    for (_, out) in smart_decode(rest, limit, 4) {
        assert!(out.len() <= limit);
    }
    let (a, b) = rest.split_at(rest.len() / 2);
    for level in [DiffLevel::Words, DiffLevel::Bytes] {
        let r = diff(a, b, level);
        let (mut ra, mut rb) = (0usize, 0usize);
        for o in &r.ops {
            match o.kind {
                DiffKind::Equal => {
                    assert_eq!(a[o.a_start..o.a_start + o.len], b[o.b_start..o.b_start + o.len]);
                    ra += o.len;
                    rb += o.len;
                }
                DiffKind::Delete => ra += o.len,
                DiffKind::Insert => rb += o.len,
            }
        }
        assert_eq!((ra, rb), (a.len(), b.len()));
    }
});
