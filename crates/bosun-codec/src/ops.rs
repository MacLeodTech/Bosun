//! The encodings and decoders, and chains of them.

use std::io::{Read, Write};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use utoipa::ToSchema;

use crate::CodecError;
use crate::schema::Typed;

/// One step of a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    UrlEncode,
    /// `%XX` sequences only.
    UrlDecode,
    /// As `url_decode`, and `+` becomes a space (form encoding).
    UrlDecodeForm,
    HtmlEncode,
    HtmlDecode,
    Base64Encode,
    Base64Decode,
    Base64urlEncode,
    Base64urlDecode,
    HexEncode,
    HexDecode,
    GzipDecode,
    /// zlib, or raw deflate if the zlib header is missing.
    DeflateDecode,
    BrotliDecode,
    ZstdDecode,
    /// gzip, default level.
    GzipEncode,
    /// zlib, default level.
    DeflateEncode,
    BrotliEncode,
    ZstdEncode,
    /// Header and payload as text. The signature is not checked.
    JwtDecode,
    UnicodeEscape,
    UnicodeUnescape,
    /// Broken for security uses; here for matching what a target computes.
    Md5,
    /// Broken for security uses; here for matching what a target computes.
    Sha1,
    Sha256,
    Sha512,
    /// A protobuf message as text (field numbers, no schema).
    ProtobufDecode,
    /// The text form of a protobuf message back to bytes.
    ProtobufEncode,
    /// A gRPC or gRPC-Web body as text, one `@message` per frame.
    GrpcDecode,
    /// The text form of a gRPC body back to bytes.
    GrpcEncode,
    /// A GraphQL request body as the query and the variables, apart.
    GraphqlDecode,
}

impl Op {
    /// Every operation, in the order the Decoder lists them.
    pub const ALL: [Op; 31] = [
        Op::UrlDecode,
        Op::UrlDecodeForm,
        Op::HtmlDecode,
        Op::Base64Decode,
        Op::Base64urlDecode,
        Op::HexDecode,
        Op::UnicodeUnescape,
        Op::GzipDecode,
        Op::DeflateDecode,
        Op::BrotliDecode,
        Op::ZstdDecode,
        Op::JwtDecode,
        Op::ProtobufDecode,
        Op::GrpcDecode,
        Op::GraphqlDecode,
        Op::UrlEncode,
        Op::HtmlEncode,
        Op::Base64Encode,
        Op::Base64urlEncode,
        Op::HexEncode,
        Op::UnicodeEscape,
        Op::ProtobufEncode,
        Op::GrpcEncode,
        Op::GzipEncode,
        Op::DeflateEncode,
        Op::BrotliEncode,
        Op::ZstdEncode,
        Op::Md5,
        Op::Sha1,
        Op::Sha256,
        Op::Sha512,
    ];

    /// The name used in the API (`snake_case`).
    pub fn name(self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    }

    /// The operation with this API name.
    pub fn from_name(name: &str) -> Option<Op> {
        serde_json::from_value(serde_json::Value::String(name.to_owned())).ok()
    }
}

pub(crate) fn bounded(mut r: impl Read, limit: usize, what: &'static str) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    r.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| CodecError::Invalid(what))?;
    if out.len() > limit {
        return Err(CodecError::TooLarge(limit));
    }
    Ok(out)
}

fn check(n: usize, limit: usize) -> Result<(), CodecError> {
    if n > limit {
        Err(CodecError::TooLarge(limit))
    } else {
        Ok(())
    }
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn url_decode(input: &[u8], plus: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' if i + 2 < input.len()
                && hex_val(input[i + 1]).is_some()
                && hex_val(input[i + 2]).is_some() =>
            {
                out.push(hex_val(input[i + 1]).unwrap_or(0) << 4 | hex_val(input[i + 2]).unwrap_or(0));
                i += 3;
            }
            b'+' if plus => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn html_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\'' => out.extend_from_slice(b"&#39;"),
            _ => out.push(b),
        }
    }
    out
}

fn push_char(out: &mut Vec<u8>, c: u32) {
    match char::from_u32(c) {
        Some(ch) => {
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
        None => out.extend_from_slice("\u{fffd}".as_bytes()),
    }
}

fn html_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'&'
            && let Some(rel) = input[i + 1..].iter().take(12).position(|&b| b == b';')
        {
            let name = &input[i + 1..i + 1 + rel];
            let decoded = match name {
                b"amp" => Some(u32::from(b'&')),
                b"lt" => Some(u32::from(b'<')),
                b"gt" => Some(u32::from(b'>')),
                b"quot" => Some(u32::from(b'"')),
                b"apos" => Some(u32::from(b'\'')),
                b"nbsp" => Some(0xA0),
                [b'#', b'x' | b'X', digits @ ..] if !digits.is_empty() => std::str::from_utf8(digits)
                    .ok()
                    .and_then(|s| u32::from_str_radix(s, 16).ok()),
                [b'#', digits @ ..] if !digits.is_empty() => {
                    std::str::from_utf8(digits).ok().and_then(|s| s.parse().ok())
                }
                _ => None,
            };
            if let Some(c) = decoded {
                push_char(&mut out, c);
                i += rel + 2;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    b.trim_ascii()
}

fn b64_decode(input: &[u8], url: bool) -> Result<Vec<u8>, CodecError> {
    let cleaned: Vec<u8> = trim_ascii(input)
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let unpadded: &[u8] = {
        let mut end = cleaned.len();
        while end > 0 && cleaned[end - 1] == b'=' {
            end -= 1;
        }
        &cleaned[..end]
    };
    let e = if url { URL_SAFE_NO_PAD } else { STANDARD_NO_PAD };
    e.decode(unpadded)
        .map_err(|_| CodecError::Invalid(if url { "base64url" } else { "base64" }))
}

fn hex_decode(input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let digits: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace() && *b != b':')
        .collect();
    let digits = digits.strip_prefix(b"0x").map_or(digits.as_slice(), |d| d);
    if !digits.len().is_multiple_of(2) {
        return Err(CodecError::Invalid("hex"));
    }
    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| match (hex_val(p[0]), hex_val(p[1])) {
            (Some(h), Some(l)) => Ok(h << 4 | l),
            _ => Err(CodecError::Invalid("hex")),
        })
        .collect()
}

fn unicode_escape(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for ch in String::from_utf8_lossy(input).chars() {
        if ch.is_ascii() {
            out.push(ch as u8);
        } else {
            let mut units = [0u16; 2];
            for u in ch.encode_utf16(&mut units) {
                out.extend_from_slice(format!("\\u{u:04x}").as_bytes());
            }
        }
    }
    out
}

fn unicode_unescape(input: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(input);
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let hex4 = |at: usize| -> Option<u32> {
        let h: String = chars.get(at..at + 4)?.iter().collect();
        if h.chars().all(|c| c.is_ascii_hexdigit()) {
            u32::from_str_radix(&h, 16).ok()
        } else {
            None
        }
    };
    while i < chars.len() {
        if chars[i] == '\\' && chars.get(i + 1) == Some(&'u') {
            if chars.get(i + 2) == Some(&'{')
                && let Some(close) = chars[i + 3..].iter().take(7).position(|&c| c == '}')
            {
                let h: String = chars[i + 3..i + 3 + close].iter().collect();
                if let Ok(c) = u32::from_str_radix(&h, 16) {
                    push_char(&mut out, c);
                    i += close + 4;
                    continue;
                }
            } else if let Some(hi) = hex4(i + 2) {
                // A surrogate pair is two escapes.
                if (0xD800..0xDC00).contains(&hi)
                    && chars.get(i + 6) == Some(&'\\')
                    && chars.get(i + 7) == Some(&'u')
                    && let Some(lo) = hex4(i + 8)
                    && (0xDC00..0xE000).contains(&lo)
                {
                    push_char(&mut out, 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00));
                    i += 12;
                    continue;
                }
                push_char(&mut out, hi);
                i += 6;
                continue;
            }
        }
        let mut buf = [0u8; 4];
        out.extend_from_slice(chars[i].encode_utf8(&mut buf).as_bytes());
        i += 1;
    }
    out
}

fn jwt_decode(input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let text = std::str::from_utf8(trim_ascii(input)).map_err(|_| CodecError::Invalid("JWT"))?;
    let mut parts = text.split('.');
    let (Some(h), Some(p), Some(sig), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(CodecError::Invalid("JWT"));
    };
    let dec = |s: &str| {
        URL_SAFE_NO_PAD
            .decode(s.trim_end_matches('='))
            .map_err(|_| CodecError::Invalid("JWT"))
    };
    let (h, p) = (dec(h)?, dec(p)?);
    // Both parts must be JSON objects; anything else is not a token.
    for part in [&h, &p] {
        if part.first() != Some(&b'{') {
            return Err(CodecError::Invalid("JWT"));
        }
    }
    let mut out = h;
    out.push(b'\n');
    out.extend_from_slice(&p);
    out.extend_from_slice(b"\n(signature: ");
    out.extend_from_slice(sig.as_bytes());
    out.push(b')');
    Ok(out)
}

/// Run one step. `limit` bounds the output.
pub fn apply(op: Op, input: &[u8], limit: usize) -> Result<Vec<u8>, CodecError> {
    apply_with(op, input, limit, None)
}

/// [`apply`] with a schema, which the protobuf and gRPC operations use to name fields.
pub fn apply_with(
    op: Op,
    input: &[u8],
    limit: usize,
    typed: Option<Typed<'_>>,
) -> Result<Vec<u8>, CodecError> {
    let out = match op {
        Op::UrlEncode => {
            check(input.len().saturating_mul(3), limit.saturating_mul(1)).or_else(|e| {
                // Only an error if the real size is too big; the estimate is the worst case.
                let real: usize = input.iter().map(|&b| if is_unreserved(b) { 1 } else { 3 }).sum();
                if real > limit { Err(e) } else { Ok(()) }
            })?;
            let mut o = Vec::with_capacity(input.len());
            for &b in input {
                if is_unreserved(b) {
                    o.push(b);
                } else {
                    o.extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
                }
            }
            o
        }
        Op::UrlDecode => url_decode(input, false),
        Op::UrlDecodeForm => url_decode(input, true),
        Op::HtmlEncode => html_encode(input),
        Op::HtmlDecode => html_decode(input),
        Op::Base64Encode => STANDARD.encode(input).into_bytes(),
        Op::Base64Decode => b64_decode(input, false)?,
        Op::Base64urlEncode => URL_SAFE
            .encode(input)
            .trim_end_matches('=')
            .to_string()
            .into_bytes(),
        Op::Base64urlDecode => b64_decode(input, true)?,
        Op::HexEncode => {
            let mut o = Vec::with_capacity(input.len() * 2);
            for &b in input {
                o.push(HEX[usize::from(b >> 4)].to_ascii_lowercase());
                o.push(HEX[usize::from(b & 15)].to_ascii_lowercase());
            }
            o
        }
        Op::HexDecode => hex_decode(input)?,
        Op::GzipDecode => bounded(flate2::read::MultiGzDecoder::new(input), limit, "gzip data")?,
        Op::DeflateDecode => match bounded(flate2::read::ZlibDecoder::new(input), limit, "deflate data") {
            Err(CodecError::Invalid(_)) => {
                bounded(flate2::read::DeflateDecoder::new(input), limit, "deflate data")?
            }
            other => other?,
        },
        Op::BrotliDecode => bounded(brotli::Decompressor::new(input, 4096), limit, "brotli data")?,
        Op::ZstdDecode => {
            let d = zstd::stream::read::Decoder::new(input).map_err(|_| CodecError::Invalid("zstd data"))?;
            bounded(d, limit, "zstd data")?
        }
        Op::GzipEncode => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(input).map_err(|_| CodecError::Invalid("input"))?;
            e.finish().map_err(|_| CodecError::Invalid("input"))?
        }
        Op::DeflateEncode => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(input).map_err(|_| CodecError::Invalid("input"))?;
            e.finish().map_err(|_| CodecError::Invalid("input"))?
        }
        Op::BrotliEncode => {
            let mut o = Vec::new();
            {
                let mut e = brotli::CompressorWriter::new(&mut o, 4096, 5, 22);
                e.write_all(input).map_err(|_| CodecError::Invalid("input"))?;
                e.flush().map_err(|_| CodecError::Invalid("input"))?;
            }
            o
        }
        Op::ZstdEncode => zstd::encode_all(input, 3).map_err(|_| CodecError::Invalid("input"))?,
        Op::JwtDecode => jwt_decode(input)?,
        Op::UnicodeEscape => unicode_escape(input),
        Op::UnicodeUnescape => unicode_unescape(input),
        Op::Md5 => hex_of(&md5::Md5::digest(input)),
        Op::Sha1 => hex_of(&sha1::Sha1::digest(input)),
        Op::Sha256 => hex_of(&sha2::Sha256::digest(input)),
        Op::Sha512 => hex_of(&sha2::Sha512::digest(input)),
        Op::ProtobufDecode => crate::proto::decode_text_with(input, limit, typed)?.into_bytes(),
        Op::ProtobufEncode => crate::proto::encode_text_with(input, limit, typed)?,
        Op::GrpcDecode => crate::proto::grpc_decode_with(input, limit, typed)?.into_bytes(),
        Op::GrpcEncode => crate::proto::grpc_encode_with(input, limit, typed)?,
        Op::GraphqlDecode => crate::graphql::decode_text(input, limit)?.into_bytes(),
    };
    check(out.len(), limit)?;
    Ok(out)
}

fn hex_of(d: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(d.len() * 2);
    for &b in d {
        o.push(HEX[usize::from(b >> 4)].to_ascii_lowercase());
        o.push(HEX[usize::from(b & 15)].to_ascii_lowercase());
    }
    o
}

/// Run a chain and return the output of every step (so the UI can show each stage). A failing step stops
/// the chain; the outputs so far are returned with the error.
pub fn apply_chain(ops: &[Op], input: &[u8], limit: usize) -> (Vec<Vec<u8>>, Option<(usize, CodecError)>) {
    apply_chain_with(ops, input, limit, None)
}

/// [`apply_chain`] with a schema for its protobuf and gRPC steps.
pub fn apply_chain_with(
    ops: &[Op],
    input: &[u8],
    limit: usize,
    typed: Option<Typed<'_>>,
) -> (Vec<Vec<u8>>, Option<(usize, CodecError)>) {
    let mut outs: Vec<Vec<u8>> = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        let prev: &[u8] = outs.last().map_or(input, Vec::as_slice);
        match apply_with(*op, prev, limit, typed) {
            Ok(o) => outs.push(o),
            Err(e) => return (outs, Some((i, e))),
        }
    }
    (outs, None)
}

/// Guess a chain of decoders for `input` and run it, up to `max_steps`. Returns the steps it chose, each with
/// its output. It stops when nothing recognisable is left.
pub fn smart_decode(input: &[u8], limit: usize, max_steps: usize) -> Vec<(Op, Vec<u8>)> {
    let mut steps: Vec<(Op, Vec<u8>)> = Vec::new();
    let mut cur = input.to_vec();
    for _ in 0..max_steps {
        let Some((op, next)) = guess(&cur, limit) else {
            break;
        };
        if next == cur {
            break;
        }
        steps.push((op, next.clone()));
        cur = next;
    }
    steps
}

fn guess(b: &[u8], limit: usize) -> Option<(Op, Vec<u8>)> {
    let t = trim_ascii(b);
    let try_op = |op: Op| apply(op, b, limit).ok().map(|o| (op, o));
    // Magic numbers first: they are unambiguous.
    if t.starts_with(&[0x1f, 0x8b]) {
        return try_op(Op::GzipDecode);
    }
    if t.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return try_op(Op::ZstdDecode);
    }
    if t.starts_with(b"eyJ") && t.iter().filter(|&&c| c == b'.').count() == 2 {
        return try_op(Op::JwtDecode);
    }
    if t.len() >= 2 && t.contains(&b'%') && url_decode(t, false) != t {
        return try_op(Op::UrlDecode);
    }
    if t.windows(2).any(|w| w == b"\\u") && unicode_unescape(t) != t {
        return try_op(Op::UnicodeUnescape);
    }
    if t.contains(&b'&') && t.contains(&b';') && html_decode(t) != t {
        return try_op(Op::HtmlDecode);
    }
    let all = |f: fn(&u8) -> bool| !t.is_empty() && t.iter().all(f);
    if t.len() >= 4 && t.len().is_multiple_of(2) && all(|c| c.is_ascii_hexdigit()) {
        return try_op(Op::HexDecode);
    }
    if t.len() >= 8 && all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=')) {
        let r = apply(Op::Base64Decode, b, limit).ok()?;
        // Plain words happen to be valid base64; only accept results that look like data or text.
        if !r.is_empty()
            && (std::str::from_utf8(&r).is_ok_and(|s| !s.chars().any(char::is_control))
                || r.starts_with(&[0x1f, 0x8b]))
        {
            return Some((Op::Base64Decode, r));
        }
    }
    if t.len() >= 8 && all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_')) {
        let r = apply(Op::Base64urlDecode, b, limit).ok()?;
        if !r.is_empty() && std::str::from_utf8(&r).is_ok_and(|s| !s.chars().any(char::is_control)) {
            return Some((Op::Base64urlDecode, r));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const L: usize = 1 << 20;

    #[test]
    fn url_round_trip_and_edge_cases() {
        assert_eq!(
            apply(Op::UrlEncode, "a b&c=d/é".as_bytes(), L).unwrap(),
            b"a%20b%26c%3Dd%2F%C3%A9"
        );
        assert_eq!(apply(Op::UrlDecode, b"a%20b%26c%zz%2", L).unwrap(), b"a b&c%zz%2");
        assert_eq!(apply(Op::UrlDecode, b"a+b", L).unwrap(), b"a+b");
        assert_eq!(apply(Op::UrlDecodeForm, b"a+b%21", L).unwrap(), b"a b!");
        assert_eq!(apply(Op::UrlDecode, b"%41", L).unwrap(), b"A");
    }

    #[test]
    fn html_entities() {
        assert_eq!(
            apply(Op::HtmlEncode, b"<a href=\"x\">&'", L).unwrap(),
            b"&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        assert_eq!(
            apply(Op::HtmlDecode, b"&lt;&#65;&#x42;&amp;lt;&bogus;&", L).unwrap(),
            b"<AB&lt;&bogus;&"
        );
        // An out-of-range code point is replaced, never a panic.
        assert_eq!(
            apply(Op::HtmlDecode, b"&#99999999999;", L).unwrap(),
            b"&#99999999999;"
        );
        assert_eq!(
            apply(Op::HtmlDecode, b"&#xD800;", L).unwrap(),
            "\u{fffd}".as_bytes()
        );
    }

    #[test]
    fn base64_forms() {
        assert_eq!(apply(Op::Base64Encode, b"hi?>", L).unwrap(), b"aGk/Pg==");
        assert_eq!(apply(Op::Base64urlEncode, b"hi?>", L).unwrap(), b"aGk_Pg");
        assert_eq!(apply(Op::Base64Decode, b"aGk/Pg", L).unwrap(), b"hi?>");
        assert_eq!(apply(Op::Base64Decode, b" aGk/\nPg== ", L).unwrap(), b"hi?>");
        assert_eq!(apply(Op::Base64urlDecode, b"aGk_Pg==", L).unwrap(), b"hi?>");
        assert!(apply(Op::Base64Decode, b"!!!", L).is_err());
    }

    #[test]
    fn hex_forms() {
        assert_eq!(apply(Op::HexEncode, &[0, 255, 16], L).unwrap(), b"00ff10");
        assert_eq!(apply(Op::HexDecode, b"00 FF:10", L).unwrap(), [0, 255, 16]);
        assert_eq!(apply(Op::HexDecode, b"0x00ff", L).unwrap(), [0, 255]);
        assert!(apply(Op::HexDecode, b"abc", L).is_err());
        assert!(apply(Op::HexDecode, b"zz", L).is_err());
    }

    #[test]
    fn compression_and_bombs() {
        use std::io::Write;
        let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        g.write_all(b"hello hello hello").unwrap();
        let gz = g.finish().unwrap();
        assert_eq!(apply(Op::GzipDecode, &gz, L).unwrap(), b"hello hello hello");
        let z = zstd::encode_all(&b"zstd data"[..], 3).unwrap();
        assert_eq!(apply(Op::ZstdDecode, &z, L).unwrap(), b"zstd data");
        let mut d = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        d.write_all(b"zlib").unwrap();
        assert_eq!(
            apply(Op::DeflateDecode, &d.finish().unwrap(), L).unwrap(),
            b"zlib"
        );
        let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(b"raw").unwrap();
        assert_eq!(
            apply(Op::DeflateDecode, &raw.finish().unwrap(), L).unwrap(),
            b"raw"
        );
        // A bomb: 4 MiB of zeros compresses to a few KiB; a 1 KiB limit must refuse it.
        let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        g.write_all(&vec![0u8; 4 << 20]).unwrap();
        let bomb = g.finish().unwrap();
        assert!(bomb.len() < 10_000);
        assert_eq!(
            apply(Op::GzipDecode, &bomb, 1024),
            Err(CodecError::TooLarge(1024))
        );
        let zb = zstd::encode_all(&vec![0u8; 4 << 20][..], 19).unwrap();
        assert_eq!(apply(Op::ZstdDecode, &zb, 1024), Err(CodecError::TooLarge(1024)));
        assert!(apply(Op::GzipDecode, b"not gzip", L).is_err());
        assert!(apply(Op::BrotliDecode, b"\xff\xff\xff", L).is_err());
    }

    #[test]
    fn jwt() {
        let t = b"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.sig";
        let out = apply(Op::JwtDecode, t, L).unwrap();
        assert_eq!(out, b"{\"alg\":\"none\"}\n{\"sub\":\"1\"}\n(signature: sig)");
        assert!(apply(Op::JwtDecode, b"a.b", L).is_err());
        assert!(apply(Op::JwtDecode, b"aGk.aGk.x", L).is_err());
    }

    #[test]
    fn unicode_escapes() {
        assert_eq!(
            apply(Op::UnicodeEscape, "aé😀".as_bytes(), L).unwrap(),
            b"a\\u00e9\\ud83d\\ude00"
        );
        assert_eq!(
            apply(
                Op::UnicodeUnescape,
                b"a\\u00e9\\ud83d\\ude00\\u{1F600}\\uZZZZ\\ud800x",
                L
            )
            .unwrap(),
            "aé😀😀\\uZZZZ\u{fffd}x".as_bytes()
        );
    }

    #[test]
    fn hashes() {
        assert_eq!(
            apply(Op::Sha256, b"abc", L).unwrap(),
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn all_lists_every_op_once_and_names_round_trip() {
        // An exhaustive match: adding a variant stops this compiling until `ALL` is updated too.
        let counted = |op: Op| match op {
            Op::UrlEncode
            | Op::UrlDecode
            | Op::UrlDecodeForm
            | Op::HtmlEncode
            | Op::HtmlDecode
            | Op::Base64Encode
            | Op::Base64Decode
            | Op::Base64urlEncode
            | Op::Base64urlDecode
            | Op::HexEncode
            | Op::HexDecode
            | Op::GzipDecode
            | Op::DeflateDecode
            | Op::BrotliDecode
            | Op::ZstdDecode
            | Op::GzipEncode
            | Op::DeflateEncode
            | Op::BrotliEncode
            | Op::ZstdEncode
            | Op::JwtDecode
            | Op::UnicodeEscape
            | Op::UnicodeUnescape
            | Op::Md5
            | Op::Sha1
            | Op::Sha256
            | Op::Sha512
            | Op::ProtobufDecode
            | Op::ProtobufEncode
            | Op::GrpcDecode
            | Op::GrpcEncode
            | Op::GraphqlDecode => 1,
        };
        assert_eq!(Op::ALL.iter().map(|&o| counted(o)).sum::<usize>(), 31);
        for (i, a) in Op::ALL.iter().enumerate() {
            assert_eq!(Op::from_name(&a.name()), Some(*a));
            assert!(!Op::ALL[..i].contains(a), "{a:?} is listed twice");
        }
        assert_eq!(Op::from_name("nope"), None);
    }

    #[test]
    fn md5_and_sha1() {
        assert_eq!(
            apply(Op::Md5, b"abc", L).unwrap(),
            b"900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            apply(Op::Md5, b"", L).unwrap(),
            b"d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            apply(Op::Sha1, b"abc", L).unwrap(),
            b"a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn compression_encoders_round_trip_and_respect_the_limit() {
        let data = b"hello hello hello hello hello hello".repeat(20);
        for (enc, dec) in [
            (Op::GzipEncode, Op::GzipDecode),
            (Op::DeflateEncode, Op::DeflateDecode),
            (Op::BrotliEncode, Op::BrotliDecode),
            (Op::ZstdEncode, Op::ZstdDecode),
        ] {
            let c = apply(enc, &data, L).unwrap();
            assert!(c.len() < data.len(), "{enc:?} did not compress");
            assert_eq!(apply(dec, &c, L).unwrap(), data, "{enc:?}");
            assert_eq!(apply(enc, &data, 4), Err(CodecError::TooLarge(4)), "{enc:?}");
            assert!(apply(enc, b"", L).is_ok());
        }
    }

    #[test]
    fn output_limit_applies_to_every_op() {
        assert!(matches!(
            apply(Op::HexEncode, &[0u8; 100], 50),
            Err(CodecError::TooLarge(50))
        ));
        assert!(matches!(
            apply(Op::UrlEncode, &[0u8; 100], 50),
            Err(CodecError::TooLarge(50))
        ));
    }

    #[test]
    fn chain_stops_at_the_first_error_and_keeps_earlier_output() {
        let (outs, err) = apply_chain(&[Op::Base64Encode, Op::HexDecode, Op::HexEncode], b"hi", L);
        assert_eq!(outs, vec![b"aGk=".to_vec()]);
        assert_eq!(err.map(|(i, _)| i), Some(1));
    }

    #[test]
    fn smart_decode_peels_layers() {
        // base64( url-encoded text )
        let inner = apply(Op::UrlEncode, b"a b<c>", L).unwrap();
        let outer = apply(Op::Base64Encode, &inner, L).unwrap();
        let steps = smart_decode(&outer, L, 8);
        assert_eq!(steps.last().unwrap().1, b"a b<c>");
        assert_eq!(steps[0].0, Op::Base64Decode);
        // Plain text is left alone.
        assert!(smart_decode(b"hello world", L, 8).is_empty());
        assert!(smart_decode(b"", L, 8).is_empty());
    }

    proptest! {
        #[test]
        fn round_trips(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            for (enc, dec) in [
                (Op::UrlEncode, Op::UrlDecode),
                (Op::Base64Encode, Op::Base64Decode),
                (Op::Base64urlEncode, Op::Base64urlDecode),
                (Op::HexEncode, Op::HexDecode),
            ] {
                let e = apply(enc, &data, 1 << 20).unwrap();
                prop_assert_eq!(apply(dec, &e, 1 << 20).unwrap(), data.clone());
            }
        }

        #[test]
        fn text_round_trips(s in "\\PC{0,80}") {
            let e = apply(Op::UnicodeEscape, s.as_bytes(), 1 << 20).unwrap();
            prop_assert_eq!(apply(Op::UnicodeUnescape, &e, 1 << 20).unwrap(), s.as_bytes());
        }

        #[test]
        fn no_op_panics_or_exceeds_the_limit(data in proptest::collection::vec(any::<u8>(), 0..300), limit in 0usize..400) {
            for op in [Op::UrlEncode, Op::UrlDecode, Op::UrlDecodeForm, Op::HtmlEncode, Op::HtmlDecode,
                Op::Base64Encode, Op::Base64Decode, Op::Base64urlEncode, Op::Base64urlDecode, Op::HexEncode,
                Op::HexDecode, Op::GzipDecode, Op::DeflateDecode, Op::BrotliDecode, Op::ZstdDecode,
                Op::JwtDecode, Op::UnicodeEscape, Op::UnicodeUnescape, Op::Sha256, Op::Sha512, Op::Md5, Op::Sha1, Op::GzipEncode, Op::DeflateEncode, Op::BrotliEncode, Op::ZstdEncode] {
                if let Ok(out) = apply(op, &data, limit) { prop_assert!(out.len() <= limit); }
            }
            let _ = smart_decode(&data, limit, 8);
        }
    }
}
