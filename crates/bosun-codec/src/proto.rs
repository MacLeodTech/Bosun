//! Protobuf (schema-less) and gRPC framing, as text you can read and edit.
//!
//! Without a schema only field numbers and wire types are known, so a decoded message looks like
//! `protoc --decode_raw`:
//!
//! ```text
//! 1: 150            varint
//! 2: "hello"        length-delimited that is text
//! 3 { 1: 5 }        length-delimited that parses as a message
//! 4: h"00ff"        length-delimited that is neither (bytes)
//! 5: fixed32 0x0000002a
//! 6: fixed64 0x000000000000002a
//! ```
//!
//! `encode_text` reads that form back, so a message can be edited and re-sent. gRPC bodies are a run of
//! frames (flag byte, 4-byte big-endian length, payload); each shows as an `@message` line followed by its
//! fields. Everything is bounded: nesting depth, and the size of the output.

use crate::CodecError;

const MAX_DEPTH: usize = 24;
/// The biggest field number protobuf allows.
const MAX_FIELD: u64 = (1 << 29) - 1;

type Res<T> = Result<T, CodecError>;

fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..70).step_by(7) {
        let b = *buf.get(*pos)?;
        *pos += 1;
        if shift == 63 && b > 1 {
            return None;
        }
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn is_text(b: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(b).ok()?;
    s.chars()
        .all(|c| !c.is_control() || matches!(c, '\n' | '\t' | '\r'))
        .then_some(s)
}

fn quote(b: &[u8], out: &mut String) {
    out.push('"');
    let mut rest = b;
    while !rest.is_empty() {
        let (ok, bad) = match std::str::from_utf8(rest) {
            Ok(s) => (s, 0),
            Err(e) => {
                let n = e.valid_up_to();
                // Safe: valid_up_to is a valid prefix.
                (std::str::from_utf8(&rest[..n]).unwrap_or(""), e.error_len().unwrap_or(rest.len() - n))
            }
        };
        for c in ok.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c.is_control() => {
                    let mut buf = [0u8; 4];
                    for b in c.encode_utf8(&mut buf).bytes() {
                        out.push_str(&format!("\\x{b:02x}"));
                    }
                }
                c => out.push(c),
            }
        }
        for b in &rest[ok.len()..ok.len() + bad] {
            out.push_str(&format!("\\x{b:02x}"));
        }
        rest = &rest[ok.len() + bad..];
    }
    out.push('"');
}

fn hex(b: &[u8], out: &mut String) {
    out.push_str("h\"");
    for x in b {
        out.push_str(&format!("{x:02x}"));
    }
    out.push('"');
}

/// Decode a protobuf message to text. `Err` when `buf` is not a well-formed message.
pub fn decode_text(buf: &[u8], limit: usize) -> Res<String> {
    let mut out = String::new();
    message(buf, 0, &mut out, limit)?;
    Ok(out)
}

fn message(buf: &[u8], depth: usize, out: &mut String, limit: usize) -> Res<()> {
    let mut pos = 0;
    let pad = "  ".repeat(depth);
    while pos < buf.len() {
        if out.len() > limit {
            return Err(CodecError::TooLarge(limit));
        }
        let tag = varint(buf, &mut pos).ok_or(CodecError::Invalid("protobuf message"))?;
        let (num, wire) = (tag >> 3, tag & 7);
        if num == 0 || num > MAX_FIELD {
            return Err(CodecError::Invalid("protobuf message"));
        }
        match wire {
            0 => {
                let v = varint(buf, &mut pos).ok_or(CodecError::Invalid("protobuf message"))?;
                out.push_str(&format!("{pad}{num}: {v}\n"));
            }
            1 => {
                let b = buf.get(pos..pos + 8).ok_or(CodecError::Invalid("protobuf message"))?;
                pos += 8;
                let v = u64::from_le_bytes(b.try_into().unwrap_or_default());
                out.push_str(&format!("{pad}{num}: fixed64 0x{v:016x}\n"));
            }
            5 => {
                let b = buf.get(pos..pos + 4).ok_or(CodecError::Invalid("protobuf message"))?;
                pos += 4;
                let v = u32::from_le_bytes(b.try_into().unwrap_or_default());
                out.push_str(&format!("{pad}{num}: fixed32 0x{v:08x}\n"));
            }
            2 => {
                let len = varint(buf, &mut pos).ok_or(CodecError::Invalid("protobuf message"))?;
                let len = usize::try_from(len).map_err(|_| CodecError::Invalid("protobuf message"))?;
                let end = pos.checked_add(len).filter(|e| *e <= buf.len());
                let data = &buf[pos..end.ok_or(CodecError::Invalid("protobuf message"))?];
                pos += len;
                if data.is_empty() {
                    out.push_str(&format!("{pad}{num}: \"\"\n"));
                } else if let Some(s) = is_text(data) {
                    out.push_str(&format!("{pad}{num}: "));
                    quote(s.as_bytes(), out);
                    out.push('\n');
                } else {
                    let mut inner = String::new();
                    if depth + 1 < MAX_DEPTH && message(data, depth + 1, &mut inner, limit).is_ok() {
                        out.push_str(&format!("{pad}{num} {{\n{inner}{pad}}}\n"));
                    } else {
                        out.push_str(&format!("{pad}{num}: "));
                        hex(data, out);
                        out.push('\n');
                    }
                }
            }
            _ => return Err(CodecError::Invalid("protobuf message")),
        }
    }
    Ok(())
}

// ---- text to bytes ----

struct Reader<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn skip(&mut self) {
        while let Some(&c) = self.s.get(self.pos) {
            if c.is_ascii_whitespace() {
                self.pos += 1;
            } else if c == b'#' {
                while self.s.get(self.pos).is_some_and(|&c| c != b'\n') {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }
    fn peek(&mut self) -> Option<u8> {
        self.skip();
        self.s.get(self.pos).copied()
    }
    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn word(&mut self) -> &[u8] {
        self.skip();
        let start = self.pos;
        while self.s.get(self.pos).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
            self.pos += 1;
        }
        &self.s[start..self.pos]
    }
}

fn bad() -> CodecError {
    CodecError::Invalid("protobuf text")
}

fn string(r: &mut Reader) -> Res<Vec<u8>> {
    if !r.eat(b'"') {
        return Err(bad());
    }
    let mut out = Vec::new();
    loop {
        let c = *r.s.get(r.pos).ok_or_else(bad)?;
        r.pos += 1;
        match c {
            b'"' => return Ok(out),
            b'\\' => {
                let e = *r.s.get(r.pos).ok_or_else(bad)?;
                r.pos += 1;
                match e {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'"' | b'\\' => out.push(e),
                    b'x' => {
                        let h = r.s.get(r.pos..r.pos + 2).ok_or_else(bad)?;
                        let h = std::str::from_utf8(h).map_err(|_| bad())?;
                        out.push(u8::from_str_radix(h, 16).map_err(|_| bad())?);
                        r.pos += 2;
                    }
                    _ => return Err(bad()),
                }
            }
            c => out.push(c),
        }
    }
}

fn hex_string(r: &mut Reader) -> Res<Vec<u8>> {
    let s = string(r)?;
    if s.len() % 2 != 0 {
        return Err(bad());
    }
    s.chunks(2)
        .map(|p| {
            let t = std::str::from_utf8(p).map_err(|_| bad())?;
            u8::from_str_radix(t, 16).map_err(|_| bad())
        })
        .collect()
}

fn number(r: &mut Reader) -> Res<u64> {
    let w = r.word();
    std::str::from_utf8(w)
        .ok()
        .and_then(|t| {
            t.strip_prefix("0x")
                .map_or_else(|| t.parse().ok(), |h| u64::from_str_radix(h, 16).ok())
        })
        .ok_or_else(bad)
}

fn fields(r: &mut Reader, depth: usize, out: &mut Vec<u8>, limit: usize, close: bool) -> Res<()> {
    if depth > MAX_DEPTH {
        return Err(bad());
    }
    loop {
        match r.peek() {
            None if !close => return Ok(()),
            Some(b'}') if close => {
                r.pos += 1;
                return Ok(());
            }
            None | Some(b'}') => return Err(bad()),
            _ => {}
        }
        if out.len() > limit {
            return Err(CodecError::TooLarge(limit));
        }
        let num = number(r)?;
        if num == 0 || num > MAX_FIELD {
            return Err(bad());
        }
        if r.eat(b'{') {
            let mut inner = Vec::new();
            fields(r, depth + 1, &mut inner, limit, true)?;
            put_varint(out, num << 3 | 2);
            put_varint(out, inner.len() as u64);
            out.extend_from_slice(&inner);
            continue;
        }
        if !r.eat(b':') {
            return Err(bad());
        }
        match r.peek() {
            Some(b'"') => {
                let s = string(r)?;
                put_varint(out, num << 3 | 2);
                put_varint(out, s.len() as u64);
                out.extend_from_slice(&s);
            }
            Some(b'h') if r.s.get(r.pos + 1) == Some(&b'"') => {
                r.pos += 1;
                let s = hex_string(r)?;
                put_varint(out, num << 3 | 2);
                put_varint(out, s.len() as u64);
                out.extend_from_slice(&s);
            }
            _ => {
                let save = r.pos;
                match r.word() {
                    b"fixed32" => {
                        let v = u32::try_from(number(r)?).map_err(|_| bad())?;
                        put_varint(out, num << 3 | 5);
                        out.extend_from_slice(&v.to_le_bytes());
                    }
                    b"fixed64" => {
                        let v = number(r)?;
                        put_varint(out, num << 3 | 1);
                        out.extend_from_slice(&v.to_le_bytes());
                    }
                    _ => {
                        r.pos = save;
                        let v = number(r)?;
                        put_varint(out, num << 3);
                        put_varint(out, v);
                    }
                }
            }
        }
    }
}

/// Read the text form back into protobuf bytes.
pub fn encode_text(text: &[u8], limit: usize) -> Res<Vec<u8>> {
    let mut out = Vec::new();
    fields(&mut Reader { s: text, pos: 0 }, 0, &mut out, limit, false)?;
    if out.len() > limit {
        return Err(CodecError::TooLarge(limit));
    }
    Ok(out)
}

// ---- gRPC framing ----

/// One frame of a gRPC (or gRPC-Web) body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The flag byte: bit 0 compressed, bit 7 trailers (gRPC-Web).
    pub flag: u8,
    pub payload: &'a [u8],
}

/// Split a body into frames. `Err` when a frame is cut short or the flag byte is not one gRPC uses.
pub fn frames(buf: &[u8]) -> Res<Vec<Frame<'_>>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let head = buf.get(pos..pos + 5).ok_or(CodecError::Invalid("gRPC frame"))?;
        let flag = head[0];
        if flag & !0x81 != 0 {
            return Err(CodecError::Invalid("gRPC frame"));
        }
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        pos += 5;
        let payload = pos
            .checked_add(len)
            .and_then(|e| buf.get(pos..e))
            .ok_or(CodecError::Invalid("gRPC frame"))?;
        pos += len;
        out.push(Frame { flag, payload });
    }
    Ok(out)
}

/// A gRPC body as text: `@message` (or `@message compressed`, `@raw`, `@trailers`) lines, each followed by the frame.
pub fn grpc_decode(buf: &[u8], limit: usize) -> Res<String> {
    let mut out = String::new();
    for f in frames(buf)? {
        if out.len() > limit {
            return Err(CodecError::TooLarge(limit));
        }
        if f.flag & 0x80 != 0 {
            out.push_str("@trailers\n");
            quote(f.payload, &mut out);
            out.push('\n');
        } else if f.flag & 1 != 0 {
            out.push_str("@message compressed\n");
            hex(f.payload, &mut out);
            out.push('\n');
        } else {
            out.push_str("@message\n");
            // A message that is not valid protobuf (or is empty) still shows, as bytes.
            match decode_text(f.payload, limit) {
                Ok(t) => out.push_str(&t),
                Err(CodecError::TooLarge(n)) => return Err(CodecError::TooLarge(n)),
                Err(_) => {
                    // Not protobuf (a different codec, say): keep the bytes.
                    out.truncate(out.len() - "@message\n".len());
                    out.push_str("@raw\n");
                    hex(f.payload, &mut out);
                    out.push('\n');
                }
            }
        }
    }
    Ok(out)
}

/// The inverse of [`grpc_decode`].
pub fn grpc_encode(text: &[u8], limit: usize) -> Res<Vec<u8>> {
    let mut out = Vec::new();
    let mut sections: Vec<(u8, Vec<u8>)> = Vec::new();
    for line in text.split(|&b| b == b'\n') {
        let t = line.strip_suffix(b"\r").unwrap_or(line);
        let flag = match t {
            b"@message" => Some(0),
            b"@message compressed" => Some(1),
            b"@trailers" => Some(0x80),
            b"@raw" => Some(0x40),
            _ => None,
        };
        match (flag, sections.last_mut()) {
            (Some(f), _) => sections.push((f, Vec::new())),
            (None, Some((_, body))) => {
                body.extend_from_slice(line);
                body.push(b'\n');
            }
            (None, None) if t.iter().all(u8::is_ascii_whitespace) => {}
            (None, None) => return Err(bad()),
        }
    }
    for (flag, body) in sections {
        let payload = if flag == 0 {
            encode_text(&body, limit)?
        } else {
            let mut r = Reader { s: &body, pos: 0 };
            if flag == 1 || flag == 0x40 {
                if r.peek() != Some(b'h') {
                    return Err(bad());
                }
                r.pos += 1;
                hex_string(&mut r)?
            } else {
                string(&mut r)?
            }
        };
        let len = u32::try_from(payload.len()).map_err(|_| CodecError::TooLarge(limit))?;
        out.push(flag & 0x81);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&payload);
        if out.len() > limit {
            return Err(CodecError::TooLarge(limit));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 1 << 20;

    #[test]
    fn decodes_the_documented_example() {
        // 1: 150, 2: "testing", 3 { 1: 5 }
        let mut b = vec![0x08, 0x96, 0x01, 0x12, 7];
        b.extend_from_slice(b"testing");
        b.extend_from_slice(&[0x1a, 2, 0x08, 5]);
        let t = decode_text(&b, LIMIT).unwrap();
        assert_eq!(t, "1: 150\n2: \"testing\"\n3 {\n  1: 5\n}\n");
        assert_eq!(encode_text(t.as_bytes(), LIMIT).unwrap(), b);
    }

    #[test]
    fn fixed_and_bytes_round_trip() {
        let mut b = vec![0x25, 42, 0, 0, 0]; // 4: fixed32
        b.extend_from_slice(&[0x31, 1, 0, 0, 0, 0, 0, 0, 0]); // 6: fixed64
        b.extend_from_slice(&[0x42, 2, 0xff, 0xfe]); // 8: bytes
        let t = decode_text(&b, LIMIT).unwrap();
        assert!(t.contains("fixed32 0x0000002a") && t.contains("h\"fffe\""), "{t}");
        assert_eq!(encode_text(t.as_bytes(), LIMIT).unwrap(), b);
    }

    #[test]
    fn rejects_garbage_and_deep_nesting() {
        assert!(decode_text(&[0x0a, 0x05, 1], LIMIT).is_err(), "length past the end");
        assert!(decode_text(&[0x00, 0x01], LIMIT).is_err(), "field 0");
        assert!(decode_text(&[0x0b], LIMIT).is_err(), "group");
        let deep = "1 {".repeat(100);
        assert!(encode_text(deep.as_bytes(), LIMIT).is_err());
        assert!(encode_text(b"1: 2 }", LIMIT).is_err());
    }

    #[test]
    fn output_is_capped() {
        let mut b = Vec::new();
        for _ in 0..1000 {
            b.extend_from_slice(&[0x08, 0x01]);
        }
        assert!(matches!(decode_text(&b, 100), Err(CodecError::TooLarge(100))));
    }

    #[test]
    fn grpc_round_trip_with_trailers_and_compressed() {
        let mut body = Vec::new();
        for (flag, p) in [(0u8, vec![0x08, 0x07]), (1, vec![1, 2, 3]), (0x80, b"grpc-status: 0\r\n".to_vec())] {
            body.push(flag);
            body.extend_from_slice(&(p.len() as u32).to_be_bytes());
            body.extend_from_slice(&p);
        }
        let t = grpc_decode(&body, LIMIT).unwrap();
        let raw = grpc_decode(&[0, 0, 0, 0, 2, 0xff, 0xff], LIMIT).unwrap();
        assert_eq!(raw, "@raw\nh\"ffff\"\n");
        assert_eq!(grpc_encode(raw.as_bytes(), LIMIT).unwrap(), [0, 0, 0, 0, 2, 0xff, 0xff]);
        assert!(t.starts_with("@message\n1: 7\n@message compressed\nh\"010203\"\n@trailers\n"), "{t}");
        assert_eq!(grpc_encode(t.as_bytes(), LIMIT).unwrap(), body);
    }

    #[test]
    fn grpc_frames_are_checked() {
        assert!(frames(&[0, 0, 0, 0, 9, 1]).is_err(), "cut short");
        assert!(frames(&[2, 0, 0, 0, 0]).is_err(), "unknown flag");
        assert_eq!(frames(&[]).unwrap().len(), 0);
        assert!(grpc_encode(b"1: 2", LIMIT).is_err(), "no @message line");
    }

    proptest::proptest! {
        #[test]
        fn never_panics(b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300)) {
            let _ = decode_text(&b, 4096);
            let _ = encode_text(&b, 4096);
            let _ = grpc_decode(&b, 4096);
            let _ = grpc_encode(&b, 4096);
        }

        #[test]
        fn built_messages_round_trip(
            fields in proptest::collection::vec((1u64..2000, 0u64..u64::MAX), 0..12),
            s in "[a-zA-Z0-9 ]{1,20}",
        ) {
            let mut b = Vec::new();
            for (n, v) in &fields {
                put_varint(&mut b, n << 3);
                put_varint(&mut b, *v);
            }
            put_varint(&mut b, 9 << 3 | 2);
            put_varint(&mut b, s.len() as u64);
            b.extend_from_slice(s.as_bytes());
            let t = decode_text(&b, LIMIT).unwrap();
            proptest::prop_assert_eq!(encode_text(t.as_bytes(), LIMIT).unwrap(), b);
        }
    }
}
