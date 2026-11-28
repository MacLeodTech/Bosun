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
use crate::schema::{Field, Scalar, Ty, Typed};

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
                (
                    std::str::from_utf8(&rest[..n]).unwrap_or(""),
                    e.error_len().unwrap_or(rest.len() - n),
                )
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
    decode_text_with(buf, limit, None)
}

/// [`decode_text`] with a schema: known fields are shown by name, with their type's value form.
pub fn decode_text_with(buf: &[u8], limit: usize, typed: Option<Typed<'_>>) -> Res<String> {
    let mut out = String::new();
    message(buf, 0, &mut out, limit, typed)?;
    Ok(out)
}

/// A varint field as its schema type shows it; `None` when it does not fit the type (shown as a plain number).
fn varint_text(t: Typed<'_>, ty: &Ty, v: u64) -> Option<String> {
    Some(match ty {
        Ty::Scalar(sc) => match sc {
            Scalar::Int32 => {
                let x = v as i32;
                if i64::from(x) as u64 != v {
                    return None;
                }
                x.to_string()
            }
            Scalar::Int64 => (v as i64).to_string(),
            Scalar::Uint32 => u32::try_from(v).ok()?.to_string(),
            Scalar::Uint64 => v.to_string(),
            Scalar::Sint32 => {
                let u = u32::try_from(v).ok()?;
                (((u >> 1) as i32) ^ -((u & 1) as i32)).to_string()
            }
            Scalar::Sint64 => (((v >> 1) as i64) ^ -((v & 1) as i64)).to_string(),
            Scalar::Bool => match v {
                0 => "false".into(),
                1 => "true".into(),
                _ => return None,
            },
            _ => return None,
        },
        Ty::Enum(n) => {
            let x = v as i32;
            if i64::from(x) as u64 != v {
                return None;
            }
            t.enumeration(n)
                .and_then(|e| e.name_of(x))
                .map_or_else(|| x.to_string(), str::to_owned)
        }
        _ => return None,
    })
}

fn fixed64_text(ty: &Ty, v: u64) -> Option<String> {
    match ty {
        Ty::Scalar(Scalar::Fixed64) => Some(v.to_string()),
        Ty::Scalar(Scalar::Sfixed64) => Some((v as i64).to_string()),
        Ty::Scalar(Scalar::Double) => {
            let f = f64::from_bits(v);
            f.is_finite().then(|| format!("{f:?}"))
        }
        _ => None,
    }
}

fn fixed32_text(ty: &Ty, v: u32) -> Option<String> {
    match ty {
        Ty::Scalar(Scalar::Fixed32) => Some(v.to_string()),
        Ty::Scalar(Scalar::Sfixed32) => Some((v as i32).to_string()),
        Ty::Scalar(Scalar::Float) => {
            let f = f32::from_bits(v);
            f.is_finite().then(|| format!("{f:?}"))
        }
        _ => None,
    }
}

/// A length-delimited field the schema knows: text, bytes, a nested message, or a packed run of numbers.
/// Returns false when it does not fit (the caller then shows it as an unknown field).
fn len_typed(
    t: Typed<'_>,
    f: &Field,
    data: &[u8],
    depth: usize,
    pad: &str,
    out: &mut String,
    limit: usize,
) -> Res<bool> {
    let name = &f.name;
    match &f.ty {
        Ty::Scalar(Scalar::String) => {
            out.push_str(&format!("{pad}{name}: "));
            quote(data, out);
            out.push('\n');
        }
        Ty::Scalar(Scalar::Bytes) => {
            out.push_str(&format!("{pad}{name}: "));
            match is_text(data) {
                Some(s) if !data.is_empty() => quote(s.as_bytes(), out),
                _ => hex(data, out),
            }
            out.push('\n');
        }
        Ty::Message(m) => {
            let Some(sub) = t.sub(m) else { return Ok(false) };
            let mut inner = String::new();
            if depth + 1 >= MAX_DEPTH || message(data, depth + 1, &mut inner, limit, Some(sub)).is_err() {
                return Ok(false);
            }
            out.push_str(&format!("{pad}{name} {{\n{inner}{pad}}}\n"));
        }
        Ty::Scalar(_) | Ty::Enum(_) => {
            // Packed: the elements run together.
            let mut lines = String::new();
            let mut pos = 0;
            while pos < data.len() {
                let text = match &f.ty {
                    Ty::Scalar(Scalar::Fixed32 | Scalar::Sfixed32 | Scalar::Float) => {
                        let b = data.get(pos..pos + 4);
                        pos += 4;
                        b.and_then(|b| {
                            fixed32_text(&f.ty, u32::from_le_bytes(b.try_into().unwrap_or_default()))
                        })
                    }
                    Ty::Scalar(Scalar::Fixed64 | Scalar::Sfixed64 | Scalar::Double) => {
                        let b = data.get(pos..pos + 8);
                        pos += 8;
                        b.and_then(|b| {
                            fixed64_text(&f.ty, u64::from_le_bytes(b.try_into().unwrap_or_default()))
                        })
                    }
                    Ty::Scalar(Scalar::String | Scalar::Bytes) => None,
                    _ => varint(data, &mut pos).and_then(|v| varint_text(t, &f.ty, v)),
                };
                let Some(text) = text else { return Ok(false) };
                lines.push_str(&format!("{pad}{name}: {text}\n"));
                if lines.len() > limit {
                    return Err(CodecError::TooLarge(limit));
                }
            }
            out.push_str(&lines);
        }
        Ty::Opaque => return Ok(false),
    }
    Ok(true)
}

fn message(buf: &[u8], depth: usize, out: &mut String, limit: usize, typed: Option<Typed<'_>>) -> Res<()> {
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
        let field = typed.and_then(|t| t.msg.by_num(num));
        match wire {
            0 => {
                let v = varint(buf, &mut pos).ok_or(CodecError::Invalid("protobuf message"))?;
                match typed
                    .zip(field)
                    .and_then(|(t, f)| varint_text(t, &f.ty, v).map(|s| (f, s)))
                {
                    Some((f, s)) => out.push_str(&format!("{pad}{}: {s}\n", f.name)),
                    None => out.push_str(&format!("{pad}{num}: {v}\n")),
                }
            }
            1 => {
                let b = buf
                    .get(pos..pos + 8)
                    .ok_or(CodecError::Invalid("protobuf message"))?;
                pos += 8;
                let v = u64::from_le_bytes(b.try_into().unwrap_or_default());
                match field.and_then(|f| fixed64_text(&f.ty, v).map(|s| (f, s))) {
                    Some((f, s)) => out.push_str(&format!("{pad}{}: {s}\n", f.name)),
                    None => out.push_str(&format!("{pad}{num}: fixed64 0x{v:016x}\n")),
                }
            }
            5 => {
                let b = buf
                    .get(pos..pos + 4)
                    .ok_or(CodecError::Invalid("protobuf message"))?;
                pos += 4;
                let v = u32::from_le_bytes(b.try_into().unwrap_or_default());
                match field.and_then(|f| fixed32_text(&f.ty, v).map(|s| (f, s))) {
                    Some((f, s)) => out.push_str(&format!("{pad}{}: {s}\n", f.name)),
                    None => out.push_str(&format!("{pad}{num}: fixed32 0x{v:08x}\n")),
                }
            }
            2 => {
                let len = varint(buf, &mut pos).ok_or(CodecError::Invalid("protobuf message"))?;
                let len = usize::try_from(len).map_err(|_| CodecError::Invalid("protobuf message"))?;
                let end = pos.checked_add(len).filter(|e| *e <= buf.len());
                let data = &buf[pos..end.ok_or(CodecError::Invalid("protobuf message"))?];
                pos += len;
                if let Some((t, f)) = typed.zip(field)
                    && len_typed(t, f, data, depth, &pad, out, limit)?
                {
                    continue;
                }
                if data.is_empty() {
                    out.push_str(&format!("{pad}{num}: \"\"\n"));
                } else if let Some(s) = is_text(data) {
                    out.push_str(&format!("{pad}{num}: "));
                    quote(s.as_bytes(), out);
                    out.push('\n');
                } else {
                    let mut inner = String::new();
                    if depth + 1 < MAX_DEPTH && message(data, depth + 1, &mut inner, limit, None).is_ok() {
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
        while self
            .s
            .get(self.pos)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        {
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

/// A word with signs and a point in it, so `-5` and `1.5e-3` are one token.
fn token<'a>(r: &mut Reader<'a>) -> &'a str {
    r.skip();
    let start = r.pos;
    while r
        .s
        .get(r.pos)
        .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'+' | b'-'))
    {
        r.pos += 1;
    }
    std::str::from_utf8(&r.s[start..r.pos]).unwrap_or("")
}

fn int_of(t: &str) -> Option<i128> {
    let (neg, u) = match t.strip_prefix('-') {
        Some(u) => (true, u),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let v = match u.strip_prefix("0x") {
        Some(h) => i128::from_str_radix(h, 16).ok()?,
        None => u.parse::<i128>().ok()?,
    };
    Some(if neg { -v } else { v })
}

/// The value of a field the schema names, written as its type shows it.
fn typed_value(r: &mut Reader, t: Typed<'_>, f: &Field, out: &mut Vec<u8>) -> Res<()> {
    let tok = token(r);
    let tag = |wire: u64| u64::from(f.num) << 3 | wire;
    let (wire, bytes): (u64, Vec<u8>) = match &f.ty {
        Ty::Enum(n) => {
            let v = match int_of(tok) {
                Some(v) => i32::try_from(v).map_err(|_| bad())?,
                None => t.enumeration(n).and_then(|e| e.value_of(tok)).ok_or_else(bad)?,
            };
            let mut b = Vec::new();
            put_varint(&mut b, i64::from(v) as u64);
            (0, b)
        }
        Ty::Scalar(sc) => {
            let int = || int_of(tok).ok_or_else(bad);
            let mut b = Vec::new();
            match sc {
                Scalar::Int32 => put_varint(
                    &mut b,
                    i64::from(i32::try_from(int()?).map_err(|_| bad())?) as u64,
                ),
                Scalar::Int64 => put_varint(&mut b, i64::try_from(int()?).map_err(|_| bad())? as u64),
                Scalar::Uint32 => put_varint(&mut b, u64::from(u32::try_from(int()?).map_err(|_| bad())?)),
                Scalar::Uint64 => put_varint(&mut b, u64::try_from(int()?).map_err(|_| bad())?),
                Scalar::Sint32 => {
                    let x = i32::try_from(int()?).map_err(|_| bad())?;
                    put_varint(&mut b, u64::from(((x << 1) ^ (x >> 31)) as u32));
                }
                Scalar::Sint64 => {
                    let x = i64::try_from(int()?).map_err(|_| bad())?;
                    put_varint(&mut b, ((x << 1) ^ (x >> 63)) as u64);
                }
                Scalar::Bool => put_varint(
                    &mut b,
                    match tok {
                        "true" | "1" => 1,
                        "false" | "0" => 0,
                        _ => return Err(bad()),
                    },
                ),
                Scalar::Fixed32 => {
                    b.extend_from_slice(&u32::try_from(int()?).map_err(|_| bad())?.to_le_bytes());
                    return emit(out, tag(5), &b);
                }
                Scalar::Sfixed32 => {
                    b.extend_from_slice(&i32::try_from(int()?).map_err(|_| bad())?.to_le_bytes());
                    return emit(out, tag(5), &b);
                }
                Scalar::Float => {
                    b.extend_from_slice(&tok.parse::<f32>().map_err(|_| bad())?.to_le_bytes());
                    return emit(out, tag(5), &b);
                }
                Scalar::Fixed64 => {
                    b.extend_from_slice(&u64::try_from(int()?).map_err(|_| bad())?.to_le_bytes());
                    return emit(out, tag(1), &b);
                }
                Scalar::Sfixed64 => {
                    b.extend_from_slice(&i64::try_from(int()?).map_err(|_| bad())?.to_le_bytes());
                    return emit(out, tag(1), &b);
                }
                Scalar::Double => {
                    b.extend_from_slice(&tok.parse::<f64>().map_err(|_| bad())?.to_le_bytes());
                    return emit(out, tag(1), &b);
                }
                Scalar::String | Scalar::Bytes => return Err(bad()),
            }
            (0, b)
        }
        _ => return Err(bad()),
    };
    emit(out, tag(wire), &bytes)
}

fn emit(out: &mut Vec<u8>, tag: u64, bytes: &[u8]) -> Res<()> {
    put_varint(out, tag);
    out.extend_from_slice(bytes);
    Ok(())
}

fn fields(
    r: &mut Reader,
    depth: usize,
    out: &mut Vec<u8>,
    limit: usize,
    close: bool,
    typed: Option<Typed<'_>>,
) -> Res<()> {
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
        // The field is a number, or (with a schema) its name.
        let (num, field, named) = if r.peek().is_some_and(|c| c.is_ascii_digit()) {
            let n = number(r)?;
            (n, typed.and_then(|t| t.msg.by_num(n)), false)
        } else {
            let name = String::from_utf8_lossy(r.word()).into_owned();
            let f = typed.and_then(|t| t.msg.by_name(&name)).ok_or_else(bad)?;
            (u64::from(f.num), Some(f), true)
        };
        if num == 0 || num > MAX_FIELD {
            return Err(bad());
        }
        if r.eat(b'{') {
            let sub = match (typed, field) {
                (
                    Some(t),
                    Some(Field {
                        ty: Ty::Message(m), ..
                    }),
                ) => t.sub(m),
                _ => None,
            };
            if named && sub.is_none() {
                return Err(bad());
            }
            let mut inner = Vec::new();
            fields(r, depth + 1, &mut inner, limit, true, sub)?;
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
            _ if named => {
                let (Some(t), Some(f)) = (typed, field) else {
                    return Err(bad());
                };
                typed_value(r, t, f, out)?;
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
    encode_text_with(text, limit, None)
}

/// [`encode_text`] with a schema: a field may be written by its name, with a value in its type's form.
pub fn encode_text_with(text: &[u8], limit: usize, typed: Option<Typed<'_>>) -> Res<Vec<u8>> {
    let mut out = Vec::new();
    fields(&mut Reader { s: text, pos: 0 }, 0, &mut out, limit, false, typed)?;
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

/// How a compressed gRPC message was compressed (the `grpc-encoding` header says; the bytes say it too).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Packing {
    Gzip,
    /// zlib, which is what gRPC calls `deflate`.
    Deflate,
    Zstd,
}

impl Packing {
    fn name(self) -> &'static str {
        match self {
            Packing::Gzip => "gzip",
            Packing::Deflate => "deflate",
            Packing::Zstd => "zstd",
        }
    }
    fn from_name(n: &[u8]) -> Option<Packing> {
        match n {
            b"gzip" => Some(Packing::Gzip),
            b"deflate" => Some(Packing::Deflate),
            b"zstd" => Some(Packing::Zstd),
            _ => None,
        }
    }
    fn sniff(b: &[u8]) -> Option<Packing> {
        match b {
            [0x1f, 0x8b, ..] => Some(Packing::Gzip),
            [0x28, 0xb5, 0x2f, 0xfd, ..] => Some(Packing::Zstd),
            [a, b, ..] if a & 0x0f == 8 && (u16::from(*a) << 8 | u16::from(*b)) % 31 == 0 => {
                Some(Packing::Deflate)
            }
            _ => None,
        }
    }
    fn unpack(self, b: &[u8], limit: usize) -> Res<Vec<u8>> {
        match self {
            Packing::Gzip => crate::ops::bounded(flate2::read::MultiGzDecoder::new(b), limit, "gzip data"),
            Packing::Deflate => crate::ops::bounded(flate2::read::ZlibDecoder::new(b), limit, "deflate data"),
            Packing::Zstd => {
                let d = zstd::stream::read::Decoder::new(b).map_err(|_| CodecError::Invalid("zstd data"))?;
                crate::ops::bounded(d, limit, "zstd data")
            }
        }
    }
    fn pack(self, b: &[u8]) -> Res<Vec<u8>> {
        use std::io::Write as _;
        let bad = |_| CodecError::Invalid("input");
        match self {
            Packing::Gzip => {
                let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(b).map_err(bad)?;
                e.finish().map_err(bad)
            }
            Packing::Deflate => {
                let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(b).map_err(bad)?;
                e.finish().map_err(bad)
            }
            Packing::Zstd => zstd::encode_all(b, 3).map_err(bad),
        }
    }
}

/// A gRPC body as text: `@message` (or `@message compressed gzip`, `@message compressed`, `@raw`, `@trailers`)
/// lines, each followed by the frame.
pub fn grpc_decode(buf: &[u8], limit: usize) -> Res<String> {
    grpc_decode_with(buf, limit, None)
}

/// [`grpc_decode`] with a schema for the messages.
pub fn grpc_decode_with(buf: &[u8], limit: usize, typed: Option<Typed<'_>>) -> Res<String> {
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
            // Compressed: when the bytes say how, and they unpack to a protobuf message, show that message.
            let mut shown = None;
            if let Some(p) = Packing::sniff(f.payload) {
                match p.unpack(f.payload, limit) {
                    Ok(plain) => match decode_text_with(&plain, limit, typed) {
                        Ok(t) => shown = Some((p, t)),
                        Err(CodecError::TooLarge(n)) => return Err(CodecError::TooLarge(n)),
                        Err(_) => {}
                    },
                    Err(CodecError::TooLarge(n)) => return Err(CodecError::TooLarge(n)),
                    Err(_) => {}
                }
            }
            if let Some((p, t)) = shown {
                out.push_str(&format!("@message compressed {}\n{t}", p.name()));
            } else {
                out.push_str("@message compressed\n");
                hex(f.payload, &mut out);
                out.push('\n');
            }
        } else {
            out.push_str("@message\n");
            // A message that is not valid protobuf (or is empty) still shows, as bytes.
            match decode_text_with(f.payload, limit, typed) {
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
    grpc_encode_with(text, limit, None)
}

/// [`grpc_encode`] with a schema for the messages.
pub fn grpc_encode_with(text: &[u8], limit: usize, typed: Option<Typed<'_>>) -> Res<Vec<u8>> {
    let mut out = Vec::new();
    // Each section: its flag (0x40 is a `@raw` payload, which goes out as flag 0), how it is packed, its lines.
    let mut sections: Vec<(u8, Option<Packing>, Vec<u8>)> = Vec::new();
    for line in text.split(|&b| b == b'\n') {
        let t = line.strip_suffix(b"\r").unwrap_or(line);
        let head = match t {
            b"@message" => Some((0, None)),
            b"@message compressed" => Some((1, None)),
            b"@trailers" => Some((0x80, None)),
            b"@raw" => Some((0x40, None)),
            _ => t
                .strip_prefix(b"@message compressed ")
                .and_then(Packing::from_name)
                .map(|p| (1, Some(p))),
        };
        match (head, sections.last_mut()) {
            (Some((f, p)), _) => sections.push((f, p, Vec::new())),
            (None, Some((_, _, body))) => {
                body.extend_from_slice(line);
                body.push(b'\n');
            }
            (None, None) if t.iter().all(u8::is_ascii_whitespace) => {}
            (None, None) => return Err(bad()),
        }
    }
    for (flag, packing, body) in sections {
        let payload = if let Some(p) = packing {
            p.pack(&encode_text_with(&body, limit, typed)?)?
        } else if flag == 0 {
            encode_text_with(&body, limit, typed)?
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
    use crate::schema::Schema;

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
        assert!(
            decode_text(&[0x0a, 0x05, 1], LIMIT).is_err(),
            "length past the end"
        );
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
        for (flag, p) in [
            (0u8, vec![0x08, 0x07]),
            (1, vec![1, 2, 3]),
            (0x80, b"grpc-status: 0\r\n".to_vec()),
        ] {
            body.push(flag);
            body.extend_from_slice(&(p.len() as u32).to_be_bytes());
            body.extend_from_slice(&p);
        }
        let t = grpc_decode(&body, LIMIT).unwrap();
        let raw = grpc_decode(&[0, 0, 0, 0, 2, 0xff, 0xff], LIMIT).unwrap();
        assert_eq!(raw, "@raw\nh\"ffff\"\n");
        assert_eq!(
            grpc_encode(raw.as_bytes(), LIMIT).unwrap(),
            [0, 0, 0, 0, 2, 0xff, 0xff]
        );
        assert!(
            t.starts_with("@message\n1: 7\n@message compressed\nh\"010203\"\n@trailers\n"),
            "{t}"
        );
        assert_eq!(grpc_encode(t.as_bytes(), LIMIT).unwrap(), body);
    }

    #[test]
    fn grpc_frames_are_checked() {
        assert!(frames(&[0, 0, 0, 0, 9, 1]).is_err(), "cut short");
        assert!(frames(&[2, 0, 0, 0, 0]).is_err(), "unknown flag");
        assert_eq!(frames(&[]).unwrap().len(), 0);
        assert!(grpc_encode(b"1: 2", LIMIT).is_err(), "no @message line");
    }

    const SCHEMA: &str = r#"
        syntax = "proto3";
        package shop.v1;
        message Customer {
          enum Tier { BRONZE = 0; SILVER = 1; GOLD = 2; }
          int32 id = 1;
          string name = 2;
          Tier tier = 3;
          repeated sint64 deltas = 4;
          Address home = 5;
          map<string, int32> labels = 6;
          double ratio = 7;
          bool vip = 8;
          bytes blob = 9;
          fixed32 crc = 10;
          float temp = 11;
          int64 big = 12;
          message Address { string city = 1; }
        }
        service Shop { rpc Get (Customer) returns (Customer); }
    "#;

    fn typed(s: &Schema) -> Typed<'_> {
        s.typed("Customer").unwrap()
    }

    #[test]
    fn schema_names_fields_and_edits_by_name() {
        let s = Schema::parse(SCHEMA).unwrap();
        let text = "id: -7\nname: \"Ann\"\ntier: GOLD\ndeltas: -3\ndeltas: 4\nhome {\n  city: \"Oslo\"\n}\nlabels {\n  key: \"a\"\n  value: 1\n}\nratio: 0.25\nvip: true\nblob: h\"00ff\"\ncrc: 3735928559\ntemp: 1.5\nbig: -9000000000\n99: 5\n";
        let bytes = encode_text_with(text.as_bytes(), LIMIT, Some(typed(&s))).unwrap();
        // The same bytes, read without a schema, only have numbers.
        let plain = decode_text(&bytes, LIMIT).unwrap();
        assert!(plain.contains("1: 18446744073709551609"), "{plain}");
        assert_eq!(decode_text_with(&bytes, LIMIT, Some(typed(&s))).unwrap(), text);
        assert_eq!(
            encode_text(plain.as_bytes(), LIMIT).unwrap(),
            bytes,
            "numbers still encode the same bytes"
        );
    }

    #[test]
    fn schema_reads_packed_runs_and_odd_values_fall_back_to_numbers() {
        let s = Schema::parse(SCHEMA).unwrap();
        // deltas (field 4) packed: zigzag 6 and 7 are 3 and -4.
        let t = decode_text_with(&[0x22, 0x02, 6, 7], LIMIT, Some(typed(&s))).unwrap();
        assert_eq!(t, "deltas: 3\ndeltas: -4\n");
        // bool 2 is not a bool, an enum value with no name keeps its number, a string where an int goes stays numeric.
        assert_eq!(
            decode_text_with(&[0x40, 2], LIMIT, Some(typed(&s))).unwrap(),
            "8: 2\n"
        );
        assert_eq!(
            decode_text_with(&[0x18, 9], LIMIT, Some(typed(&s))).unwrap(),
            "tier: 9\n"
        );
        assert_eq!(
            decode_text_with(&[0x0a, 2, 0xff, 0xff], LIMIT, Some(typed(&s))).unwrap(),
            "1: h\"ffff\"\n"
        );
        // An int32 with bits above 32 cannot be shown as one.
        let wide = [0x08, 0x81, 0x80, 0x80, 0x80, 0x10];
        let t = decode_text_with(&wide, LIMIT, Some(typed(&s))).unwrap();
        assert_eq!(t, "1: 4294967297\n");
        assert_eq!(
            encode_text_with(t.as_bytes(), LIMIT, Some(typed(&s))).unwrap(),
            wide
        );
    }

    #[test]
    fn schema_errors_name_nothing_it_does_not_know() {
        let s = Schema::parse(SCHEMA).unwrap();
        let t = Some(typed(&s));
        for bad in [
            "nope: 1",
            "id: abc",
            "id: 99999999999",
            "name: 5",
            "home: 1",
            "vip: maybe",
            "tier: PLATINUM",
            "id {\n}",
        ] {
            assert!(encode_text_with(bad.as_bytes(), LIMIT, t).is_err(), "{bad}");
        }
        assert!(encode_text(b"id: 1", LIMIT).is_err(), "names need a schema");
    }

    #[test]
    fn grpc_follows_the_rpc_types_and_unpacks_compressed_messages() {
        let s = Schema::parse(SCHEMA).unwrap();
        let (req, _) = s.rpc("/shop.v1.Shop/Get").unwrap();
        for name in ["gzip", "deflate", "zstd"] {
            let text = format!(
                "@message\nid: 5\n@message compressed {name}\nname: \"x\"\n@trailers\n\"grpc-status: 0\\r\\n\"\n"
            );
            let body = grpc_encode_with(text.as_bytes(), LIMIT, Some(req)).unwrap();
            assert_eq!(body[5 + 2], 1, "the second frame is flagged compressed: {name}");
            assert_eq!(grpc_decode_with(&body, LIMIT, Some(req)).unwrap(), text, "{name}");
            // Without the schema it is the same bytes, with numbers.
            assert!(
                grpc_decode(&body, LIMIT)
                    .unwrap()
                    .contains(&format!("@message compressed {name}\n2: \"x\""))
            );
        }
        // An unknown algorithm, or bytes that unpack to something else, stay as hex.
        let t = grpc_decode(&[1, 0, 0, 0, 3, 9, 9, 9], LIMIT).unwrap();
        assert_eq!(t, "@message compressed\nh\"090909\"\n");
        // A bomb is refused, not expanded.
        let big = Packing::Gzip.pack(&vec![0u8; 1 << 20]).unwrap();
        let mut body = vec![1];
        body.extend_from_slice(&(big.len() as u32).to_be_bytes());
        body.extend_from_slice(&big);
        assert!(matches!(grpc_decode(&body, 4096), Err(CodecError::TooLarge(_))));
    }

    proptest::proptest! {
        // Messages built field by field, read with the schema: whatever it shows can be read back, and reading the
        // result again shows the same text.
        #[test]
        fn typed_text_always_reads_back(
            fields in proptest::collection::vec((1u64..14, 0u8..4, 0u64..u64::MAX, "[a-z ]{0,8}"), 0..12),
        ) {
            let s = Schema::parse(SCHEMA).unwrap();
            let t = Some(typed(&s));
            let mut b = Vec::new();
            for (num, kind, v, text) in fields {
                match kind {
                    0 => { put_varint(&mut b, num << 3); put_varint(&mut b, v); }
                    1 => { put_varint(&mut b, num << 3 | 1); b.extend_from_slice(&v.to_le_bytes()); }
                    2 => { put_varint(&mut b, num << 3 | 5); b.extend_from_slice(&(v as u32).to_le_bytes()); }
                    _ => { put_varint(&mut b, num << 3 | 2); put_varint(&mut b, text.len() as u64); b.extend_from_slice(text.as_bytes()); }
                }
            }
            let text = decode_text_with(&b, 1 << 20, t).unwrap();
            let again = encode_text_with(text.as_bytes(), 1 << 20, t).unwrap();
            proptest::prop_assert_eq!(decode_text_with(&again, 1 << 20, t).unwrap(), text);
        }

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
