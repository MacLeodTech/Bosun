//! HTTP/2 with a frame writer of our own, so malformed requests are possible.
//!
//! A hyper or h2 client refuses to send an upper-case header name, a missing `:path`, a `HEADERS` frame on stream
//! 0 or a length that does not match. Here a request is a list of [`Frame`]s and each is written as described. The
//! helpers ([`H2Request::into_plan`]) build the usual frames for a well-formed request, and everything can then
//! be edited before sending.
//!
//! What the engine does on its own, so a plan only needs the interesting frames: the connection preface and a
//! `SETTINGS` frame (unless the plan gives its own), acknowledging the server's `SETTINGS` and `PING`s
//! (`auto_ack`), and a large receive window so responses are not stalled. Everything the server sends is kept as
//! frames in [`H2Details`].

use std::time::{Duration, Instant};

use bosun_proxy::budget::COPY_FACTOR;
use fluke_hpack::{Decoder, Encoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Engine, Exchange, SendError, SendOptions, gate_path};

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub mod ty {
    pub const DATA: u8 = 0;
    pub const HEADERS: u8 = 1;
    pub const PRIORITY: u8 = 2;
    pub const RST_STREAM: u8 = 3;
    pub const SETTINGS: u8 = 4;
    pub const PUSH_PROMISE: u8 = 5;
    pub const PING: u8 = 6;
    pub const GOAWAY: u8 = 7;
    pub const WINDOW_UPDATE: u8 = 8;
    pub const CONTINUATION: u8 = 9;
}

pub mod flag {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// One HTTP/2 frame, as written or as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ty: u8,
    pub flags: u8,
    /// The stream id including its reserved top bit, as it goes on the wire.
    pub stream: u32,
    pub payload: Vec<u8>,
    /// Write this in the length field instead of the real payload length (a lie on purpose). Only for sending.
    pub declared_len: Option<u32>,
}

impl Frame {
    pub fn new(ty: u8, flags: u8, stream: u32, payload: Vec<u8>) -> Self {
        Self {
            ty,
            flags,
            stream,
            payload,
            declared_len: None,
        }
    }

    pub fn settings(values: &[(u16, u32)]) -> Self {
        let mut p = Vec::with_capacity(values.len() * 6);
        for (id, v) in values {
            p.extend_from_slice(&id.to_be_bytes());
            p.extend_from_slice(&v.to_be_bytes());
        }
        Self::new(ty::SETTINGS, 0, 0, p)
    }

    pub fn window_update(stream: u32, increment: u32) -> Self {
        Self::new(ty::WINDOW_UPDATE, 0, stream, increment.to_be_bytes().to_vec())
    }

    pub fn rst_stream(stream: u32, code: u32) -> Self {
        Self::new(ty::RST_STREAM, 0, stream, code.to_be_bytes().to_vec())
    }

    pub fn encode(&self) -> Vec<u8> {
        let len = self.declared_len.unwrap_or(self.payload.len() as u32);
        let mut out = Vec::with_capacity(9 + self.payload.len());
        out.extend_from_slice(&len.to_be_bytes()[1..]);
        out.push(self.ty);
        out.push(self.flags);
        out.extend_from_slice(&self.stream.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

/// Parse one frame from the start of `buf`: the frame and the bytes it took, `Ok(None)` if more is needed,
/// `Err(length)` if the declared payload is over `max_payload`.
pub fn parse_frame(buf: &[u8], max_payload: usize) -> Result<Option<(Frame, usize)>, usize> {
    if buf.len() < 9 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
    if len > max_payload {
        return Err(len);
    }
    if buf.len() < 9 + len {
        return Ok(None);
    }
    Ok(Some((
        Frame {
            ty: buf[3],
            flags: buf[4],
            stream: u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]),
            payload: buf[9..9 + len].to_vec(),
            declared_len: None,
        },
        9 + len,
    )))
}

/// A request as a list of headers (pseudo-headers included, in the order and spelling given) and a body.
#[derive(Debug, Clone, Default)]
pub struct H2Request {
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
    /// Split the header block over `HEADERS` and `CONTINUATION` frames of at most this many bytes.
    pub header_chunk: Option<usize>,
}

impl H2Request {
    /// The usual four pseudo-headers, then `headers`.
    pub fn new(method: &str, scheme: &str, authority: &str, path: &str, headers: &[(&str, &str)]) -> Self {
        let mut h: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), method.as_bytes().to_vec()),
            (b":scheme".to_vec(), scheme.as_bytes().to_vec()),
            (b":authority".to_vec(), authority.as_bytes().to_vec()),
            (b":path".to_vec(), path.as_bytes().to_vec()),
        ];
        h.extend(
            headers
                .iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())),
        );
        Self {
            headers: h,
            body: Vec::new(),
            header_chunk: None,
        }
    }

    /// The frames for this request on `stream`: `HEADERS` (and `CONTINUATION`s) with `END_HEADERS`, then one
    /// `DATA` frame with `END_STREAM` if there is a body (otherwise `END_STREAM` is on the `HEADERS`).
    pub fn frames(&self, stream: u32) -> Vec<Frame> {
        let block = Encoder::new().encode(self.headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        let end_stream = if self.body.is_empty() { flag::END_STREAM } else { 0 };
        let mut out = Vec::new();
        match self.header_chunk.filter(|n| *n > 0 && *n < block.len()) {
            None => out.push(Frame::new(
                ty::HEADERS,
                flag::END_HEADERS | end_stream,
                stream,
                block,
            )),
            Some(n) => {
                let mut chunks = block.chunks(n).peekable();
                if let Some(first) = chunks.next() {
                    out.push(Frame::new(ty::HEADERS, end_stream, stream, first.to_vec()));
                }
                while let Some(c) = chunks.next() {
                    let f = if chunks.peek().is_none() {
                        flag::END_HEADERS
                    } else {
                        0
                    };
                    out.push(Frame::new(ty::CONTINUATION, f, stream, c.to_vec()));
                }
            }
        }
        if !self.body.is_empty() {
            out.push(Frame::new(ty::DATA, flag::END_STREAM, stream, self.body.clone()));
        }
        out
    }

    /// A plan that sends this request on stream 1 and waits for its response.
    pub fn into_plan(self) -> H2Plan {
        H2Plan {
            frames: self.frames(1),
            wait_stream: Some(1),
            ..H2Plan::default()
        }
    }
}

/// What to send on an HTTP/2 connection, after the preface.
#[derive(Debug, Clone)]
pub struct H2Plan {
    /// Our `SETTINGS` as `(id, value)`. `None` sends sensible defaults (no push, a large window); `Some` sends
    /// exactly these, and no window update.
    pub settings: Option<Vec<(u16, u32)>>,
    /// The frames to write, in order, exactly as given.
    pub frames: Vec<Frame>,
    /// Stop when this stream ends (or is reset). `None` reads until the connection closes or goes quiet.
    pub wait_stream: Option<u32>,
    /// Acknowledge the server's `SETTINGS` and `PING`s.
    pub auto_ack: bool,
    /// With no `wait_stream`, how long a quiet connection is read before giving up.
    pub linger: Duration,
}

impl Default for H2Plan {
    fn default() -> Self {
        Self {
            settings: None,
            frames: Vec::new(),
            wait_stream: Some(1),
            auto_ack: true,
            linger: Duration::from_millis(500),
        }
    }
}

/// What happened on the wire, besides the response.
#[derive(Debug, Clone, Default)]
pub struct H2Details {
    /// Every frame written after the preface, including the engine's own (settings, acknowledgements).
    pub frames_out: Vec<Frame>,
    /// Every frame received.
    pub frames_in: Vec<Frame>,
    /// `(last stream id, error code)` of a `GOAWAY` the server sent.
    pub goaway: Option<(u32, u32)>,
    /// The error code of a `RST_STREAM` on the stream we waited for.
    pub rst: Option<u32>,
    /// The decoded response headers of the stream we waited for (informational `1xx` ones first).
    pub response_headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// The decoded request headers (the first request in the plan).
    pub request_headers: Vec<(Vec<u8>, Vec<u8>)>,
}

type Headers = Vec<(Vec<u8>, Vec<u8>)>;

/// A complete header block, decoded.
#[derive(Debug)]
pub(crate) struct Block {
    pub stream: u32,
    pub end_stream: bool,
    pub headers: Headers,
}

struct Pending {
    stream: u32,
    end_stream: bool,
    block: Vec<u8>,
}

/// Rebuilds header blocks from `HEADERS`, `PUSH_PROMISE` and `CONTINUATION` frames, in order, because HPACK's
/// table depends on every block before.
pub(crate) struct HeaderCollector {
    dec: Decoder<'static>,
    pending: Option<Pending>,
    /// The decoder panicked once; its table can no longer be trusted.
    poisoned: bool,
}

impl HeaderCollector {
    pub fn new() -> Self {
        Self {
            dec: Decoder::new(),
            pending: None,
            poisoned: false,
        }
    }

    pub fn feed(&mut self, f: &Frame) -> Result<Option<Block>, String> {
        match f.ty {
            ty::HEADERS | ty::PUSH_PROMISE => {
                let mut p = f.payload.as_slice();
                if f.flags & flag::PADDED != 0 {
                    let pad = *p.first().ok_or("padded frame without a pad length")? as usize;
                    p = &p[1..];
                    p = p
                        .get(
                            ..p.len()
                                .checked_sub(pad)
                                .ok_or("padding is longer than the frame")?,
                        )
                        .unwrap_or(&[]);
                }
                if f.ty == ty::HEADERS && f.flags & flag::PRIORITY != 0 {
                    p = p.get(5..).ok_or("priority fields are cut off")?;
                }
                if f.ty == ty::PUSH_PROMISE {
                    p = p.get(4..).ok_or("promised stream id is cut off")?;
                }
                let pending = Pending {
                    stream: f.stream & 0x7fff_ffff,
                    end_stream: f.ty == ty::HEADERS && f.flags & flag::END_STREAM != 0,
                    block: p.to_vec(),
                };
                if f.flags & flag::END_HEADERS != 0 {
                    self.finish(pending).map(Some)
                } else {
                    self.pending = Some(pending);
                    Ok(None)
                }
            }
            ty::CONTINUATION => {
                let Some(mut pending) = self.pending.take() else {
                    return Ok(None);
                };
                if pending.stream != f.stream & 0x7fff_ffff {
                    return Err("CONTINUATION on a different stream".into());
                }
                pending.block.extend_from_slice(&f.payload);
                if f.flags & flag::END_HEADERS != 0 {
                    self.finish(pending).map(Some)
                } else {
                    self.pending = Some(pending);
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    fn finish(&mut self, p: Pending) -> Result<Block, String> {
        if self.poisoned {
            return Err("HPACK: an earlier header block broke the decoder".into());
        }
        // The decoder crate panics on some cut-off blocks (a truncated table-size update), and these bytes come
        // from the server. Check the block's structure first, and keep a panic from reaching the caller.
        well_formed(&p.block).map_err(|e| format!("HPACK: {e}"))?;
        let dec = &mut self.dec;
        let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dec.decode(&p.block)));
        let headers = match decoded {
            Ok(r) => r.map_err(|e| format!("HPACK: {e:?}"))?,
            Err(_) => {
                self.poisoned = true;
                return Err("HPACK: the decoder failed on this block".into());
            }
        };
        Ok(Block {
            stream: p.stream,
            end_stream: p.end_stream,
            headers,
        })
    }
}

/// Read an HPACK integer with an `n`-bit prefix from the start of `b`; the value and the bytes it took.
fn hpack_int(b: &[u8], n: u8) -> Result<(usize, usize), &'static str> {
    let mask = (1usize << n) - 1;
    let first = (*b.first().ok_or("cut off")? as usize) & mask;
    if first < mask {
        return Ok((first, 1));
    }
    let (mut value, mut shift) = (mask, 0u32);
    for (i, byte) in b.iter().enumerate().skip(1) {
        value = value
            .checked_add(((*byte & 0x7f) as usize) << shift)
            .ok_or("integer too large")?;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        // The decoder crate refuses integers of more than five octets (about 2^28), so this does too.
        if i + 1 >= 5 {
            return Err("integer has too many octets");
        }
        shift += 7;
    }
    Err("cut off")
}

/// Walk a header block's structure (without decoding it) and say whether every representation is complete.
fn well_formed(mut b: &[u8]) -> Result<(), &'static str> {
    while let Some(&first) = b.first() {
        // (prefix bits of the first integer, whether a name string follows when that integer is 0, value string?)
        let (prefix, strings) = if first & 0x80 != 0 {
            (7, 0)
        } else if first & 0x40 != 0 {
            (6, 2)
        } else if first & 0x20 != 0 {
            (5, 0)
        } else {
            (4, 2)
        };
        let (idx, used) = hpack_int(b, prefix)?;
        b = &b[used..];
        for i in 0..strings {
            // A name string is only present when the name index is 0; a value string always is.
            if i == 0 && idx != 0 {
                continue;
            }
            let (len, used) = hpack_int(b, 7)?;
            b = b.get(used..).ok_or("cut off")?;
            b = b.get(len..).ok_or("string runs past the block")?;
        }
    }
    Ok(())
}

/// Decode the request headers of every `HEADERS` block in `frames`, in order.
pub fn decode_plan_headers(frames: &[Frame]) -> Result<Vec<(u32, Headers)>, String> {
    let mut c = HeaderCollector::new();
    let mut out = Vec::new();
    for f in frames {
        if let Some(b) = c.feed(f)? {
            out.push((b.stream, b.headers));
        }
    }
    Ok(out)
}

fn pseudo<'a>(h: &'a Headers, name: &str) -> Option<&'a [u8]> {
    h.iter()
        .find(|(n, _)| n == name.as_bytes())
        .map(|(_, v)| v.as_slice())
}

/// A text rendering of a request for storage and display: `METHOD path HTTP/2`, then the headers, then the body.
fn render_request(h: &Headers, body: &[u8]) -> Vec<u8> {
    let lossy = |b: Option<&[u8]>| b.map_or(String::new(), |b| String::from_utf8_lossy(b).into_owned());
    let mut out = format!(
        "{} {} HTTP/2\r\n",
        lossy(pseudo(h, ":method")),
        lossy(pseudo(h, ":path"))
    )
    .into_bytes();
    if let Some(a) = pseudo(h, ":authority") {
        out.extend_from_slice(b"host: ");
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
    push_headers(&mut out, h);
    out.extend_from_slice(body);
    out
}

fn render_response(status: &[u8], h: &Headers, body: &[u8]) -> Vec<u8> {
    let mut out = b"HTTP/2 ".to_vec();
    out.extend_from_slice(status);
    out.extend_from_slice(b"\r\n");
    push_headers(&mut out, h);
    out.extend_from_slice(body);
    out
}

fn push_headers(out: &mut Vec<u8>, h: &Headers) {
    for (n, v) in h.iter().filter(|(n, _)| !n.starts_with(b":")) {
        out.extend_from_slice(n);
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

/// The payload of a `DATA` frame without its padding.
fn data_payload(f: &Frame) -> &[u8] {
    if f.flags & flag::PADDED == 0 {
        return &f.payload;
    }
    let Some((&pad, rest)) = f.payload.split_first() else {
        return &[];
    };
    rest.get(..rest.len().saturating_sub(pad as usize)).unwrap_or(&[])
}

impl Engine {
    /// Send an HTTP/2 plan and read the response. Over `https` the handshake offers only `h2`; over `http` it is
    /// HTTP/2 with prior knowledge (h2c).
    ///
    /// The plan's `HEADERS` frames are decoded to check scope (the `:path` of every request in it goes through
    /// the gate), so a plan whose header blocks cannot be decoded is refused. Everything else about the frames is
    /// sent as written.
    pub async fn send_h2(
        &self,
        target: &bosun_model::Target,
        plan: &H2Plan,
        opts: &SendOptions,
    ) -> Result<Exchange, SendError> {
        let started = Instant::now();
        let requests = decode_plan_headers(&plan.frames).map_err(|_| {
            SendError::BadRequest("the HEADERS frames cannot be decoded, so scope cannot be checked")
        })?;
        let first = requests.first().map(|(_, h)| h.clone()).unwrap_or_default();
        let body: Vec<u8> = plan
            .frames
            .iter()
            .filter(|f| {
                f.ty == ty::DATA
                    && requests
                        .first()
                        .is_some_and(|(s, _)| *s == f.stream & 0x7fff_ffff)
            })
            .flat_map(|f| data_payload(f).to_vec())
            .collect();
        let paths: Vec<String> = {
            let mut p: Vec<String> = requests
                .iter()
                .map(|(_, h)| gate_path(&String::from_utf8_lossy(pseudo(h, ":path").unwrap_or(b"/"))))
                .collect();
            if p.is_empty() {
                p.push("/".into());
            }
            p.dedup();
            p
        };
        let mut o = self
            .open(target, &paths[0], render_request(&first, &body), opts, true)
            .await?;
        // Other requests in the plan may name other paths: each goes through the gate too.
        for extra in paths.iter().skip(1) {
            let gate = self.gate().clone();
            let (source, scheme, host, port, path) = (
                opts.source,
                target.scheme,
                target.host.clone(),
                target.port,
                extra.clone(),
            );
            tokio::task::spawn_blocking(move || gate.check(source, scheme, &host, port, &path))
                .await
                .map_err(|e| SendError::Connect(target.host.clone(), e.to_string()))??;
        }
        if let Some(t) = &o.ex.tls
            && t.alpn.as_deref() != Some("h2")
        {
            return Err(SendError::Tls(
                target.host.clone(),
                "the server did not negotiate h2".into(),
            ));
        }

        let mut details = H2Details {
            request_headers: first,
            ..H2Details::default()
        };
        let deadline = started + opts.total_timeout;
        let written = Instant::now();
        let window = opts.max_response.clamp(65_535, 0x7fff_ffff) as u32;
        let mut out: Vec<Frame> = Vec::new();
        match &plan.settings {
            Some(s) => out.push(Frame::settings(s)),
            None => {
                out.push(Frame::settings(&[(0x2, 0), (0x4, window)]));
                if window > 65_535 {
                    out.push(Frame::window_update(0, window - 65_535));
                }
            }
        }
        out.extend(plan.frames.iter().cloned());
        let mut wire = PREFACE.to_vec();
        for f in &out {
            wire.extend_from_slice(&f.encode());
        }
        details.frames_out = out;
        let w = async {
            o.io.write_all(&wire).await?;
            o.io.flush().await
        };
        match tokio::time::timeout_at(deadline.into(), w).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(SendError::Write(e.to_string())),
            Err(_) => return Err(SendError::Write("timed out".into())),
        }

        let mut res = self.budget().reserve(64 * 1024).ok_or(SendError::OutOfMemory)?;
        let mut collector = HeaderCollector::new();
        let (mut buf, mut chunk) = (Vec::new(), vec![0u8; 16 * 1024]);
        let mut total_in = 0usize;
        let mut resp_body: Vec<u8> = Vec::new();
        let mut done = false;
        let mut first_byte = None;
        while !done {
            // Everything buffered is parsed before reading more.
            loop {
                let (f, n) = match parse_frame(&buf, opts.max_response) {
                    Ok(Some(x)) => x,
                    Ok(None) => break,
                    Err(len) => {
                        o.ex.error = Some(format!("a frame of {len} bytes is over the limit"));
                        done = true;
                        break;
                    }
                };
                buf.drain(..n);
                let mut reply = Vec::new();
                if plan.auto_ack {
                    match f.ty {
                        ty::SETTINGS if f.flags & flag::ACK == 0 => {
                            reply.push(Frame::new(ty::SETTINGS, flag::ACK, 0, Vec::new()))
                        }
                        ty::PING if f.flags & flag::ACK == 0 => {
                            reply.push(Frame::new(ty::PING, flag::ACK, 0, f.payload.clone()))
                        }
                        _ => {}
                    }
                }
                let ours = plan.wait_stream.is_none_or(|s| s == f.stream & 0x7fff_ffff);
                match collector.feed(&f) {
                    Ok(Some(b)) if ours && b.stream != 0 => {
                        // Informational responses stay in the list; the status is the last one seen.
                        if let Some(s) = pseudo(&b.headers, ":status") {
                            o.ex.status = std::str::from_utf8(s).ok().and_then(|s| s.parse().ok());
                        }
                        details.response_headers.extend(b.headers);
                        if b.end_stream && plan.wait_stream.is_some() {
                            done = true;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        o.ex.error = Some(format!("response headers: {e}"));
                        done = true;
                    }
                }
                match f.ty {
                    ty::DATA if ours => {
                        resp_body.extend_from_slice(data_payload(&f));
                        if f.flags & flag::END_STREAM != 0 && plan.wait_stream.is_some() {
                            done = true;
                        }
                    }
                    ty::RST_STREAM if ours && f.payload.len() == 4 => {
                        let code =
                            u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]);
                        details.rst = Some(code);
                        if plan.wait_stream.is_some() {
                            o.ex.error = Some(format!("the server reset the stream (error code {code})"));
                            done = true;
                        }
                    }
                    ty::GOAWAY if f.payload.len() >= 8 => {
                        let last =
                            u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]);
                        let code =
                            u32::from_be_bytes([f.payload[4], f.payload[5], f.payload[6], f.payload[7]]);
                        details.goaway = Some((last, code));
                        done = true;
                    }
                    _ => {}
                }
                details.frames_in.push(f);
                if !reply.is_empty() {
                    let mut bytes = Vec::new();
                    for r in &reply {
                        bytes.extend_from_slice(&r.encode());
                    }
                    let _ = o.io.write_all(&bytes).await;
                    details.frames_out.extend(reply);
                }
                if done {
                    break;
                }
            }
            if done {
                break;
            }
            if resp_body.len() > opts.max_response {
                resp_body.truncate(opts.max_response);
                o.ex.truncated = true;
                break;
            }
            let idle = if plan.wait_stream.is_none() {
                plan.linger
            } else {
                opts.idle_timeout
            };
            let wait = idle.min(deadline.saturating_duration_since(Instant::now()));
            if wait.is_zero() {
                o.ex.error = Some("timed out".into());
                break;
            }
            match tokio::time::timeout(wait, o.io.read(&mut chunk)).await {
                Err(_) => {
                    if plan.wait_stream.is_some() {
                        o.ex.error = Some("timed out waiting for the response".into());
                    }
                    break;
                }
                Ok(Err(e)) => {
                    o.ex.error = Some(format!("read failed: {e}"));
                    break;
                }
                Ok(Ok(0)) => {
                    if plan.wait_stream.is_some() && details.goaway.is_none() {
                        o.ex.error = Some("connection closed before the response ended".into());
                    }
                    break;
                }
                Ok(Ok(n)) => {
                    first_byte.get_or_insert_with(|| written.elapsed().as_millis() as u64);
                    total_in += n;
                    if res.bytes() < total_in * COPY_FACTOR
                        && !res.grow((64 * 1024).max(n) * COPY_FACTOR, self.budget())
                    {
                        o.ex.truncated = true;
                        o.ex.error = Some("the memory budget is spent".into());
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
        }
        if o.ex.error.is_none()
            && plan.wait_stream.is_some()
            && let Some((_, code)) = details.goaway
            && o.ex.status.is_none()
        {
            o.ex.error = Some(format!("the server sent GOAWAY (error code {code})"));
        }
        if let Some(s) = o.ex.status {
            o.ex.response = render_response(s.to_string().as_bytes(), &details.response_headers, &resp_body);
        }
        o.ex.timings.first_byte_ms = first_byte;
        o.ex.timings.total_ms = started.elapsed().as_millis() as u64;
        o.ex.h2 = Some(details);
        Ok(o.ex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_can_lie_about_their_length() {
        let f = Frame::new(ty::DATA, flag::END_STREAM, 3, b"hello".to_vec());
        assert_eq!(parse_frame(&f.encode(), 100), Ok(Some((f.clone(), 14))));
        let mut lie = f.clone();
        lie.declared_len = Some(2);
        assert_eq!(&lie.encode()[..3], &[0, 0, 2]);
        assert_eq!(parse_frame(&f.encode()[..13], 100), Ok(None));
        assert_eq!(parse_frame(&f.encode(), 4), Err(5));
    }

    #[test]
    fn cut_off_header_blocks_are_errors_not_panics() {
        // A table-size update whose integer continues past the end: the decoder crate panics on this.
        let mut c = HeaderCollector::new();
        let f = Frame::new(ty::HEADERS, flag::END_HEADERS, 1, vec![0x3f, 0xff]);
        assert!(c.feed(&f).is_err());
        // Literal whose string is longer than the rest of the block.
        let f = Frame::new(ty::HEADERS, flag::END_HEADERS, 1, vec![0x40, 0x05, b'a']);
        assert!(c.feed(&f).is_err());
        // An integer of six octets is over the decoder's limit (it panics after its own check on this path).
        let f = Frame::new(
            ty::HEADERS,
            flag::END_HEADERS,
            1,
            vec![0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
        );
        assert!(c.feed(&f).is_err());
        // And a complete block still decodes.
        let f = Frame::new(ty::HEADERS, flag::END_HEADERS, 1, vec![0x88]);
        assert_eq!(
            c.feed(&f).unwrap().unwrap().headers,
            vec![(b":status".to_vec(), b"200".to_vec())]
        );
    }

    #[test]
    fn a_request_becomes_frames_that_decode_back_even_when_split() {
        let mut r = H2Request::new(
            "POST",
            "https",
            "a.test",
            "/p?x=1",
            &[("X-Upper", "Yes"), ("x-dup", "1"), ("x-dup", "2")],
        );
        r.body = b"data".to_vec();
        for chunk in [None, Some(7)] {
            r.header_chunk = chunk;
            let frames = r.frames(1);
            assert_eq!(
                frames.last().map(|f| (f.ty, f.flags)),
                Some((ty::DATA, flag::END_STREAM))
            );
            let decoded = decode_plan_headers(&frames).unwrap();
            assert_eq!(decoded.len(), 1);
            assert_eq!(decoded[0].1, r.headers, "chunk {chunk:?}");
        }
        assert!(r.frames(1).len() > 2, "split into CONTINUATIONs");
    }
}
