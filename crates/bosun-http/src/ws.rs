//! WebSockets with frames written as given.
//!
//! The handshake is an ordinary raw HTTP/1.1 request. After a `101`, frames are sent exactly as described by a
//! [`Frame`]: any opcode, reserved bits, FIN flag and masking key (or none, which a compliant client never does).
//! Received frames are returned one by one, not reassembled, with their flags.

use std::time::{Duration, Instant};

use bosun_model::{Direction, Target, now_ms};
use bosun_proxy::ws::{DeflateParams, Frame as PFrame, Inflater, RECORD_LIMIT};
use bosun_store::project::NewWsMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Engine, Exchange, Io, SendError, SendOptions, gate_path, request_line};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    /// The three reserved bits, as `0b00000RRR` (RSV1 is the high one of the three).
    pub rsv: u8,
    pub opcode: u8,
    /// The masking key. `None` sends the frame unmasked.
    pub mask: Option<[u8; 4]>,
    /// The payload, unmasked: masking is applied (and undone) when encoding (and parsing).
    pub payload: Vec<u8>,
}

impl Frame {
    fn with(opcode: u8, payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            rsv: 0,
            opcode,
            mask: Some(random_mask()),
            payload,
        }
    }

    pub fn text(s: &str) -> Self {
        Self::with(0x1, s.as_bytes().to_vec())
    }

    pub fn binary(b: Vec<u8>) -> Self {
        Self::with(0x2, b)
    }

    pub fn ping(b: Vec<u8>) -> Self {
        Self::with(0x9, b)
    }

    pub fn close(code: u16, reason: &str) -> Self {
        let mut p = code.to_be_bytes().to_vec();
        p.extend_from_slice(reason.as_bytes());
        Self::with(0x8, p)
    }

    /// The bytes of this frame on the wire. The length uses the shortest form that fits.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 14);
        out.push(u8::from(self.fin) << 7 | (self.rsv & 7) << 4 | (self.opcode & 0xf));
        let mbit = if self.mask.is_some() { 0x80 } else { 0 };
        match self.payload.len() {
            n if n < 126 => out.push(mbit | n as u8),
            n if n <= 0xffff => {
                out.push(mbit | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(mbit | 127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match self.mask {
            Some(k) => {
                out.extend_from_slice(&k);
                out.extend(self.payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
            }
            None => out.extend_from_slice(&self.payload),
        }
        out
    }
}

fn random_mask() -> [u8; 4] {
    let mut k = [0u8; 4];
    rand::fill(&mut k);
    k
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame payload of {0} bytes is over the limit of {1}")]
    TooLarge(u64, usize),
    #[error("frame length has its top bit set")]
    BadLength,
}

/// Parse one frame from the start of `buf`: the frame and how many bytes it took, `Ok(None)` if more is needed.
pub fn parse_frame(buf: &[u8], max_payload: usize) -> Result<Option<(Frame, usize)>, FrameError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let (b0, b1) = (buf[0], buf[1]);
    let masked = b1 & 0x80 != 0;
    let mut pos = 2;
    let len = match b1 & 0x7f {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            pos = 4;
            u64::from(u16::from_be_bytes([buf[2], buf[3]]))
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            pos = 10;
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[2..10]);
            let n = u64::from_be_bytes(b);
            if n >> 63 != 0 {
                return Err(FrameError::BadLength);
            }
            n
        }
        n => u64::from(n),
    };
    if len > max_payload as u64 {
        return Err(FrameError::TooLarge(len, max_payload));
    }
    let mask = if masked {
        if buf.len() < pos + 4 {
            return Ok(None);
        }
        let k = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
        pos += 4;
        Some(k)
    } else {
        None
    };
    let len = len as usize;
    if buf.len() < pos + len {
        return Ok(None);
    }
    let mut payload = buf[pos..pos + len].to_vec();
    if let Some(k) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= k[i % 4];
        }
    }
    Ok(Some((
        Frame {
            fin: b0 & 0x80 != 0,
            rsv: (b0 >> 4) & 7,
            opcode: b0 & 0xf,
            mask,
            payload,
        },
        pos + len,
    )))
}

/// An open WebSocket connection.
pub struct WsSession {
    handshake: Exchange,
    io: Box<dyn Io>,
    _reg: bosun_proxy::upstream::Registration,
    buf: Vec<u8>,
    max_frame: usize,
}

impl std::fmt::Debug for WsSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsSession")
            .field("handshake", &self.handshake)
            .finish_non_exhaustive()
    }
}

impl WsSession {
    /// The handshake request and its `101` response, to be recorded as the flow the frames belong to.
    pub fn handshake(&self) -> &Exchange {
        &self.handshake
    }

    /// Write one frame, exactly as described.
    pub async fn send(&mut self, frame: &Frame) -> Result<(), SendError> {
        self.send_raw(&frame.encode()).await
    }

    /// Write bytes to the stream as they are, for frames that [`Frame`] cannot describe (a length that does not
    /// match, an over-long length form, a cut-off header).
    pub async fn send_raw(&mut self, bytes: &[u8]) -> Result<(), SendError> {
        self.io
            .write_all(bytes)
            .await
            .map_err(|e| SendError::Write(e.to_string()))?;
        self.io.flush().await.map_err(|e| SendError::Write(e.to_string()))
    }

    /// The next frame from the server. `Ok(None)` when the server closed the stream or `wait` passed with nothing.
    pub async fn recv(&mut self, wait: Duration) -> Result<Option<Frame>, FrameError> {
        let end = Instant::now() + wait;
        loop {
            if let Some((f, n)) = parse_frame(&self.buf, self.max_frame)? {
                self.buf.drain(..n);
                return Ok(Some(f));
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            let mut chunk = [0u8; 16 * 1024];
            match tokio::time::timeout(left, self.io.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => self.buf.extend_from_slice(&chunk[..n]),
                _ => return Ok(None),
            }
        }
    }

    /// Close the TCP connection without a closing handshake. Send a close frame first for a clean close.
    pub async fn shutdown(mut self) {
        let _ = self.io.shutdown().await;
    }
}

/// The record of one frame, for the flow the handshake was stored as. Payloads past the store's limit are cut and
/// marked.
pub fn to_ws_message(flow_id: i64, direction: Direction, frame: &Frame, limit: usize) -> NewWsMessage {
    let truncated = frame.payload.len() > limit;
    NewWsMessage {
        flow_id,
        time_ms: now_ms(),
        direction,
        opcode: frame.opcode,
        payload: frame.payload[..frame.payload.len().min(limit)].to_vec(),
        truncated,
    }
}

/// Records the frames of one connection, inflating `permessage-deflate` messages the way the proxy does (one
/// inflater per direction, 1 MiB cap). Sent and received bytes are never altered; only the stored copy is.
pub struct WsRecorder {
    flow_id: i64,
    up: Option<Inflater>,
    down: Option<Inflater>,
}

impl WsRecorder {
    /// For the flow of `handshake`: compression is on if the server's `101` accepted `permessage-deflate`.
    pub fn new(flow_id: i64, handshake: &Exchange) -> Self {
        let text = String::from_utf8_lossy(&handshake.response);
        let params = text
            .split("\r\n")
            .filter_map(|l| l.split_once(':'))
            .filter(|(n, _)| n.trim().eq_ignore_ascii_case("sec-websocket-extensions"))
            .find_map(|(_, v)| DeflateParams::from_header(v));
        Self {
            flow_id,
            up: params.map(|p| Inflater::new(p.client_no_context_takeover, RECORD_LIMIT)),
            down: params.map(|p| Inflater::new(p.server_no_context_takeover, RECORD_LIMIT)),
        }
    }

    /// The message to store for `frame`, if one is complete (a compressed message is stored whole, on its last
    /// fragment).
    pub fn message(&mut self, direction: Direction, frame: &Frame, limit: usize) -> Option<NewWsMessage> {
        let inf = match direction {
            Direction::ClientToServer => self.up.as_mut(),
            _ => self.down.as_mut(),
        };
        let Some(inf) = inf else {
            return Some(to_ws_message(self.flow_id, direction, frame, limit));
        };
        let f = inf.process(PFrame {
            opcode: frame.opcode,
            fin: frame.fin,
            rsv1: frame.rsv & 0b100 != 0,
            payload: frame.payload.clone(),
            truncated: false,
        })?;
        let truncated = f.truncated || f.payload.len() > limit;
        Some(NewWsMessage {
            flow_id: self.flow_id,
            time_ms: now_ms(),
            direction,
            opcode: f.opcode,
            payload: f.payload[..f.payload.len().min(limit)].to_vec(),
            truncated,
        })
    }
}

impl Engine {
    /// Send a WebSocket handshake (a raw HTTP/1.1 request) and, if the server answers `101`, return the open
    /// connection. Any other answer is [`SendError::NotUpgraded`], which carries the exchange. The
    /// `Sec-WebSocket-Accept` value is **not** checked: the point is to see what the server does.
    pub async fn connect_ws(
        &self,
        target: &Target,
        raw_handshake: &[u8],
        opts: &SendOptions,
    ) -> Result<WsSession, SendError> {
        let started = Instant::now();
        let (method, path, _) = request_line(raw_handshake);
        if method.is_empty() {
            return Err(SendError::BadRequest("no request line"));
        }
        let checked = self.check(target, &gate_path(&path), opts).await?;
        let mut o = self
            .open(&checked, target, raw_handshake.to_vec(), opts, false, false)
            .await?;
        self.exchange(&mut o.io, &mut o.ex, false, opts, started + opts.total_timeout)
            .await?;
        o.ex.timings.total_ms = started.elapsed().as_millis() as u64;
        if o.ex.status != Some(101) {
            return Err(SendError::NotUpgraded(Box::new(o.ex)));
        }
        let buf = std::mem::take(&mut o.ex.leftover);
        Ok(WsSession {
            handshake: o.ex,
            io: o.io,
            _reg: o._reg,
            buf,
            max_frame: opts.max_response,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_in_every_length_form() {
        for n in [0usize, 5, 125, 126, 300, 65535, 65536, 70000] {
            for mask in [None, Some([1, 2, 3, 4])] {
                let f = Frame {
                    fin: n % 2 == 0,
                    rsv: (n % 8) as u8,
                    opcode: 2,
                    mask,
                    payload: (0..n).map(|i| i as u8).collect(),
                };
                let wire = f.encode();
                assert_eq!(parse_frame(&wire, 1 << 20), Ok(Some((f, wire.len()))), "{n}");
            }
        }
    }

    #[test]
    fn short_input_asks_for_more_and_huge_lengths_are_refused() {
        let wire = Frame::text("hello").encode();
        for cut in 0..wire.len() {
            assert_eq!(parse_frame(&wire[..cut], 100), Ok(None), "cut {cut}");
        }
        let mut big = vec![0x82, 127];
        big.extend_from_slice(&(1u64 << 40).to_be_bytes());
        assert!(matches!(
            parse_frame(&big, 1 << 20),
            Err(FrameError::TooLarge(..))
        ));
        let mut bad = vec![0x82, 127];
        bad.extend_from_slice(&(1u64 << 63).to_be_bytes());
        assert_eq!(parse_frame(&bad, 1 << 20), Err(FrameError::BadLength));
    }
}
