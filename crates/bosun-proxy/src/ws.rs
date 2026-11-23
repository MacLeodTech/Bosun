//! WebSocket relaying with message recording.
//!
//! Bytes are relayed unchanged in both directions. A streaming frame parser watches each direction and records
//! every frame (unmasked) up to a size cap, without ever buffering a whole large frame.

use bosun_model::{Direction, FlowId};
use bosun_store::NewWsMessage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::recorder::Recorder;

/// Largest payload recorded per frame; the rest is relayed but not stored.
pub const RECORD_LIMIT: usize = 1024 * 1024;

/// A frame the parser has finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub opcode: u8,
    pub fin: bool,
    pub payload: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug)]
enum State {
    Header,
    Payload {
        remaining: u64,
        mask: Option<[u8; 4]>,
        offset: u64,
    },
}

/// Incremental RFC 6455 frame parser.
#[derive(Debug)]
pub struct FrameParser {
    state: State,
    head: Vec<u8>,
    opcode: u8,
    fin: bool,
    payload: Vec<u8>,
    truncated: bool,
    limit: usize,
}

impl FrameParser {
    pub fn new(limit: usize) -> Self {
        Self {
            state: State::Header,
            head: Vec::with_capacity(14),
            opcode: 0,
            fin: false,
            payload: Vec::new(),
            truncated: false,
            limit,
        }
    }

    /// Feed bytes; returns the frames completed by them.
    pub fn feed(&mut self, mut data: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        while !data.is_empty() {
            match &mut self.state {
                State::Header => {
                    self.head.push(data[0]);
                    data = &data[1..];
                    if let Some((len, mask, hlen)) = parse_header(&self.head) {
                        debug_assert_eq!(hlen, self.head.len());
                        self.fin = self.head[0] & 0x80 != 0;
                        self.opcode = self.head[0] & 0x0f;
                        self.head.clear();
                        self.payload.clear();
                        self.truncated = false;
                        if len == 0 {
                            out.push(self.take());
                        } else {
                            self.state = State::Payload {
                                remaining: len,
                                mask,
                                offset: 0,
                            };
                        }
                    }
                }
                State::Payload {
                    remaining,
                    mask,
                    offset,
                } => {
                    let n = (*remaining).min(data.len() as u64) as usize;
                    let room = self.limit.saturating_sub(self.payload.len());
                    let keep = n.min(room);
                    let start = self.payload.len();
                    self.payload.extend_from_slice(&data[..keep]);
                    if let Some(m) = mask {
                        for (i, b) in self.payload[start..].iter_mut().enumerate() {
                            *b ^= m[((*offset as usize) + i) % 4];
                        }
                    }
                    if keep < n {
                        self.truncated = true;
                    }
                    *offset += n as u64;
                    *remaining -= n as u64;
                    data = &data[n..];
                    if *remaining == 0 {
                        self.state = State::Header;
                        out.push(self.take());
                    }
                }
            }
        }
        out
    }

    fn take(&mut self) -> Frame {
        Frame {
            opcode: self.opcode,
            fin: self.fin,
            payload: std::mem::take(&mut self.payload),
            truncated: self.truncated,
        }
    }
}

/// Returns (payload length, mask, header length) once the header bytes are complete.
fn parse_header(h: &[u8]) -> Option<(u64, Option<[u8; 4]>, usize)> {
    if h.len() < 2 {
        return None;
    }
    let masked = h[1] & 0x80 != 0;
    let (len, mut pos) = match h[1] & 0x7f {
        126 => {
            if h.len() < 4 {
                return None;
            }
            (u64::from(u16::from_be_bytes([h[2], h[3]])), 4)
        }
        127 => {
            if h.len() < 10 {
                return None;
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&h[2..10]);
            (u64::from_be_bytes(b), 10)
        }
        n => (u64::from(n), 2),
    };
    let mask = if masked {
        if h.len() < pos + 4 {
            return None;
        }
        let m = [h[pos], h[pos + 1], h[pos + 2], h[pos + 3]];
        pos += 4;
        Some(m)
    } else {
        None
    };
    (h.len() == pos).then_some((len, mask, pos))
}

/// Relay both directions until either side closes, recording frames.
pub async fn relay<C, S>(client: C, server: S, flow_id: FlowId, recorder: Recorder)
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut sr, mut sw) = tokio::io::split(server);
    let up = pump(
        &mut cr,
        &mut sw,
        flow_id,
        Direction::ClientToServer,
        recorder.clone(),
    );
    let down = pump(&mut sr, &mut cw, flow_id, Direction::ServerToClient, recorder);
    // When one direction ends, finish the other too: a WebSocket is over once either side closes.
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

async fn pump<R, W>(r: &mut R, w: &mut W, flow_id: FlowId, dir: Direction, recorder: Recorder)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut parser = FrameParser::new(RECORD_LIMIT);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        for f in parser.feed(&buf[..n]) {
            recorder.ws(NewWsMessage {
                flow_id,
                time_ms: bosun_model::now_ms(),
                direction: dir,
                opcode: f.opcode,
                payload: f.payload,
                truncated: f.truncated,
            });
        }
    }
    let _ = w.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut f = vec![0x80 | opcode];
        let m = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => f.push(m | n as u8),
            n if n <= 0xffff => {
                f.push(m | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                f.push(m | 127);
                f.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        if let Some(k) = mask {
            f.extend_from_slice(&k);
            f.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
        } else {
            f.extend_from_slice(payload);
        }
        f
    }

    #[test]
    fn parses_masked_and_unmasked_frames_split_anywhere() {
        let mut stream = frame(1, b"hello", Some([1, 2, 3, 4]));
        stream.extend(frame(2, &vec![7u8; 70_000], None));
        stream.extend(frame(9, b"", None));
        for chunk in [1usize, 3, 7, 1000, stream.len()] {
            let mut p = FrameParser::new(RECORD_LIMIT);
            let frames: Vec<Frame> = stream.chunks(chunk).flat_map(|c| p.feed(c)).collect();
            assert_eq!(frames.len(), 3, "chunk size {chunk}");
            assert_eq!(frames[0].payload, b"hello");
            assert_eq!(frames[0].opcode, 1);
            assert_eq!(frames[1].payload.len(), 70_000);
            assert_eq!(frames[2].opcode, 9);
        }
    }

    #[test]
    fn truncates_large_payloads_without_buffering_them() {
        let mut p = FrameParser::new(10);
        let frames = p.feed(&frame(2, &[1u8; 100], Some([9, 9, 9, 9])));
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, vec![1u8; 10]);
        assert!(frames[0].truncated);
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        fn frames() -> impl Strategy<Value = Vec<(u8, Vec<u8>, Option<[u8; 4]>)>> {
            proptest::collection::vec(
                (
                    prop_oneof![Just(1u8), Just(2), Just(8), Just(9), Just(10)],
                    proptest::collection::vec(any::<u8>(), 0..300),
                    proptest::option::of(any::<[u8; 4]>()),
                ),
                0..6,
            )
        }

        proptest! {
            /// However the byte stream is cut into reads, the parser yields the same frames with the same
            /// (unmasked) payloads.
            #[test]
            fn frames_survive_any_chunking(input in frames(), cuts in proptest::collection::vec(1usize..64, 1..20)) {
                let mut wire = Vec::new();
                for (op, payload, mask) in &input {
                    wire.extend(frame(*op, payload, *mask));
                }
                let mut p = FrameParser::new(RECORD_LIMIT);
                let mut got = Vec::new();
                let mut rest = &wire[..];
                let mut i = 0;
                while !rest.is_empty() {
                    let n = cuts[i % cuts.len()].min(rest.len());
                    got.extend(p.feed(&rest[..n]));
                    rest = &rest[n..];
                    i += 1;
                }
                prop_assert_eq!(got.len(), input.len());
                for (f, (op, payload, _)) in got.iter().zip(&input) {
                    prop_assert_eq!(f.opcode, *op);
                    prop_assert_eq!(&f.payload, payload);
                    prop_assert!(!f.truncated);
                }
            }

            /// A payload past the record limit is cut and flagged, and the next frame still parses.
            #[test]
            fn oversize_payloads_are_truncated_but_framing_holds(len in 20usize..400, limit in 1usize..20) {
                let mut wire = frame(2, &vec![7u8; len], Some([1, 2, 3, 4]));
                wire.extend(frame(1, b"n", None));
                let got = FrameParser::new(limit).feed(&wire);
                prop_assert_eq!(got.len(), 2);
                prop_assert!(got[0].truncated);
                prop_assert_eq!(got[0].payload.len(), limit);
                prop_assert_eq!(&got[1].payload[..], b"n");
                prop_assert!(!got[1].truncated);
            }

            /// Random bytes (a hostile peer) never panic the parser and never make it keep more than the limit.
            #[test]
            fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2000)) {
                let mut p = FrameParser::new(64);
                for f in p.feed(&data) {
                    prop_assert!(f.payload.len() <= 64);
                }
            }
        }
    }
}
