//! Byte-level helpers for HTTP/1.1 messages. Nothing here normalises: it finds boundaries and reports them.

/// Offset just past the blank line that ends a message head (`\r\n\r\n`, or bare `\n\n`), if present.
pub fn head_end(data: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\n' {
            if data.get(i + 1) == Some(&b'\n') {
                return Some(i + 2);
            }
            if data.get(i + 1) == Some(&b'\r') && data.get(i + 2) == Some(&b'\n') {
                return Some(i + 3);
            }
        }
        i += 1;
    }
    None
}

/// Set (or add) the `Content-Length` header of a raw request to the length of its body, touching nothing else.
/// If there are several, the first is rewritten and the rest are left as written. A message without a blank line
/// is returned unchanged.
pub fn update_content_length(raw: &[u8]) -> Vec<u8> {
    let Some(end) = head_end(raw) else {
        return raw.to_vec();
    };
    // No request line (the message starts with a blank line): there is no head to put a header in.
    if raw.starts_with(b"\n") || raw.starts_with(b"\r\n") {
        return raw.to_vec();
    }
    let body_len = raw.len() - end;
    let head = &raw[..end];
    // Line ending the message already uses.
    let eol: &[u8] = if head.windows(2).any(|w| w == b"\r\n") {
        b"\r\n"
    } else {
        b"\n"
    };
    let mut out = Vec::with_capacity(raw.len() + 24);
    let mut done = false;
    let mut pos = 0;
    let mut first = true;
    while pos < head.len() {
        let line_end = head[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(head.len(), |p| pos + p + 1);
        let line = &head[pos..line_end];
        let name_end = line.iter().position(|&b| b == b':');
        let is_cl =
            !first && !done && name_end.is_some_and(|n| line[..n].eq_ignore_ascii_case(b"content-length"));
        if is_cl {
            out.extend_from_slice(format!("Content-Length: {body_len}").as_bytes());
            out.extend_from_slice(eol);
            done = true;
        } else if line == b"\r\n" || line == b"\n" {
            if !done {
                out.extend_from_slice(format!("Content-Length: {body_len}").as_bytes());
                out.extend_from_slice(eol);
                done = true;
            }
            out.extend_from_slice(line);
        } else {
            out.extend_from_slice(line);
        }
        first = false;
        pos = line_end;
    }
    out.extend_from_slice(&raw[end..]);
    out
}

/// How a response body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

/// Incremental scanner that finds the end of a chunked body without decoding it.
#[derive(Debug, Default)]
pub struct ChunkScanner {
    pos: usize,
    state: ChunkState,
}

#[derive(Debug, Default)]
enum ChunkState {
    #[default]
    Size,
    Data(u64),
    DataEnd,
    Trailers,
    Done,
}

impl ChunkScanner {
    /// Scan `data` (the whole body so far, from its first byte). Returns the offset where the body ends once it is
    /// complete, `Ok(None)` if more is needed, `Err` if the framing is invalid.
    pub fn advance(&mut self, data: &[u8]) -> Result<Option<usize>, &'static str> {
        loop {
            match self.state {
                ChunkState::Done => return Ok(Some(self.pos)),
                ChunkState::Size => {
                    let Some(nl) = data[self.pos..].iter().position(|&b| b == b'\n') else {
                        return if data.len() - self.pos > 4096 {
                            Err("chunk size line too long")
                        } else {
                            Ok(None)
                        };
                    };
                    let line = &data[self.pos..self.pos + nl];
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    let hex = line.split(|&b| b == b';').next().unwrap_or(&[]);
                    let hex = std::str::from_utf8(hex).map_err(|_| "bad chunk size")?.trim();
                    let size = u64::from_str_radix(hex, 16).map_err(|_| "bad chunk size")?;
                    self.pos += nl + 1;
                    self.state = if size == 0 {
                        ChunkState::Trailers
                    } else {
                        ChunkState::Data(size)
                    };
                }
                ChunkState::Data(n) => {
                    let avail = (data.len() - self.pos) as u64;
                    if avail < n {
                        self.pos = data.len();
                        self.state = ChunkState::Data(n - avail);
                        return Ok(None);
                    }
                    self.pos += n as usize;
                    self.state = ChunkState::DataEnd;
                }
                ChunkState::DataEnd => {
                    let rest = &data[self.pos..];
                    if rest.starts_with(b"\r\n") {
                        self.pos += 2;
                    } else if rest.starts_with(b"\n") {
                        self.pos += 1;
                    } else if rest.is_empty() || rest == b"\r" {
                        return Ok(None);
                    } else {
                        return Err("missing line end after chunk");
                    }
                    self.state = ChunkState::Size;
                }
                ChunkState::Trailers => {
                    let Some(nl) = data[self.pos..].iter().position(|&b| b == b'\n') else {
                        return Ok(None);
                    };
                    let line = &data[self.pos..self.pos + nl];
                    self.pos += nl + 1;
                    if line.is_empty() || line == b"\r" {
                        self.state = ChunkState::Done;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_both_kinds_of_head_end() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nA: b\r\n\r\nxx"), Some(24));
        assert_eq!(head_end(b"GET / HTTP/1.1\nA: b\n\nxx"), Some(21));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nA: b\r\n"), None);
    }

    #[test]
    fn content_length_is_rewritten_in_place_and_added_when_missing() {
        let r =
            update_content_length(b"POST / HTTP/1.1\r\nHost: a\r\ncontent-length: 99\r\nX: y\r\n\r\nhello");
        assert_eq!(
            r,
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nX: y\r\n\r\nhello"
        );
        let r = update_content_length(b"POST / HTTP/1.1\nHost: a\n\nhi");
        assert_eq!(r, b"POST / HTTP/1.1\nHost: a\nContent-Length: 2\n\nhi");
    }

    #[test]
    fn a_message_without_a_request_line_is_left_alone() {
        assert_eq!(update_content_length(b"\n\n,x"), b"\n\n,x");
        assert_eq!(update_content_length(b"\r\n\r\nbody"), b"\r\n\r\nbody");
    }

    #[test]
    fn chunked_end_is_found_across_arbitrary_splits() {
        let body = b"5\r\nhello\r\n3;ext=1\r\nabc\r\n0\r\nT: v\r\n\r\ntail";
        for split in 1..body.len() {
            let mut s = ChunkScanner::default();
            let first = s.advance(&body[..split]).unwrap();
            let end = match first {
                Some(e) => e,
                None => s.advance(body).unwrap().expect("complete"),
            };
            assert_eq!(end, body.len() - 4, "split at {split}");
        }
    }

    #[test]
    fn bad_chunk_size_is_an_error() {
        assert!(ChunkScanner::default().advance(b"zz\r\n").is_err());
    }
}
