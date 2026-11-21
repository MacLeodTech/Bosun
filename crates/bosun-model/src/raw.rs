//! Parsing raw HTTP/1.x-style messages.
//!
//! History stores every message (HTTP/2 included) in HTTP/1.1 text form, because that is what people read and
//! edit. These parsers turn an edited message back into its parts. They are deliberately lenient about what they
//! accept from the user (bare `\n` line endings, which editors produce) and strict about limits.

use thiserror::Error;

/// Upper bound on the number of headers in a message we parse.
pub const MAX_HEADERS: usize = 256;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("the message is incomplete: the header block must end with an empty line")]
    Incomplete,
    #[error("invalid HTTP message: {0}")]
    Invalid(String),
}

/// A parsed request. Header names and values are kept as bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRequest {
    pub method: String,
    /// The request target exactly as written: origin form (`/path?q`) or absolute form.
    pub target: String,
    /// `HTTP/1.0` or `HTTP/1.1` (HTTP/2 messages are written as `HTTP/2`).
    pub version: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// Normalise bare `\n` line endings in the header block to `\r\n`, leaving the body untouched.
fn normalise_head(input: &[u8]) -> Vec<u8> {
    let head_end = find_head_end(input);
    let (head, body) = match head_end {
        Some((end, _)) => input.split_at(end),
        None => (input, &[][..]),
    };
    let mut out = Vec::with_capacity(input.len() + 32);
    let mut prev = 0u8;
    for &b in head {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    // The separator itself (`\n\n`, `\r\n\r\n` or a mix) has been rewritten as part of `head` above when it
    // was included; make sure it ends with exactly one blank line.
    while out.ends_with(b"\r\n") {
        out.truncate(out.len() - 2);
    }
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// Find the end of the header block. Returns (index just past the blank line, separator length).
fn find_head_end(input: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\n' {
            if input.get(i + 1) == Some(&b'\n') {
                return Some((i + 2, 2));
            }
            if input.get(i + 1) == Some(&b'\r') && input.get(i + 2) == Some(&b'\n') {
                return Some((i + 3, 3));
            }
        }
        i += 1;
    }
    None
}

fn version_str(v: Option<u8>) -> String {
    match v {
        Some(0) => "HTTP/1.0".into(),
        _ => "HTTP/1.1".into(),
    }
}

/// HTTP/2 messages are shown as `HTTP/2`; httparse only knows 1.x, so rewrite the version for parsing.
fn swap_h2_version(input: &[u8], in_start_line_prefix: bool) -> (Vec<u8>, bool) {
    let line_end = input.iter().position(|&b| b == b'\n').unwrap_or(input.len());
    let line = &input[..line_end];
    let needle = b"HTTP/2";
    let pos = if in_start_line_prefix {
        line.starts_with(needle).then_some(0)
    } else {
        line.windows(needle.len()).rposition(|w| w == needle)
    };
    match pos {
        Some(p) if !line[p..].starts_with(b"HTTP/2.") || line[p..].starts_with(b"HTTP/2.0") => {
            let tail_len = if line[p..].starts_with(b"HTTP/2.0") { 8 } else { 6 };
            let mut out = Vec::with_capacity(input.len() + 2);
            out.extend_from_slice(&input[..p]);
            out.extend_from_slice(b"HTTP/1.1");
            out.extend_from_slice(&input[p + tail_len..]);
            (out, true)
        }
        _ => (input.to_vec(), false),
    }
}

impl RawRequest {
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        let (swapped, was_h2) = swap_h2_version(input, false);
        let data = normalise_head(&swapped);
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        let status = req.parse(&data).map_err(|e| ParseError::Invalid(e.to_string()))?;
        let httparse::Status::Complete(head_len) = status else {
            return Err(ParseError::Incomplete);
        };
        let method = req.method.ok_or(ParseError::Incomplete)?.to_string();
        let target = req.path.ok_or(ParseError::Incomplete)?.to_string();
        let version = if was_h2 {
            "HTTP/2".to_string()
        } else {
            version_str(req.version)
        };
        let headers = req
            .headers
            .iter()
            .map(|h| (h.name.to_string(), h.value.to_vec()))
            .collect();
        Ok(Self {
            method,
            target,
            version,
            headers,
            body: data[head_len..].to_vec(),
        })
    }

    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.header(name).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Serialise as HTTP/1.1 text.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 256);
        out.extend_from_slice(format!("{} {} {}\r\n", self.method, self.target, self.version).as_bytes());
        write_headers(&mut out, &self.headers);
        out.extend_from_slice(&self.body);
        out
    }
}

impl RawResponse {
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        let (swapped, was_h2) = swap_h2_version(input, true);
        let data = normalise_head(&swapped);
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut resp = httparse::Response::new(&mut headers);
        let status = resp
            .parse(&data)
            .map_err(|e| ParseError::Invalid(e.to_string()))?;
        let httparse::Status::Complete(head_len) = status else {
            return Err(ParseError::Incomplete);
        };
        let version = if was_h2 {
            "HTTP/2".to_string()
        } else {
            version_str(resp.version)
        };
        Ok(Self {
            version,
            status: resp.code.ok_or(ParseError::Incomplete)?,
            reason: resp.reason.unwrap_or("").to_string(),
            headers: resp
                .headers
                .iter()
                .map(|h| (h.name.to_string(), h.value.to_vec()))
                .collect(),
            body: data[head_len..].to_vec(),
        })
    }

    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 256);
        let reason = if self.reason.is_empty() {
            String::new()
        } else {
            format!(" {}", self.reason)
        };
        out.extend_from_slice(format!("{} {}{}\r\n", self.version, self.status, reason).as_bytes());
        write_headers(&mut out, &self.headers);
        out.extend_from_slice(&self.body);
        out
    }
}

fn write_headers(out: &mut Vec<u8>, headers: &[(String, Vec<u8>)]) {
    for (name, value) in headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_with_bare_newlines_and_keeps_body_bytes() {
        let raw = b"POST /a?b=1 HTTP/1.1\nHost: x\nContent-Length: 4\n\n\x00\r\n\xff";
        let req = RawRequest::parse(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/a?b=1");
        assert_eq!(req.header_str("host"), Some("x"));
        assert_eq!(req.body, b"\x00\r\n\xff");
    }

    #[test]
    fn round_trips_request() {
        let raw = b"GET / HTTP/1.1\r\nHost: a\r\nX: y\r\n\r\n";
        let req = RawRequest::parse(raw).unwrap();
        assert_eq!(req.to_bytes(), raw);
    }

    #[test]
    fn handles_http2_version_text() {
        let req = RawRequest::parse(b"GET / HTTP/2\r\nhost: a\r\n\r\n").unwrap();
        assert_eq!(req.version, "HTTP/2");
        let resp = RawResponse::parse(b"HTTP/2 204\r\nx: y\r\n\r\n").unwrap();
        assert_eq!(resp.status, 204);
        assert_eq!(resp.version, "HTTP/2");
    }

    #[test]
    fn missing_blank_line_is_completed_for_bodyless_messages() {
        // Users often delete the trailing blank line while editing; a message without a body still parses.
        let req = RawRequest::parse(b"GET / HTTP/1.1\r\nHost: a").unwrap();
        assert_eq!(req.header_str("Host"), Some("a"));
        assert!(req.body.is_empty());
    }

    #[test]
    fn rejects_garbage() {
        assert!(RawRequest::parse(b"\x00\x01 nope").is_err());
        assert!(RawResponse::parse(b"HTTP/1.1 abc\r\n\r\n").is_err());
    }

    #[test]
    fn response_round_trip() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let resp = RawResponse::parse(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.to_bytes(), raw);
    }
}
