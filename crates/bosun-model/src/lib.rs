//! Core data types shared by every Bosun component.
//!
//! Messages are kept as raw bytes as far as possible: a security testing tool must be able to show and replay
//! exactly what went over the wire, including malformed or non-UTF-8 content. Parsed views (headers, start line)
//! are derived from the raw bytes, never the other way round.

use serde::{Deserialize, Serialize};

pub mod raw;

pub use raw::{ParseError, RawRequest, RawResponse};

/// Identifier of a recorded flow (one request and, when there is one, its response) in a project.
pub type FlowId = i64;

/// Where a flow came from. Every tool that sends traffic records it with its own source so history can be
/// filtered and so nothing a tool sends is hidden from the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowSource {
    Proxy,
    Repeater,
    Intruder,
    Scanner,
    Crawler,
    Plugin,
    /// Recorded in a HAR or Burp file and imported: nothing was sent.
    Import,
}

impl FlowSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Repeater => "repeater",
            Self::Intruder => "intruder",
            Self::Scanner => "scanner",
            Self::Crawler => "crawler",
            Self::Plugin => "plugin",
            Self::Import => "import",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "proxy" => Self::Proxy,
            "repeater" => Self::Repeater,
            "intruder" => Self::Intruder,
            "scanner" => Self::Scanner,
            "crawler" => Self::Crawler,
            "plugin" => Self::Plugin,
            "import" => Self::Import,
            _ => return None,
        })
    }
}

/// The network target of a request: scheme, host and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn new(scheme: Scheme, host: impl Into<String>, port: u16) -> Self {
        Self {
            scheme,
            host: host.into().to_ascii_lowercase(),
            port,
        }
    }

    /// `scheme://host[:port]`, leaving out the default port.
    pub fn origin(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.scheme.default_port() {
            format!("{}://{}", self.scheme.as_str(), host)
        } else {
            format!("{}://{}:{}", self.scheme.as_str(), host, self.port)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "http" | "ws" => Some(Self::Http),
            "https" | "wss" => Some(Self::Https),
            _ => None,
        }
    }
}

/// A flow as listed in history: everything needed for the table, without bodies.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FlowSummary {
    pub id: FlowId,
    pub source: FlowSource,
    /// Unix time in milliseconds when the request was received.
    pub started_ms: i64,
    pub duration_ms: Option<i64>,
    /// Milliseconds from the request being received to the response head arriving.
    #[serde(default)]
    pub ttfb_ms: Option<i64>,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub http_version: String,
    pub status: Option<u16>,
    pub request_len: i64,
    pub response_len: Option<i64>,
    pub mime: Option<String>,
    pub in_scope: bool,
    /// The flow was edited in the intercept queue or by a match-and-replace rule.
    pub edited: bool,
    /// Error text when no response arrived (connection refused, TLS failure, dropped by the user...).
    pub error: Option<String>,
    pub tags: Vec<String>,
    pub note: Option<String>,
}

/// A flow with its raw messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDetail {
    pub summary: FlowSummary,
    /// The request as sent upstream (after any edits).
    #[serde(with = "b64")]
    pub request: Vec<u8>,
    /// The request as the client sent it, when it was edited before forwarding.
    #[serde(with = "b64_opt")]
    pub original_request: Option<Vec<u8>>,
    #[serde(with = "b64_opt")]
    pub response: Option<Vec<u8>>,
    #[serde(with = "b64_opt")]
    pub original_response: Option<Vec<u8>>,
    /// The body was larger than the recording limit, so only the start of it is stored.
    pub response_truncated: bool,
}

/// A WebSocket message seen on an upgraded connection.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WsMessage {
    pub id: i64,
    /// The flow holding the HTTP upgrade handshake.
    pub flow_id: FlowId,
    pub time_ms: i64,
    pub direction: Direction,
    pub opcode: u8,
    #[serde(with = "b64")]
    #[schema(value_type = String, format = Byte)]
    pub payload: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// Bytes go over JSON as standard base64 so non-UTF-8 content survives intact.
pub mod b64 {
    use base64_impl::{decode, encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        decode(&s).map_err(serde::de::Error::custom)
    }

    /// A tiny, dependency-free standard base64 codec (RFC 4648 with padding).
    pub mod base64_impl {
        const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        pub fn encode(input: &[u8]) -> String {
            let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
            for chunk in input.chunks(3) {
                let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
                let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
                out.push(ALPHABET[(n >> 18) as usize & 63] as char);
                out.push(ALPHABET[(n >> 12) as usize & 63] as char);
                out.push(if chunk.len() > 1 {
                    ALPHABET[(n >> 6) as usize & 63] as char
                } else {
                    '='
                });
                out.push(if chunk.len() > 2 {
                    ALPHABET[n as usize & 63] as char
                } else {
                    '='
                });
            }
            out
        }

        pub fn decode(input: &str) -> Result<Vec<u8>, &'static str> {
            fn val(c: u8) -> Result<u32, &'static str> {
                Ok(match c {
                    b'A'..=b'Z' => c - b'A',
                    b'a'..=b'z' => c - b'a' + 26,
                    b'0'..=b'9' => c - b'0' + 52,
                    b'+' => 62,
                    b'/' => 63,
                    _ => return Err("invalid base64"),
                }
                .into())
            }
            let bytes = input.as_bytes();
            if !bytes.len().is_multiple_of(4) {
                return Err("invalid base64 length");
            }
            let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
            for (i, chunk) in bytes.chunks(4).enumerate() {
                let last = i == bytes.len() / 4 - 1;
                let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
                if pad > 2 || (pad > 0 && !last) {
                    return Err("invalid base64 padding");
                }
                let mut n = 0u32;
                for (j, &c) in chunk.iter().enumerate() {
                    n <<= 6;
                    if j < 4 - pad {
                        n |= val(c)?;
                    }
                }
                out.push((n >> 16) as u8);
                if pad < 2 {
                    out.push((n >> 8) as u8);
                }
                if pad < 1 {
                    out.push(n as u8);
                }
            }
            Ok(out)
        }
    }
}

pub mod b64_opt {
    use super::b64::base64_impl::{decode, encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_some(&encode(v)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| decode(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Current Unix time in milliseconds.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::b64::base64_impl::{decode, encode};
    use super::*;

    #[test]
    fn base64_round_trips_every_length() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data);
        }
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert!(decode("Zm9=v").is_err());
        assert!(decode("Z===").is_err());
    }

    #[test]
    fn origin_leaves_out_default_ports() {
        assert_eq!(
            Target::new(Scheme::Https, "Example.COM", 443).origin(),
            "https://example.com"
        );
        assert_eq!(Target::new(Scheme::Http, "a", 8080).origin(), "http://a:8080");
        assert_eq!(Target::new(Scheme::Http, "::1", 80).origin(), "http://[::1]");
    }
}
