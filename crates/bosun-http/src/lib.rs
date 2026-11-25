//! The raw request engine.
//!
//! Sends a message **exactly as written**: duplicate headers, bare LF line ends, odd methods and wrong
//! `Content-Length` values all go out unchanged, which a normal HTTP client cannot do. Repeater, Intruder,
//! Sequencer and the scanner all send through here.
//!
//! The rules every send follows:
//! - the target goes through [`bosun_scope::Gate::check`] first, and the connection goes to the **pinned**
//!   addresses it returns; the name is never resolved again;
//! - the response is read under the shared [`MemoryBudget`] and a per-message cap;
//! - the result carries timings, the negotiated TLS details and the raw bytes, and turns into a recorded flow
//!   with the caller's [`FlowSource`].
//!
//! This first slice speaks HTTP/1.1 (plain and TLS). HTTP/2 frames and WebSockets come next.

mod tls;
pub mod wire;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bosun_model::{FlowSource, Scheme, Target, now_ms};
use bosun_proxy::budget::{COPY_FACTOR, MemoryBudget, Reservation};
use bosun_scope::{Gate, ScopeError};
use bosun_store::project::NewFlow;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use wire::{ChunkScanner, Framing};

/// What can stop a send before there is a connection to talk about.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error(transparent)]
    Refused(#[from] ScopeError),
    #[error("could not connect to {0}: {1}")]
    Connect(String, String),
    #[error("TLS handshake with {0} failed: {1}")]
    Tls(String, String),
    #[error("could not write the request: {0}")]
    Write(String),
    #[error("the request is not a valid message: {0}")]
    BadRequest(&'static str),
    #[error("the memory budget is spent")]
    OutOfMemory,
}

#[derive(Debug, Clone)]
pub struct SendOptions {
    pub source: FlowSource,
    /// Rewrite (or add) `Content-Length` to match the body. Off by default: the point is to send what was written.
    pub update_content_length: bool,
    /// Check the server's certificate. Pentesting targets often have bad ones, so the Repeater turns this off.
    pub verify_tls: bool,
    pub connect_timeout: Duration,
    /// No bytes for this long ends the read.
    pub idle_timeout: Duration,
    /// The whole exchange, from connecting to the last byte.
    pub total_timeout: Duration,
    /// Response bytes kept; more is cut off and marked truncated.
    pub max_response: usize,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            source: FlowSource::Repeater,
            update_content_length: false,
            verify_tls: false,
            connect_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(120),
            max_response: 16 * 1024 * 1024,
        }
    }
}

/// Where the time went, in milliseconds. `None` for a phase that did not happen (no TLS on plain HTTP).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timings {
    /// The gate check, which includes resolving the name.
    pub dns_ms: u64,
    pub connect_ms: u64,
    pub tls_ms: Option<u64>,
    /// From the request being written to the first response byte.
    pub first_byte_ms: Option<u64>,
    pub total_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    pub version: String,
    pub cipher: String,
    pub alpn: Option<String>,
    /// The server's certificate, DER.
    pub leaf_der: Option<Vec<u8>>,
}

/// One request and what came back.
#[derive(Debug, Clone)]
pub struct Exchange {
    pub target: Target,
    /// The bytes that were written, after the optional Content-Length update and nothing else.
    pub request: Vec<u8>,
    /// The bytes that were read, exactly as received (chunk framing included).
    pub response: Vec<u8>,
    /// Status of the final response, if the head could be parsed.
    pub status: Option<u16>,
    pub truncated: bool,
    /// Set when reading ended early (timeout, reset, bad framing). The partial response is still here.
    pub error: Option<String>,
    pub peer: SocketAddr,
    pub tls: Option<TlsInfo>,
    pub timings: Timings,
    pub started_ms: i64,
    pub in_scope: bool,
}

impl Exchange {
    /// The record to store for this exchange. `id` comes from `Project::next_flow_id`.
    pub fn to_new_flow(&self, id: i64, source: FlowSource) -> NewFlow {
        let (method, path, version) = request_line(&self.request);
        NewFlow {
            id,
            source,
            started_ms: self.started_ms,
            duration_ms: Some(self.timings.total_ms as i64),
            scheme: self.target.scheme,
            host: self.target.host.clone(),
            port: self.target.port,
            method,
            path,
            http_version: version,
            status: self.status,
            in_scope: self.in_scope,
            edited: false,
            error: self.error.clone(),
            request: self.request.clone(),
            original_request: None,
            response: (!self.response.is_empty()).then(|| self.response.clone()),
            original_response: None,
            response_truncated: self.truncated,
        }
    }
}

/// Sends raw messages. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Engine {
    gate: Gate,
    budget: MemoryBudget,
    verified: Arc<rustls::ClientConfig>,
    unverified: Arc<rustls::ClientConfig>,
}

impl Engine {
    pub fn new(gate: Gate, budget: MemoryBudget) -> Self {
        Self {
            gate,
            budget,
            verified: Arc::new(tls::client_config(true)),
            unverified: Arc::new(tls::client_config(false)),
        }
    }

    /// Send `raw` to `target` and read the response.
    pub async fn send(&self, target: &Target, raw: &[u8], opts: &SendOptions) -> Result<Exchange, SendError> {
        let started = Instant::now();
        let started_ms = now_ms();
        let (method, path, _) = request_line(raw);
        if method.is_empty() {
            return Err(SendError::BadRequest("no request line"));
        }
        let request = if opts.update_content_length {
            wire::update_content_length(raw)
        } else {
            raw.to_vec()
        };

        // The gate resolves the name (blocking), so it runs off the async threads. Its answer is the only
        // address list this send will connect to.
        let gate = self.gate.clone();
        let (source, scheme, host, port, gpath) = (
            opts.source,
            target.scheme,
            target.host.clone(),
            target.port,
            gate_path(&path),
        );
        let pinned = tokio::task::spawn_blocking({
            let host = host.clone();
            let gpath = gpath.clone();
            move || gate.check(source, scheme, &host, port, &gpath)
        })
        .await
        .map_err(|e| SendError::Connect(host.clone(), e.to_string()))??;
        let dns_ms = started.elapsed().as_millis() as u64;
        let in_scope = self.gate.scope().contains(scheme, &host, port, &gpath);

        let deadline = started + opts.total_timeout;
        let t0 = Instant::now();
        let (tcp, peer) = connect_pinned(&pinned.addrs, opts.connect_timeout)
            .await
            .map_err(|e| SendError::Connect(format!("{}:{}", pinned.host, pinned.port), e))?;
        let connect_ms = t0.elapsed().as_millis() as u64;

        let head_only = method.eq_ignore_ascii_case("HEAD");
        let mut ex = Exchange {
            target: target.clone(),
            request,
            response: Vec::new(),
            status: None,
            truncated: false,
            error: None,
            peer,
            tls: None,
            timings: Timings {
                dns_ms,
                connect_ms,
                ..Timings::default()
            },
            started_ms,
            in_scope,
        };

        match scheme {
            Scheme::Http => self.exchange(tcp, &mut ex, head_only, opts, deadline).await?,
            Scheme::Https => {
                let cfg = if opts.verify_tls {
                    &self.verified
                } else {
                    &self.unverified
                };
                let name =
                    tls::server_name(&pinned.host).map_err(|e| SendError::Tls(pinned.host.clone(), e))?;
                let t1 = Instant::now();
                let conn = tokio::time::timeout(
                    opts.connect_timeout,
                    TlsConnector::from(cfg.clone()).connect(name, tcp),
                )
                .await
                .map_err(|_| SendError::Tls(pinned.host.clone(), "timed out".into()))?
                .map_err(|e| SendError::Tls(pinned.host.clone(), e.to_string()))?;
                ex.timings.tls_ms = Some(t1.elapsed().as_millis() as u64);
                ex.tls = Some(tls::info(conn.get_ref().1));
                self.exchange(conn, &mut ex, head_only, opts, deadline).await?;
            }
        }
        ex.timings.total_ms = started.elapsed().as_millis() as u64;
        Ok(ex)
    }

    async fn exchange<S>(
        &self,
        mut io: S,
        ex: &mut Exchange,
        head_only: bool,
        opts: &SendOptions,
        deadline: Instant,
    ) -> Result<(), SendError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let written = Instant::now();
        let w = async {
            io.write_all(&ex.request).await?;
            io.flush().await
        };
        match tokio::time::timeout_at(deadline.into(), w).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(SendError::Write(e.to_string())),
            Err(_) => return Err(SendError::Write("timed out".into())),
        }
        let mut res = self.budget.reserve(64 * 1024).ok_or(SendError::OutOfMemory)?;
        let out = read_response(
            &mut io,
            head_only,
            opts,
            deadline,
            written,
            &self.budget,
            &mut res,
        )
        .await;
        ex.response = out.bytes;
        ex.status = out.status;
        ex.truncated = out.truncated;
        ex.error = out.error;
        ex.timings.first_byte_ms = out.first_byte_ms;
        Ok(())
    }
}

struct Read {
    bytes: Vec<u8>,
    status: Option<u16>,
    truncated: bool,
    error: Option<String>,
    first_byte_ms: Option<u64>,
}

/// Read one response (skipping `100 Continue` and other interim ones, which stay in the bytes).
async fn read_response<S>(
    io: &mut S,
    head_only: bool,
    opts: &SendOptions,
    deadline: Instant,
    since: Instant,
    budget: &MemoryBudget,
    res: &mut Reservation,
) -> Read
where
    S: AsyncRead + Unpin,
{
    let mut out = Read {
        bytes: Vec::new(),
        status: None,
        truncated: false,
        error: None,
        first_byte_ms: None,
    };
    let mut chunk = vec![0u8; 16 * 1024];
    // Start of the message being read (interim responses come before it), and its parsed shape.
    let mut msg_start = 0usize;
    let mut body_start: Option<usize> = None;
    let mut framing = Framing::None;
    let mut scanner = ChunkScanner::default();
    loop {
        // Is the response complete with what we have?
        if body_start.is_none()
            && let Some(rel) = wire::head_end(&out.bytes[msg_start..])
        {
            let end = msg_start + rel;
            match parse_head(&out.bytes[msg_start..end]) {
                Ok(h) if h.status / 100 == 1 && h.status != 101 => {
                    msg_start = end;
                    continue;
                }
                Ok(h) => {
                    out.status = Some(h.status);
                    framing = if head_only || h.status == 101 || h.status == 204 || h.status == 304 {
                        Framing::None
                    } else {
                        h.framing
                    };
                    body_start = Some(end);
                }
                Err(e) => {
                    out.error = Some(e.into());
                    return out;
                }
            }
        }
        if let Some(bs) = body_start {
            let body = &out.bytes[bs..];
            let done = match framing {
                Framing::None => true,
                Framing::Length(n) => body.len() as u64 >= n,
                Framing::Chunked => match scanner.advance(body) {
                    Ok(end) => end.is_some(),
                    Err(e) => {
                        out.error = Some(format!("bad chunked body: {e}"));
                        return out;
                    }
                },
                Framing::UntilClose => false,
            };
            if done {
                // Anything past the end of this message is not part of the response.
                match framing {
                    Framing::Length(n) => out.bytes.truncate(bs + n as usize),
                    Framing::None => out.bytes.truncate(bs),
                    Framing::Chunked => {
                        if let Ok(Some(end)) = ChunkScanner::default().advance(&out.bytes[bs..]) {
                            out.bytes.truncate(bs + end);
                        }
                    }
                    Framing::UntilClose => {}
                }
                return out;
            }
        }
        if out.bytes.len() >= opts.max_response {
            out.bytes.truncate(opts.max_response);
            out.truncated = true;
            return out;
        }
        let wait = opts
            .idle_timeout
            .min(deadline.saturating_duration_since(Instant::now()));
        if wait.is_zero() {
            out.error = Some("timed out".into());
            return out;
        }
        match tokio::time::timeout(wait, io.read(&mut chunk)).await {
            Err(_) => {
                out.error = Some("timed out waiting for the response".into());
                return out;
            }
            Ok(Err(e)) => {
                out.error = Some(format!("read failed: {e}"));
                return out;
            }
            Ok(Ok(0)) => {
                // The server closed. For a close-delimited body that is the end; otherwise it is early.
                if body_start.is_none() {
                    if !out.bytes.is_empty() {
                        out.error = Some("connection closed before the response head ended".into());
                    } else {
                        out.error = Some("connection closed without a response".into());
                    }
                } else if framing != Framing::UntilClose {
                    out.error = Some("connection closed before the response body ended".into());
                }
                return out;
            }
            Ok(Ok(n)) => {
                if out.first_byte_ms.is_none() {
                    out.first_byte_ms = Some(since.elapsed().as_millis() as u64);
                }
                if res.bytes() < (out.bytes.len() + n) * COPY_FACTOR
                    && !res.grow((64 * 1024).max(n) * COPY_FACTOR, budget)
                {
                    out.truncated = true;
                    out.error = Some("the memory budget is spent".into());
                    return out;
                }
                out.bytes.extend_from_slice(&chunk[..n]);
            }
        }
    }
}

struct Head {
    status: u16,
    framing: Framing,
}

fn parse_head(head: &[u8]) -> Result<Head, &'static str> {
    let mut headers = [httparse::EMPTY_HEADER; bosun_model::raw::MAX_HEADERS];
    let mut r = httparse::Response::new(&mut headers);
    let cfg = httparse::ParserConfig::default();
    match cfg.parse_response(&mut r, head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err("the response head is not valid HTTP/1.x"),
    }
    let status = r.code.ok_or("no status code")?;
    let chunked = r.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(h.value).is_ok_and(|v| v.to_ascii_lowercase().contains("chunked"))
    });
    let length = r.headers.iter().find_map(|h| {
        h.name
            .eq_ignore_ascii_case("content-length")
            .then(|| std::str::from_utf8(h.value).ok()?.trim().parse::<u64>().ok())
            .flatten()
    });
    let framing = if chunked {
        Framing::Chunked
    } else if let Some(n) = length {
        Framing::Length(n)
    } else {
        Framing::UntilClose
    };
    Ok(Head { status, framing })
}

/// Try each pinned address in turn; the first that accepts wins.
async fn connect_pinned(addrs: &[SocketAddr], timeout: Duration) -> Result<(TcpStream, SocketAddr), String> {
    let mut last = "no addresses".to_string();
    for a in addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok((s, *a));
            }
            Ok(Err(e)) => last = format!("{a}: {e}"),
            Err(_) => last = format!("{a}: timed out"),
        }
    }
    Err(last)
}

/// Method, target and version from a raw request's first line, lossily.
fn request_line(raw: &[u8]) -> (String, String, String) {
    let line_end = raw.iter().position(|&b| b == b'\n').unwrap_or(raw.len());
    let line = String::from_utf8_lossy(&raw[..line_end]);
    let mut it = line.trim_end_matches('\r').split(' ');
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("").to_string();
    let version = it.next().unwrap_or("HTTP/1.1").to_string();
    (method, target, version)
}

/// The path the scope rules see: no query, no scheme and host of an absolute-form target.
fn gate_path(target: &str) -> String {
    let t = target.split(['?', '#']).next().unwrap_or("");
    let t = match t.find("://") {
        Some(i) => t[i + 3..].find('/').map_or("/", |j| &t[i + 3 + j..]),
        None => t,
    };
    if t.starts_with('/') {
        t.to_string()
    } else {
        "/".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_path_strips_query_and_absolute_form() {
        assert_eq!(gate_path("/a/b?x=1"), "/a/b");
        assert_eq!(gate_path("http://h:8/p/q?z"), "/p/q");
        assert_eq!(gate_path("http://h"), "/");
        assert_eq!(gate_path("*"), "/");
    }

    #[test]
    fn request_line_is_read_lossily() {
        let (m, t, v) = request_line(b"BREW /pot HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!((m.as_str(), t.as_str(), v.as_str()), ("BREW", "/pot", "HTTP/1.1"));
    }
}
