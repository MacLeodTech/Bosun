//! Multiplexed HTTP/2: one shared connection per target carrying many requests at once.
//!
//! A [`Conn`] is a background task that owns the socket. Requests arrive as jobs; the task gives each a stream
//! id, writes its frames, keeps both flow-control windows (what we may send, and what we let the server send),
//! reads responses and hands each back to whoever asked. It answers `SETTINGS` and `PING`, honours the server's
//! limits (concurrent streams, frame size, windows), stops taking new requests after `GOAWAY`, and cancels a
//! stream (`RST_STREAM`) when its caller gives up.
//!
//! Requests are encoded as written, like the plans in [`crate::h2`]: nothing is added or corrected. A batch is
//! written in one go, which is what a race-condition test (the "single-packet attack") needs: every request
//! reaches the server in the same TCP segment when they fit in one.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bosun_model::Target;
use bosun_proxy::budget::{COPY_FACTOR, MemoryBudget, Reservation};
use bosun_proxy::upstream::Registration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};

use crate::h2::{
    self, H2Details, H2Request, HeaderCollector, Headers, PREFACE, data_payload, encode_block, flag, parse_frame,
    pseudo, ty,
};
use crate::h2::Frame;
use crate::{Engine, Exchange, Io, SendError, SendOptions, TlsInfo, gate_path, pool};

/// How much a stream may receive before we raise its window, and the window we start with.
const STREAM_WINDOW: u32 = 1 << 20;
/// The connection-level receive window we ask for.
const CONN_WINDOW: u32 = 16 << 20;
/// A connection with nothing to do for this long is closed.
const IDLE_CLOSE: Duration = Duration::from_secs(60);

/// What a request came to.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    pub status: Option<u16>,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub truncated: bool,
    pub error: Option<String>,
    pub rst: Option<u32>,
    pub goaway: Option<(u32, u32)>,
    /// The server did not process the request (`GOAWAY` below its stream, or `REFUSED_STREAM`): sending it again
    /// on a new connection is safe whatever the method.
    pub retry_safe: bool,
    /// The connection ended before a single byte of response for this stream.
    pub no_response: bool,
    pub first_byte_ms: Option<u64>,
    pub frames_in: Vec<Frame>,
    pub frames_out: Vec<Frame>,
}

pub(crate) struct Job {
    pub headers: Headers,
    pub body: Vec<u8>,
    pub max_response: usize,
    pub deadline: Instant,
    pub reply: oneshot::Sender<Outcome>,
}

enum Cmd {
    /// Start all of these in one write.
    Batch(Vec<Job>),
}

/// A shared HTTP/2 connection.
pub struct Conn {
    tx: mpsc::Sender<Cmd>,
    alive: Arc<AtomicBool>,
    pub(crate) peer: SocketAddr,
    pub(crate) tls: Option<TlsInfo>,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn").field("peer", &self.peer).finish_non_exhaustive()
    }
}

impl Conn {
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst) && !self.tx.is_closed()
    }

    /// Queue jobs; if the connection is gone they come back.
    async fn submit(&self, jobs: Vec<Job>) -> Result<(), Vec<Job>> {
        match self.tx.send(Cmd::Batch(jobs)).await {
            Ok(()) => Ok(()),
            Err(mpsc::error::SendError(Cmd::Batch(jobs))) => Err(jobs),
        }
    }

    /// Write the connection preface and our settings, then start the driver.
    pub(crate) async fn start(
        mut io: Box<dyn Io>,
        reg: Registration,
        peer: SocketAddr,
        tls: Option<TlsInfo>,
        budget: MemoryBudget,
    ) -> Result<Arc<Self>, SendError> {
        let mut hello = PREFACE.to_vec();
        // No server push; our per-stream receive window; then the connection window.
        for f in [
            Frame::settings(&[(0x2, 0), (0x4, STREAM_WINDOW)]),
            Frame::window_update(0, CONN_WINDOW - 65_535),
        ] {
            hello.extend_from_slice(&f.encode());
        }
        io.write_all(&hello)
            .await
            .map_err(|e| SendError::Write(e.to_string()))?;
        io.flush().await.map_err(|e| SendError::Write(e.to_string()))?;
        let (rd, wr) = tokio::io::split(io);
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (ev_tx, ev_rx) = mpsc::channel(256);
        let alive = Arc::new(AtomicBool::new(true));
        tokio::spawn(reader(rd, ev_tx));
        tokio::spawn(
            Driver::new(wr, budget, alive.clone())
                .run(cmd_rx, ev_rx, reg),
        );
        Ok(Arc::new(Self {
            tx: cmd_tx,
            alive,
            peer,
            tls,
        }))
    }
}

enum Event {
    Frame(Frame),
    Closed(Option<String>),
}

async fn reader(mut rd: ReadHalf<Box<dyn Io>>, tx: mpsc::Sender<Event>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 32 * 1024];
    loop {
        match rd.read(&mut chunk).await {
            Ok(0) => {
                let _ = tx.send(Event::Closed(None)).await;
                return;
            }
            Err(e) => {
                let _ = tx.send(Event::Closed(Some(e.to_string()))).await;
                return;
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        let mut used = 0;
        loop {
            match parse_frame(&buf[used..], 1 << 20) {
                Ok(Some((f, n))) => {
                    used += n;
                    if tx.send(Event::Frame(f)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(len) => {
                    let _ = tx
                        .send(Event::Closed(Some(format!("a frame of {len} bytes is over the limit"))))
                        .await;
                    return;
                }
            }
        }
        buf.drain(..used);
    }
}

struct Stream {
    reply: oneshot::Sender<Outcome>,
    deadline: Instant,
    max_response: usize,
    status: Option<u16>,
    headers: Headers,
    body: Vec<u8>,
    to_send: Vec<u8>,
    sent: usize,
    send_window: i64,
    recv_unacked: u32,
    res: Reservation,
    truncated: bool,
    started: Instant,
    first_byte: Option<u64>,
    frames_in: Vec<Frame>,
    frames_out: Vec<Frame>,
}

struct Driver {
    wr: WriteHalf<Box<dyn Io>>,
    budget: MemoryBudget,
    alive: Arc<AtomicBool>,
    collector: HeaderCollector,
    streams: BTreeMap<u32, Stream>,
    pending: VecDeque<Job>,
    next_id: u32,
    conn_send: i64,
    peer_initial: i64,
    peer_max_frame: usize,
    peer_max_streams: usize,
    conn_recv_unacked: u32,
    goaway: Option<(u32, u32)>,
    out: Vec<u8>,
    last_activity: Instant,
}

impl Driver {
    fn new(wr: WriteHalf<Box<dyn Io>>, budget: MemoryBudget, alive: Arc<AtomicBool>) -> Self {
        Self {
            wr,
            budget,
            alive,
            collector: HeaderCollector::new(),
            streams: BTreeMap::new(),
            pending: VecDeque::new(),
            next_id: 1,
            conn_send: 65_535,
            peer_initial: 65_535,
            peer_max_frame: 16_384,
            peer_max_streams: 100,
            conn_recv_unacked: 0,
            goaway: None,
            out: Vec::new(),
            last_activity: Instant::now(),
        }
    }

    async fn run(mut self, mut cmds: mpsc::Receiver<Cmd>, mut events: mpsc::Receiver<Event>, _reg: Registration) {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        let mut cmds_open = true;
        loop {
            tokio::select! {
                cmd = cmds.recv(), if cmds_open && self.goaway.is_none() => match cmd {
                    Some(Cmd::Batch(jobs)) => {
                        self.last_activity = Instant::now();
                        self.pending.extend(jobs);
                    }
                    None => cmds_open = false,
                },
                ev = events.recv() => match ev {
                    Some(Event::Frame(f)) => {
                        self.last_activity = Instant::now();
                        self.on_frame(f);
                    }
                    Some(Event::Closed(e)) => {
                        self.fail_all(e.unwrap_or_else(|| "the connection closed".into()), false);
                        break;
                    }
                    None => break,
                },
                _ = tick.tick() => {
                    self.expire();
                    let idle = self.streams.is_empty() && self.pending.is_empty();
                    if idle && (!cmds_open || self.goaway.is_some() || self.last_activity.elapsed() > IDLE_CLOSE) {
                        break;
                    }
                }
            }
            self.start_pending();
            self.pump();
            if !self.out.is_empty() {
                let buf = std::mem::take(&mut self.out);
                let w = async {
                    self.wr.write_all(&buf).await?;
                    self.wr.flush().await
                };
                if let Err(e) = w.await {
                    self.fail_all(format!("write failed: {e}"), false);
                    break;
                }
            }
            if self.next_id > 0x7fff_fff0 {
                // Out of stream ids: take no more requests on this connection.
                self.alive.store(false, Ordering::SeqCst);
            }
        }
        self.alive.store(false, Ordering::SeqCst);
        self.fail_all("the connection closed".into(), false);
        let _ = self.wr.shutdown().await;
    }

    fn put(&mut self, f: &Frame) {
        self.out.extend_from_slice(&f.encode());
    }

    fn start_pending(&mut self) {
        while self.streams.len() < self.peer_max_streams && self.next_id <= 0x7fff_fff0 {
            let Some(job) = self.pending.pop_front() else { break };
            let id = self.next_id;
            self.next_id += 2;
            let Some(res) = self.budget.reserve(32 * 1024) else {
                let _ = job.reply.send(Outcome {
                    error: Some("the memory budget is spent".into()),
                    ..Outcome::default()
                });
                continue;
            };
            let block = encode_block(&job.headers);
            let end_stream = if job.body.is_empty() { flag::END_STREAM } else { 0 };
            let mut frames_out = Vec::new();
            let max = self.peer_max_frame.max(1);
            if block.len() <= max {
                frames_out.push(Frame::new(ty::HEADERS, flag::END_HEADERS | end_stream, id, block));
            } else {
                let mut chunks = block.chunks(max).peekable();
                if let Some(first) = chunks.next() {
                    frames_out.push(Frame::new(ty::HEADERS, end_stream, id, first.to_vec()));
                }
                while let Some(c) = chunks.next() {
                    let f = if chunks.peek().is_none() { flag::END_HEADERS } else { 0 };
                    frames_out.push(Frame::new(ty::CONTINUATION, f, id, c.to_vec()));
                }
            }
            // The header frames are written together, so no other stream's frame comes between them.
            for f in &frames_out {
                self.put(f);
            }
            self.streams.insert(
                id,
                Stream {
                    reply: job.reply,
                    deadline: job.deadline,
                    max_response: job.max_response,
                    status: None,
                    headers: Vec::new(),
                    body: Vec::new(),
                    to_send: job.body,
                    sent: 0,
                    send_window: self.peer_initial,
                    recv_unacked: 0,
                    res,
                    truncated: false,
                    started: Instant::now(),
                    first_byte: None,
                    frames_in: Vec::new(),
                    frames_out,
                },
            );
        }
    }

    /// Write as much request body as the windows and the frame size allow.
    fn pump(&mut self) {
        let max = self.peer_max_frame;
        let mut frames = Vec::new();
        for (id, st) in &mut self.streams {
            while st.sent < st.to_send.len() && self.conn_send > 0 && st.send_window > 0 {
                let n = (st.to_send.len() - st.sent)
                    .min(max)
                    .min(st.send_window as usize)
                    .min(self.conn_send as usize);
                let last = st.sent + n == st.to_send.len();
                frames.push(Frame::new(
                    ty::DATA,
                    if last { flag::END_STREAM } else { 0 },
                    *id,
                    st.to_send[st.sent..st.sent + n].to_vec(),
                ));
                st.sent += n;
                st.send_window -= n as i64;
                self.conn_send -= n as i64;
            }
        }
        for f in &frames {
            self.put(f);
        }
    }

    fn on_frame(&mut self, f: Frame) {
        let sid = f.stream & 0x7fff_ffff;
        match f.ty {
            ty::SETTINGS if f.flags & flag::ACK == 0 => {
                for pair in f.payload.as_chunks::<6>().0 {
                    let id = u16::from_be_bytes([pair[0], pair[1]]);
                    let v = u32::from_be_bytes([pair[2], pair[3], pair[4], pair[5]]);
                    match id {
                        0x3 => self.peer_max_streams = (v as usize).max(1),
                        0x4 if v <= 0x7fff_ffff => {
                            let delta = i64::from(v) - self.peer_initial;
                            self.peer_initial = i64::from(v);
                            for st in self.streams.values_mut() {
                                st.send_window += delta;
                            }
                        }
                        0x5 if (16_384..=16_777_215).contains(&v) => self.peer_max_frame = v as usize,
                        _ => {}
                    }
                }
                self.put(&Frame::new(ty::SETTINGS, flag::ACK, 0, Vec::new()));
            }
            ty::PING if f.flags & flag::ACK == 0 => {
                let reply = Frame::new(ty::PING, flag::ACK, 0, f.payload.clone());
                self.put(&reply);
            }
            ty::WINDOW_UPDATE if f.payload.len() == 4 => {
                let inc = i64::from(u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]) & 0x7fff_ffff);
                if sid == 0 {
                    self.conn_send += inc;
                } else if let Some(st) = self.streams.get_mut(&sid) {
                    st.send_window += inc;
                }
            }
            ty::GOAWAY if f.payload.len() >= 8 => {
                let last = u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]) & 0x7fff_ffff;
                let code = u32::from_be_bytes([f.payload[4], f.payload[5], f.payload[6], f.payload[7]]);
                self.goaway = Some((last, code));
                self.alive.store(false, Ordering::SeqCst);
                let msg = format!("the server sent GOAWAY (error code {code}) before processing this request");
                for job in std::mem::take(&mut self.pending) {
                    let _ = job.reply.send(Outcome {
                        error: Some(msg.clone()),
                        goaway: self.goaway,
                        retry_safe: true,
                        no_response: true,
                        ..Outcome::default()
                    });
                }
                let doomed: Vec<u32> = self.streams.keys().copied().filter(|id| *id > last).collect();
                for id in doomed {
                    self.finish(id, Some(msg.clone()), |o| o.retry_safe = true);
                }
            }
            ty::RST_STREAM if f.payload.len() == 4 => {
                let code = u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]);
                if let Some(st) = self.streams.get_mut(&sid) {
                    st.frames_in.push(f);
                    // `NO_ERROR` after a complete response is a server stopping our upload, not a failure.
                    let msg = (!(code == 0 && st.status.is_some()))
                        .then(|| format!("the server reset the stream (error code {code})"));
                    self.finish(sid, msg, |o| {
                        o.rst = Some(code);
                        o.retry_safe = code == 0x7;
                    });
                }
            }
            ty::DATA => self.on_data(sid, &f),
            ty::HEADERS | ty::CONTINUATION | ty::PUSH_PROMISE => {
                let kept = (f.ty != ty::PUSH_PROMISE).then(|| f.clone());
                match self.collector.feed(&f) {
                    Ok(Some(b)) if f.ty != ty::PUSH_PROMISE => {
                        if let Some(st) = self.streams.get_mut(&b.stream) {
                            st.frames_in.extend(kept);
                        }
                        self.on_block(b);
                    }
                    Ok(_) => {
                        if let (Some(st), Some(k)) = (self.streams.get_mut(&sid), kept) {
                            st.frames_in.push(k);
                        }
                    }
                    Err(e) => {
                        self.fail_all(format!("response headers: {e}"), false);
                        self.alive.store(false, Ordering::SeqCst);
                    }
                }
            }
            _ => {}
        }
    }

    fn on_block(&mut self, b: h2::Block) {
        let Some(st) = self.streams.get_mut(&b.stream) else { return };
        let status = pseudo(&b.headers, ":status").and_then(|s| std::str::from_utf8(s).ok()?.parse::<u16>().ok());
        st.first_byte.get_or_insert_with(|| st.started.elapsed().as_millis() as u64);
        match status {
            // Informational: the real response comes later.
            Some(s) if (100..200).contains(&s) => return,
            Some(s) if st.status.is_none() => {
                st.status = Some(s);
                st.headers = b.headers;
            }
            // Trailers (a second block): not part of the response we keep.
            _ => {}
        }
        if b.end_stream {
            self.finish(b.stream, None, |_| {});
        }
    }

    fn on_data(&mut self, sid: u32, f: &Frame) {
        let n = f.payload.len() as u32;
        self.conn_recv_unacked += n;
        let mut cancel = false;
        let mut done = false;
        let mut update = None;
        if let Some(st) = self.streams.get_mut(&sid) {
            st.first_byte.get_or_insert_with(|| st.started.elapsed().as_millis() as u64);
            let data = data_payload(f);
            if st.body.len() + data.len() > st.max_response {
                let room = st.max_response - st.body.len();
                st.body.extend_from_slice(&data[..room]);
                st.truncated = true;
                cancel = true;
            } else if st.res.bytes() < (st.body.len() + data.len()) * COPY_FACTOR
                && !st.res.grow((32 * 1024).max(data.len()) * COPY_FACTOR, &self.budget)
            {
                st.truncated = true;
                cancel = true;
            } else {
                st.body.extend_from_slice(data);
            }
            st.recv_unacked += n;
            if f.flags & flag::END_STREAM != 0 {
                done = true;
            } else if !cancel && st.recv_unacked >= STREAM_WINDOW / 4 {
                update = Some(std::mem::take(&mut st.recv_unacked));
            }
        }
        if let Some(inc) = update {
            self.put(&Frame::window_update(sid, inc));
        }
        if cancel {
            self.put(&Frame::rst_stream(sid, 0x8));
            self.finish(sid, Some("the response is over the limit and was cut off".into()), |_| {});
        } else if done {
            self.finish(sid, None, |_| {});
        }
        if self.conn_recv_unacked >= CONN_WINDOW / 16 {
            let inc = std::mem::take(&mut self.conn_recv_unacked);
            self.put(&Frame::window_update(0, inc));
        }
    }

    /// Remove a stream and give its caller the result.
    fn finish(&mut self, id: u32, error: Option<String>, tweak: impl FnOnce(&mut Outcome)) {
        let Some(st) = self.streams.remove(&id) else { return };
        // The response ended before we finished sending: stop the upload.
        if st.sent < st.to_send.len() {
            self.put(&Frame::rst_stream(id, 0x8));
        }
        let mut o = Outcome {
            status: st.status,
            headers: st.headers,
            body: st.body,
            truncated: st.truncated,
            error,
            goaway: self.goaway,
            first_byte_ms: st.first_byte,
            no_response: st.first_byte.is_none(),
            frames_in: st.frames_in,
            frames_out: st.frames_out,
            ..Outcome::default()
        };
        tweak(&mut o);
        let _ = st.reply.send(o);
    }

    fn fail_all(&mut self, why: String, retry_safe: bool) {
        for job in std::mem::take(&mut self.pending) {
            let _ = job.reply.send(Outcome {
                error: Some(why.clone()),
                no_response: true,
                retry_safe,
                ..Outcome::default()
            });
        }
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            self.finish(id, Some(why.clone()), |o| o.retry_safe = retry_safe);
        }
    }

    /// Cancel streams nobody is waiting for any more, and those past their deadline.
    fn expire(&mut self) {
        let now = Instant::now();
        let gone: Vec<(u32, bool)> = self
            .streams
            .iter()
            .filter(|(_, s)| s.reply.is_closed() || now >= s.deadline)
            .map(|(id, s)| (*id, s.reply.is_closed()))
            .collect();
        for (id, abandoned) in gone {
            self.put(&Frame::rst_stream(id, 0x8));
            let msg = (!abandoned).then(|| "timed out waiting for the response".to_string());
            // `finish` would send a second reset for an unfinished upload; the stream is already cancelled.
            if let Some(st) = self.streams.get_mut(&id) {
                st.sent = st.to_send.len();
            }
            self.finish(id, msg, |_| {});
        }
    }
}

impl Engine {
    /// Send one HTTP/2 request on the shared connection to `target`, opening it if there is none. Many sends can
    /// be in flight on the one connection at the same time.
    pub async fn send_h2_request(
        &self,
        target: &Target,
        req: &H2Request,
        opts: &SendOptions,
    ) -> Result<Exchange, SendError> {
        let mut v = self.send_h2_batch(target, std::slice::from_ref(req), opts).await?;
        v.pop().ok_or(SendError::BadRequest("no request"))
    }

    /// Send several requests on the shared connection, all written in one go. For a race-condition test this is
    /// the "single-packet attack": the requests reach the server together, so it handles them as close to
    /// simultaneously as the network allows. Results come back in the order of `reqs`. The scope gate is asked
    /// about every `:path` first, and nothing is sent if any is refused.
    pub async fn send_h2_batch(
        &self,
        target: &Target,
        reqs: &[H2Request],
        opts: &SendOptions,
    ) -> Result<Vec<Exchange>, SendError> {
        if reqs.is_empty() {
            return Ok(Vec::new());
        }
        let paths: Vec<String> = {
            let mut p: Vec<String> = reqs
                .iter()
                .map(|r| gate_path(&String::from_utf8_lossy(pseudo(&r.headers, ":path").unwrap_or(b"/"))))
                .collect();
            p.sort();
            p.dedup();
            p
        };
        let checked = self.check(target, &paths[0], opts).await?;
        for extra in paths.iter().skip(1) {
            let gate = self.gate().clone();
            let (source, scheme, host, port, path) =
                (opts.source, target.scheme, target.host.clone(), target.port, extra.clone());
            tokio::task::spawn_blocking(move || gate.check(source, scheme, &host, port, &path))
                .await
                .map_err(|e| SendError::Connect(target.host.clone(), e.to_string()))??;
        }
        let key = pool::Key::new(target, opts.verify_tls);
        let deadline = checked.started + opts.total_timeout;
        let mut results: Vec<Option<Exchange>> = (0..reqs.len()).map(|_| None).collect();
        let mut todo: Vec<usize> = (0..reqs.len()).collect();
        for attempt in 0..2 {
            let (conn, reused, connect_ms, tls_ms) = self.h2_conn(&key, &checked, target, opts, attempt > 0).await?;
            let mut jobs = Vec::new();
            let mut waits = Vec::new();
            for &i in &todo {
                let (tx, rx) = oneshot::channel();
                jobs.push(Job {
                    headers: reqs[i].headers.clone(),
                    body: reqs[i].body.clone(),
                    max_response: opts.max_response,
                    deadline,
                    reply: tx,
                });
                waits.push((i, rx));
            }
            if let Err(back) = conn.submit(jobs).await {
                drop(back);
                if attempt == 0 {
                    continue;
                }
                return Err(SendError::Write("the HTTP/2 connection is closed".into()));
            }
            let mut retry = Vec::new();
            for (i, rx) in waits {
                let out = match tokio::time::timeout_at(deadline.into(), rx).await {
                    Ok(Ok(o)) => o,
                    Ok(Err(_)) => Outcome {
                        error: Some("the connection closed".into()),
                        no_response: true,
                        ..Outcome::default()
                    },
                    Err(_) => Outcome {
                        error: Some("timed out waiting for the response".into()),
                        ..Outcome::default()
                    },
                };
                let method = pseudo(&reqs[i].headers, ":method").unwrap_or(b"");
                let idempotent = [&b"GET"[..], b"HEAD", b"OPTIONS", b"TRACE", b"PUT", b"DELETE"]
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(method));
                if attempt == 0 && (out.retry_safe || (reused && out.no_response && idempotent)) {
                    retry.push(i);
                    continue;
                }
                let mut ex = Self::blank_exchange(
                    &checked,
                    target,
                    h2::render_request(&reqs[i].headers, &reqs[i].body),
                    conn.peer,
                );
                ex.tls = conn.tls.clone();
                ex.reused = reused;
                if !reused {
                    ex.timings.connect_ms = connect_ms;
                    ex.timings.tls_ms = tls_ms;
                }
                ex.status = out.status;
                ex.truncated = out.truncated;
                ex.error = out.error;
                ex.timings.first_byte_ms = out.first_byte_ms;
                ex.timings.total_ms = checked.started.elapsed().as_millis() as u64;
                if let Some(s) = out.status {
                    ex.response = h2::render_response(s.to_string().as_bytes(), &out.headers, &out.body);
                }
                ex.h2 = Some(H2Details {
                    frames_out: out.frames_out,
                    frames_in: out.frames_in,
                    goaway: out.goaway,
                    rst: out.rst,
                    response_headers: out.headers,
                    request_headers: reqs[i].headers.clone(),
                });
                results[i] = Some(ex);
            }
            todo = retry;
            if todo.is_empty() {
                break;
            }
        }
        results
            .into_iter()
            .map(|r| r.ok_or(SendError::BadRequest("a request was never sent")))
            .collect()
    }

    /// The shared connection for `key`: the live one if its address is still among the pinned ones, otherwise a
    /// new one. Returns whether it was reused, and the connect and TLS times when it was not.
    async fn h2_conn(
        &self,
        key: &pool::Key,
        checked: &crate::Checked,
        target: &Target,
        opts: &SendOptions,
        force_new: bool,
    ) -> Result<(Arc<Conn>, bool, u64, Option<u64>), SendError> {
        let slot = self.pool.h2_slot(key);
        let mut guard = slot.lock().await;
        if !force_new
            && let Some(c) = guard.as_ref()
            && c.is_alive()
            && checked.pinned.addrs.contains(&c.peer)
        {
            return Ok((c.clone(), true, 0, None));
        }
        let o = self.open(checked, target, Vec::new(), opts, true, false).await?;
        if let Some(t) = &o.ex.tls
            && t.alpn.as_deref() != Some("h2")
        {
            return Err(SendError::Tls(target.host.clone(), "the server did not negotiate h2".into()));
        }
        let (connect_ms, tls_ms) = (o.ex.timings.connect_ms, o.ex.timings.tls_ms);
        let conn = Conn::start(o.io, o._reg, o.ex.peer, o.ex.tls, self.budget.clone()).await?;
        *guard = Some(conn.clone());
        Ok((conn, false, connect_ms, tls_ms))
    }
}
