//! Response bodies streamed to the client while a capped copy is kept for history.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

use crate::budget::{MemoryBudget, Reservation};
use crate::upstream::BoxError;

/// Called once with the captured bytes when the body ends, fails, or is dropped part-way.
pub type OnDone = Box<dyn FnOnce(Vec<u8>, bool, Option<String>) + Send>;

pub struct TeeBody<B> {
    inner: B,
    captured: Vec<u8>,
    limit: usize,
    truncated: bool,
    on_done: Option<OnDone>,
    budget: Option<(MemoryBudget, Reservation)>,
    /// Bytes already reserved (admission) that capture may use up before it reserves more.
    prepaid: usize,
}

impl<B> std::fmt::Debug for TeeBody<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeeBody")
            .field("captured", &self.captured.len())
            .finish_non_exhaustive()
    }
}

impl<B: Body> TeeBody<B> {
    /// An empty body is finished immediately (hyper may never poll it).
    pub fn new(inner: B, limit: usize, on_done: OnDone) -> Self {
        let mut t = Self {
            inner,
            captured: Vec::new(),
            limit,
            truncated: false,
            on_done: Some(on_done),
            budget: None,
            prepaid: 0,
        };
        if t.inner.is_end_stream() {
            t.finish(None);
        }
        t
    }
}

impl<B> TeeBody<B> {
    /// Count the captured bytes against the shared memory budget; capture stops (and the record is marked
    /// truncated) when the budget is spent. The reservation is released when the body is done.
    pub fn with_budget(mut self, budget: &MemoryBudget) -> Self {
        if let Some(r) = budget.reserve(0) {
            self.budget = Some((budget.clone(), r));
        }
        self
    }

    /// Like [`Self::with_budget`], starting from a reservation made up front (a known body length).
    pub fn with_reservation(mut self, budget: &MemoryBudget, r: Reservation) -> Self {
        self.prepaid = r.bytes();
        self.budget = Some((budget.clone(), r));
        self
    }

    fn finish(&mut self, error: Option<String>) {
        if let Some(f) = self.on_done.take() {
            f(std::mem::take(&mut self.captured), self.truncated, error);
        }
        self.budget = None;
    }
}

impl<B> Drop for TeeBody<B> {
    fn drop(&mut self) {
        if self.on_done.is_some() {
            self.truncated = true;
            self.finish(Some(
                "the client closed the connection before the response finished".into(),
            ));
        }
    }
}

impl<B> Body for TeeBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref() {
                    let mut room = this.limit.saturating_sub(this.captured.len());
                    if let Some((b, r)) = &mut this.budget {
                        let want = d.len().min(room);
                        let from_prepaid = want.min(this.prepaid);
                        this.prepaid -= from_prepaid;
                        if want > from_prepaid && !r.grow(want - from_prepaid, b) {
                            room = 0;
                        }
                    }
                    if d.len() > room {
                        this.truncated = true;
                    }
                    this.captured.extend_from_slice(&d[..d.len().min(room)]);
                }
                // hyper stops polling once the body says it has ended, so this may be the last call.
                if this.inner.is_end_stream() {
                    this.finish(None);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                let e: BoxError = e.into();
                this.finish(Some(format!("upstream body error: {e}")));
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.finish(None);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// How much of a refused request body is read and thrown away before the refusal is sent, and for how long.
///
/// A server that answers and closes while the client is still uploading resets the connection (unread data in its
/// receive buffer), and the client can lose the answer: Windows clients report "connection aborted" instead of the
/// 413 or 503. Reading the rest of a body that is not too large lets the client finish its upload and read the
/// answer, and keeps the connection usable. Past the limit we stop and close: nothing is stored either way, so the
/// cost is bounded bandwidth and time per refused request.
pub const DISCARD_LIMIT: usize = 8 * 1024 * 1024;
pub const DISCARD_TIME: std::time::Duration = std::time::Duration::from_secs(5);

/// Read and drop the rest of a request body (up to [`DISCARD_LIMIT`] bytes, within [`DISCARD_TIME`]). Nothing is
/// buffered and nothing is reserved from the memory budget.
pub async fn discard_body<B>(mut body: B)
where
    B: Body<Data = Bytes> + Unpin,
{
    use http_body_util::BodyExt;
    let _ = tokio::time::timeout(DISCARD_TIME, async {
        let mut seen = 0usize;
        while let Some(Ok(frame)) = body.frame().await {
            if let Some(d) = frame.data_ref() {
                seen += d.len();
                if seen > DISCARD_LIMIT {
                    break;
                }
            }
        }
    })
    .await;
}

/// Why a body could not be buffered.
#[derive(Debug)]
pub enum CollectError {
    /// Over the configured per-message limit.
    TooBig,
    /// The shared memory budget is spent.
    OutOfMemory,
    Other(String),
}

/// Read a whole body into memory, reserving from the budget as it arrives (so many large concurrent bodies are
/// refused rather than exhausting memory). The reservation covers [`crate::budget::COPY_FACTOR`] copies and is
/// returned so the caller can hold it for as long as the message is buffered.
pub async fn collect_budgeted<B>(
    body: &mut B,
    limit: usize,
    budget: &MemoryBudget,
) -> Result<(Bytes, Reservation), CollectError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    use http_body_util::BodyExt;
    if body.size_hint().lower() > limit as u64 {
        return Err(CollectError::TooBig);
    }
    let mut mem = budget.reserve(0).ok_or(CollectError::OutOfMemory)?;
    // One data frame (the common case for small bodies) is kept as it is; only several are joined.
    let mut first: Option<Bytes> = None;
    let mut joined: Option<Vec<u8>> = None;
    let mut len = 0usize;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| CollectError::Other(e.into().to_string()))?;
        if let Some(d) = frame.data_ref() {
            if len + d.len() > limit {
                return Err(CollectError::TooBig);
            }
            if !mem.grow(d.len() * crate::budget::COPY_FACTOR, budget) {
                return Err(CollectError::OutOfMemory);
            }
            len += d.len();
            match (&mut first, &mut joined) {
                (None, None) => first = Some(d.clone()),
                (Some(f), None) => {
                    let mut v = Vec::with_capacity(len.max(f.len() * 2));
                    v.extend_from_slice(f);
                    v.extend_from_slice(d);
                    first = None;
                    joined = Some(v);
                }
                (_, Some(v)) => v.extend_from_slice(d),
            }
        }
    }
    let out = match (first, joined) {
        (Some(b), _) => b,
        (None, Some(v)) => Bytes::from(v),
        (None, None) => Bytes::new(),
    };
    Ok((out, mem))
}

/// Passes a body through and fails it once it has carried more than `limit` bytes (for streamed request bodies
/// of unknown length; a declared length over the limit is refused with 413 before anything is forwarded).
pub struct LimitBody<B> {
    inner: B,
    left: usize,
}

impl<B> LimitBody<B> {
    pub fn new(inner: B, limit: usize) -> Self {
        Self { inner, left: limit }
    }
}

impl<B> Body for LimitBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref() {
                    if d.len() > this.left {
                        this.left = 0;
                        return Poll::Ready(Some(Err(
                            "request body is larger than proxy.max_request_body".into()
                        )));
                    }
                    this.left -= d.len();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
