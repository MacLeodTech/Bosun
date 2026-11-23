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
                        if !r.grow(want, b) {
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
    mut body: B,
    limit: usize,
    budget: &MemoryBudget,
) -> Result<(Vec<u8>, Reservation), CollectError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    use http_body_util::BodyExt;
    if body.size_hint().lower() > limit as u64 {
        return Err(CollectError::TooBig);
    }
    let mut mem = budget.reserve(0).ok_or(CollectError::OutOfMemory)?;
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| CollectError::Other(e.into().to_string()))?;
        if let Some(d) = frame.data_ref() {
            if out.len() + d.len() > limit {
                return Err(CollectError::TooBig);
            }
            if !mem.grow(d.len() * crate::budget::COPY_FACTOR, budget) {
                return Err(CollectError::OutOfMemory);
            }
            out.extend_from_slice(d);
        }
    }
    Ok((out, mem))
}
