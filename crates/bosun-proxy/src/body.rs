//! Response bodies streamed to the client while a capped copy is kept for history.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

use crate::upstream::BoxError;

/// Called once with the captured bytes when the body ends, fails, or is dropped part-way.
pub type OnDone = Box<dyn FnOnce(Vec<u8>, bool, Option<String>) + Send>;

pub struct TeeBody<B> {
    inner: B,
    captured: Vec<u8>,
    limit: usize,
    truncated: bool,
    on_done: Option<OnDone>,
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
        };
        if t.inner.is_end_stream() {
            t.finish(None);
        }
        t
    }
}

impl<B> TeeBody<B> {
    fn finish(&mut self, error: Option<String>) {
        if let Some(f) = self.on_done.take() {
            f(std::mem::take(&mut self.captured), self.truncated, error);
        }
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
                    let room = this.limit.saturating_sub(this.captured.len());
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
