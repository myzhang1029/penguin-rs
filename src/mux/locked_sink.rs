//! A wrapper around `Sink + Stream` that can be cloned and shared between tasks.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use futures_util::{Sink as FutureSink, SinkExt, Stream as FutureStream, StreamExt};
use parking_lot::Mutex;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tracing::trace;
use tungstenite::Message;

/// A wrapper around `Sink + Stream` that can be cloned and shared between tasks.
pub struct LockedSink<SinkStream>(Arc<Mutex<SinkStream>>);

impl<SinkStream> LockedSink<SinkStream> {
    /// Create a new `LockedSink` from a `Sink + Stream`
    #[inline]
    pub fn new(sink: SinkStream) -> Self {
        Self(Arc::new(Mutex::new(sink)))
    }
}

impl<Sink: FutureSink<Message, Error = tungstenite::Error> + Unpin> LockedSink<Sink> {
    /// Lock and send the resulting `Message` from a computation.
    /// The computation is only executed if the sink is ready.
    /// The computation may return `Poll::Pending` to indicate that it is not
    /// ready yet, in which case the task should be woken up when it is ready.
    #[inline]
    pub fn poll_send_with(
        &self,
        cx: &mut Context<'_>,
        msg_fn: impl FnOnce(&mut Context<'_>) -> Poll<Message>,
    ) -> Poll<Result<(), tungstenite::Error>> {
        let mut sink = self.0.lock();
        // `ready`: if we return here, nothing happens
        ready!(sink.poll_ready_unpin(cx))?;
        let msg = ready!(msg_fn(cx));
        let result = sink.start_send_unpin(msg);
        trace!("message sent");
        Poll::Ready(result)
    }

    #[inline]
    pub async fn send_with(&self, msg_fn: impl Fn() -> Message) -> Result<(), tungstenite::Error> {
        poll_fn(|cx| self.poll_send_with(cx, |_cx| Poll::Ready(msg_fn()))).await
    }

    #[inline]
    pub async fn send_message(&self, msg: &Message) -> Result<(), tungstenite::Error> {
        self.send_with(|| msg.clone()).await
    }

    /// Lock and flush the sink
    #[inline]
    pub fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<Result<(), tungstenite::Error>> {
        self.0.lock().poll_flush_unpin(cx)
    }

    /// Lock and flush the sink, ignoring errors that indicate the connection
    /// is closed.
    /// It is sometimes acceptable when the other side closes the connection
    /// because the user should only discover this when they try to work with
    /// the stream for the next time.
    #[inline]
    pub fn poll_flush_ignore_closed(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), tungstenite::Error>> {
        match ready!(self.0.lock().poll_flush_unpin(cx)) {
            Ok(()) | Err(tungstenite::Error::ConnectionClosed) => Poll::Ready(Ok(())),
            Err(tungstenite::Error::Io(ioerror))
                if ioerror.kind() == std::io::ErrorKind::BrokenPipe =>
            {
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    #[inline]
    pub async fn flush_ignore_closed(&self) -> Result<(), tungstenite::Error> {
        poll_fn(|cx| self.poll_flush_ignore_closed(cx)).await
    }

    /// Lock and close the sink
    #[inline]
    pub fn poll_close(&self, cx: &mut Context<'_>) -> Poll<Result<(), tungstenite::Error>> {
        self.0.lock().poll_close_unpin(cx)
    }

    #[inline]
    pub async fn close(&self) -> Result<(), tungstenite::Error> {
        poll_fn(|cx| self.poll_close(cx)).await
    }
}

impl<Stream: FutureStream<Item = tungstenite::Result<Message>> + Unpin> LockedSink<Stream> {
    #[inline]
    pub fn poll_next(&self, cx: &mut Context<'_>) -> Poll<Option<tungstenite::Result<Message>>> {
        self.0.lock().poll_next_unpin(cx)
    }

    #[inline]
    pub async fn next(&self) -> Option<tungstenite::Result<Message>> {
        poll_fn(|cx| self.poll_next(cx)).await
    }
}

impl<SinkStream> Clone for LockedSink<SinkStream> {
    // `Clone` is manually implemented because we don't need `SinkStream: Clone`.
    #[inline]
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<SinkStream> crate::dupe::Dupe for LockedSink<SinkStream> {
    #[inline]
    fn dupe(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<SinkStream: std::fmt::Debug> std::fmt::Debug for LockedSink<SinkStream> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Mutex<SinkStream> as std::fmt::Debug>::fmt(self.0.as_ref(), f)
    }
}
