//! A wrapper around `Sink` that can be cloned and shared between tasks.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use futures_util::{Sink as FutureSink, SinkExt};
use parking_lot::Mutex;
use std::sync::Arc;
use std::task::{ready, Poll};
use tracing::trace;
use tungstenite::Message;

/// A wrapper around `Sink` that can be cloned and shared between tasks.
pub struct LockedSink<Sink>(Arc<Mutex<Sink>>);

impl<Sink> LockedSink<Sink> {
    /// Create a new `LockedSink` from a `Sink`
    #[inline]
    pub fn new(sink: Sink) -> Self {
        Self(Arc::new(Mutex::new(sink)))
    }
}

impl<Sink: FutureSink<Message, Error = tungstenite::Error> + Unpin> LockedSink<Sink> {
    /// Lock and send the resulting `Message` from a computation
    #[inline]
    pub fn poll_send_with(
        &self,
        cx: &mut std::task::Context<'_>,
        msg_fn: impl FnOnce() -> Message,
    ) -> Poll<Result<(), tungstenite::Error>> {
        let mut sink = self.0.lock();
        // `ready`: if we return here, nothing happens
        ready!(sink.poll_ready_unpin(cx))?;
        let msg = msg_fn();
        let result = sink.start_send_unpin(msg);
        trace!("message sent");
        Poll::Ready(result)
    }

    /// Lock and send a `Message`
    #[inline]
    pub fn poll_send_message(
        &self,
        cx: &mut std::task::Context<'_>,
        msg: &Message,
    ) -> Poll<Result<(), tungstenite::Error>> {
        self.poll_send_with(cx, || msg.clone())
    }

    /// Lock and flush the sink
    #[inline]
    pub fn poll_flush(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), tungstenite::Error>> {
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
        cx: &mut std::task::Context<'_>,
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

    /// Lock and close the sink
    #[inline]
    pub fn poll_close(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), tungstenite::Error>> {
        self.0.lock().poll_close_unpin(cx)
    }
}

impl<Sink> Clone for LockedSink<Sink> {
    // `Clone` is manually implemented because we don't need `Sink: Clone`.
    #[inline]
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<Sink> crate::dupe::Dupe for LockedSink<Sink> {
    #[inline]
    fn dupe(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<Sink: std::fmt::Debug> std::fmt::Debug for LockedSink<Sink> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Mutex<Sink> as std::fmt::Debug>::fmt(self.0.as_ref(), f)
    }
}
