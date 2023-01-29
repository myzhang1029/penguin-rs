//! A wrapper around `tokio_tungstenite::WebSocketStream` that uses locking
//! to ensure that only one task is writing to the sink at a time.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{Frame, StreamFrame};
use futures_util::{Sink as FutureSink, SinkExt};
use parking_lot::Mutex;
use std::sync::Arc;
use std::task::{ready, Poll};
use tracing::trace;
use tungstenite::Message;

/// `Sink` of frames with locking.
#[derive(Debug)]
pub(super) struct LockedMessageSink<Sink> {
    /// The sink to write to.
    sink: Arc<Mutex<Sink>>,
}

impl<Sink> LockedMessageSink<Sink> {
    /// Create a new `LockedMessageSink` from a `Sink`.
    #[inline]
    pub fn new(sink: Sink) -> Self {
        Self {
            sink: Arc::new(Mutex::new(sink)),
        }
    }
}

impl<Sink> Clone for LockedMessageSink<Sink> {
    // `Clone` is manually implemented because we don't need `Sink: Clone`.
    #[inline]
    fn clone(&self) -> Self {
        Self {
            sink: self.sink.clone(),
        }
    }
}

impl<Sink> crate::dupe::Dupe for LockedMessageSink<Sink> {
    // Explicitly providing a `dupe` implementation to prove that everything
    // can be cheaply cloned.
    #[inline]
    fn dupe(&self) -> Self {
        Self {
            sink: self.sink.dupe(),
        }
    }
}

impl<Sink: FutureSink<Message, Error = tungstenite::Error> + Unpin> LockedMessageSink<Sink> {
    /// Lock and run `sink.start_send` on the underlying `Sink`.
    #[tracing::instrument(skip(self, cx, buf), level = "trace")]
    #[inline]
    pub fn poll_send_stream_buf(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        our_port: u16,
        their_port: u16,
    ) -> Poll<Result<(), super::Error>> {
        // These code need to be duplicated instead of calling `self.poll_send_message`
        // because we want to create `Frame`s only when `sink.poll_ready` succeeds.
        let mut sink = self.sink.lock();
        // `ready`: if we return here, nothing happens
        ready!(sink.poll_ready_unpin(cx))?;
        let frame = Frame::Stream(StreamFrame::new_psh(
            our_port,
            their_port,
            buf.to_vec().into(),
        ));
        let message: Message = frame.try_into()?;
        sink.start_send_unpin(message)?;
        Poll::Ready(Ok(()))
    }

    /// Lock and send a message
    #[tracing::instrument(skip(self, cx), level = "trace")]
    #[inline]
    pub fn poll_send_message(
        &self,
        cx: &mut std::task::Context<'_>,
        msg: &Message,
    ) -> Poll<Result<(), tungstenite::Error>> {
        let mut sink = self.sink.lock();
        // `ready`: if we return here, nothing happens
        ready!(sink.poll_ready_unpin(cx))?;
        let result = sink.start_send_unpin(msg.clone());
        trace!("message sent");
        Poll::Ready(result)
    }

    /// Lock and send a message
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    pub async fn send_message(&self, msg: Message) -> Result<(), tungstenite::Error> {
        std::future::poll_fn(|cx| self.poll_send_message(cx, &msg)).await
    }

    /// Lock and run `sink.poll_flush` on the underlying `Sink`.
    #[tracing::instrument(skip(self, cx), level = "trace")]
    #[inline]
    pub fn poll_flush(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), tungstenite::Error>> {
        let mut sink = self.sink.lock();
        sink.poll_flush_unpin(cx)
    }

    /// Lock and run `sink.poll_flush` on the underlying `Sink`.
    #[tracing::instrument(skip(self), level = "trace")]
    #[inline]
    pub async fn flush(&self) -> Result<(), tungstenite::Error> {
        std::future::poll_fn(|cx| self.poll_flush(cx)).await
    }

    /// Lock and run `sink.poll_close` on the underlying `Sink`.
    /// Note that we should not close the sink if we only want to close one connection.
    #[tracing::instrument(skip(self, cx), level = "trace")]
    #[inline]
    pub fn poll_close(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), tungstenite::Error>> {
        let mut sink = self.sink.lock();
        sink.poll_close_unpin(cx)
    }

    /// Lock and run `sink.poll_close` on the underlying `Sink`.
    /// Note that we should not close the sink if we only want to close one connection.
    #[tracing::instrument(skip(self), level = "trace")]
    #[inline]
    pub async fn close(&self) -> Result<(), tungstenite::Error> {
        std::future::poll_fn(|cx| self.poll_close(cx)).await
    }
}

// Isn't very reasonable to test this file directly
