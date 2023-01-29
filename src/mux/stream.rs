//! `AsyncRead + AsyncWrite` object returned by `*_new_stream_channel`.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{Frame, StreamFrame};
use super::locked_sink::LockedMessageSink;
use super::tungstenite_error_to_io_error;
use bytes::Bytes;
use futures_util::Sink as FutureSink;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};
use tungstenite::Message;

/// All parameters of a stream channel
#[allow(clippy::module_name_repetitions)]
pub struct MuxStream<Sink> {
    /// Receive stream frames
    pub(super) frame_rx: mpsc::Receiver<Bytes>,
    /// Our port
    pub our_port: u16,
    /// Port of the other end
    pub their_port: u16,
    /// Forwarding destination. Only used on `Role::Server`
    pub dest_host: Bytes,
    /// Forwarding destination port. Only used on `Role::Server`
    pub dest_port: u16,
    /// Whether `Fin` has been sent
    pub(super) fin_sent: AtomicBool,
    /// Whether our entry in `inner.streams` has been removed and
    /// no more writes should succeed
    pub(super) stream_removed: Arc<AtomicBool>,
    /// Remaining bytes to be read
    pub(super) buf: Bytes,
    /// See `MultiplexorInner`.
    pub(super) sink: LockedMessageSink<Sink>,
    /// See `MultiplexorInner`.
    pub(super) dropped_ports_tx: mpsc::UnboundedSender<(u16, u16, bool)>,
}

impl<Sink> std::fmt::Debug for MuxStream<Sink> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxStream")
            .field("our_port", &self.our_port)
            .field("their_port", &self.their_port)
            .field("dest_host", &self.dest_host)
            .field("dest_port", &self.dest_port)
            .field("fin_sent", &self.fin_sent)
            .finish()
    }
}

impl<Sink> Drop for MuxStream<Sink> {
    /// Dropping the port should act like `close()` has been called.
    /// Since `drop` is not async, this is handled by the mux task.
    fn drop(&mut self) {
        // Notify the task that this port is no longer in use
        self.dropped_ports_tx
            .send((
                self.our_port,
                self.their_port,
                self.fin_sent.load(Ordering::Relaxed),
            ))
            // Maybe the task has already exited, who knows
            .unwrap_or_else(|_| warn!("Failed to notify task of dropped port"));
    }
}

// Proxy the AsyncRead trait to the underlying stream so that users don't access `stream`
impl<Sink> AsyncRead for MuxStream<Sink>
where
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Sync + Unpin + 'static,
{
    /// Read data from the stream.
    /// There are two cases where this function gives EOF:
    /// 1. One `Message` contains an empty payload.
    /// 2. `Sink`'s sender is dropped.
    #[tracing::instrument(skip(cx, buf), level = "trace")]
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let remaining = buf.remaining();
        if self.buf.is_empty() {
            trace!("polling the stream");
            let next = ready!(self.frame_rx.poll_recv(cx));
            if next.is_none() || next.as_ref().unwrap().is_empty() {
                // See `tokio::sync::mpsc`#clean-shutdown
                self.frame_rx.close();
                // The stream has been closed, just return 0 bytes read
                return Poll::Ready(Ok(()));
            }
            self.buf = next.unwrap();
        } else {
            // There is some data left in `self.buf`.
            trace!("using the remaining buffer");
        }
        if remaining < self.buf.len() {
            // The buffer is too small. Fill it and advance `self.buf`
            let to_write = self.buf.split_to(remaining);
            buf.put_slice(&to_write);
        } else {
            // The buffer is large enough. Copy the frame into it
            buf.put_slice(&self.buf);
            self.buf.clear();
        }
        Poll::Ready(Ok(()))
    }
}

impl<Sink> AsyncWrite for MuxStream<Sink>
where
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Sync + Unpin + 'static,
{
    #[tracing::instrument(skip(cx, buf), level = "trace")]
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.fin_sent.load(Ordering::Relaxed) || self.stream_removed.load(Ordering::Relaxed) {
            // The stream has been closed. Return an error
            debug!("stream has been closed, returning `BrokenPipe`");
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(self
            .sink
            .poll_send_stream_buf(cx, buf, self.our_port, self.their_port))?;
        Poll::Ready(Ok(buf.len()))
    }

    #[tracing::instrument(skip(cx), level = "trace")]
    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        ready!(self.sink.poll_flush(cx)).map_err(tungstenite_error_to_io_error)?;
        Poll::Ready(Ok(()))
    }

    /// Close the write end of the stream (`shutdown(SHUT_WR)`).
    /// This function will send a `Fin` frame to the remote peer.
    #[tracing::instrument(skip(cx), level = "trace")]
    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.fin_sent.load(Ordering::Relaxed) {
            let message = Frame::Stream(StreamFrame::new_fin(self.our_port, self.their_port))
                .try_into()
                .expect("Frame should be representable as a message (this is a bug)");
            ready!(self.sink.poll_send_message(cx, &message))
                .map_err(tungstenite_error_to_io_error)?;
            self.fin_sent.store(true, Ordering::Relaxed);
        }
        // We don't want to `close()` the sink here!!!
        // This line is allowed to fail, because the sink might have been closed altogether
        ready!(self.sink.poll_flush(cx)).ok();
        Poll::Ready(Ok(()))
    }
}
