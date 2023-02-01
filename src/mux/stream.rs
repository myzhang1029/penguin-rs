//! `AsyncRead + AsyncWrite` object returned by `*_new_stream_channel`.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::StreamFrame;
use super::locked_sink::LockedWebSocket;
use super::tungstenite_error_to_io_error;
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// All parameters of a stream channel
#[allow(clippy::module_name_repetitions)]
pub struct MuxStream<S> {
    /// Receive stream frames
    pub(super) frame_rx: mpsc::Receiver<Bytes>,
    /// Our port
    pub(super) our_port: u16,
    /// Port of the other end
    pub(super) their_port: u16,
    /// Forwarding destination. Only used on `Role::Server`
    pub dest_host: Bytes,
    /// Forwarding destination port. Only used on `Role::Server`
    pub dest_port: u16,
    /// Whether writes should succeed.
    /// There are two cases for `false`:
    /// 1. `Fin` has been sent.
    /// 2. The stream has been removed from `inner.streams`
    ///    (or the mux has been dropped).
    pub(super) can_write: Arc<AtomicBool>,
    /// Remaining bytes to be read
    pub(super) buf: Bytes,
    /// See `MultiplexorInner`.
    pub(super) ws: LockedWebSocket<S>,
    /// See `MultiplexorInner`.
    pub(super) dropped_ports_tx: mpsc::UnboundedSender<(u16, u16)>,
}

impl<S> std::fmt::Debug for MuxStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxStream")
            .field("our_port", &self.our_port)
            .field("their_port", &self.their_port)
            .field("dest_host", &self.dest_host)
            .field("dest_port", &self.dest_port)
            .field("can_write", &self.can_write)
            .finish()
    }
}

impl<S> Drop for MuxStream<S> {
    /// Dropping the port should act like `close()` has been called.
    /// Since `drop` is not async, this is handled by the mux task.
    fn drop(&mut self) {
        // Notify the task that this port is no longer in use
        self.dropped_ports_tx
            .send((self.our_port, self.their_port))
            // Maybe the task has already exited, who knows
            .unwrap_or_else(|_| warn!("Failed to notify task of dropped port"));
    }
}

// Proxy the AsyncRead trait to the underlying stream so that users don't access `stream`
impl<S> AsyncRead for MuxStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
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

impl<S> AsyncWrite for MuxStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    #[tracing::instrument(skip(cx, buf), level = "trace")]
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.can_write.load(Ordering::Relaxed) {
            // The stream has been closed. Return an error
            debug!("stream has been closed, returning `BrokenPipe`");
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        // `ready`: nothing happens if return here
        ready!(self.ws.poll_send_with(cx, |_cx| {
            Poll::Ready(
                StreamFrame::new_psh(self.our_port, self.their_port, buf.to_vec().into()).into(),
            )
        }))
        .map_err(tungstenite_error_to_io_error)?;
        trace!("sent a frame");
        Poll::Ready(Ok(buf.len()))
    }

    #[tracing::instrument(skip(cx), level = "trace")]
    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        ready!(self.ws.poll_flush(cx)).map_err(tungstenite_error_to_io_error)?;
        Poll::Ready(Ok(()))
    }

    /// Close the write end of the stream (`shutdown(SHUT_WR)`).
    /// This function will send a `Fin` frame to the remote peer.
    #[tracing::instrument(skip(cx), level = "trace")]
    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // There is no need to send a `Fin` frame if the mux task has already removed the stream
        // because either:
        // 1. `MuxStream` was dropped before `poll_shutdown` is completed and the mux task should
        //    have already sent a `Rst` frame.
        // 2. The entire mux task has been dropped, so we will only get `BrokenPipe` error.
        if self.can_write.load(Ordering::Relaxed) {
            // Can write means that things above have not happened, so we should send a `Fin` frame.
            // `ready`: nothing happens if return here
            ready!(self.ws.poll_send_with(cx, |_cx| {
                Poll::Ready(StreamFrame::new_fin(self.our_port, self.their_port).into())
            }))
            .map_err(tungstenite_error_to_io_error)?;
            self.can_write.store(false, Ordering::Relaxed);
        }
        // `ready`: if poll resumes, `self.fin_sent` indicates where to continue
        // We don't want to `close()` the sink here!!!
        // This line is allowed to fail, because the sink might have been closed altogether
        ready!(self.ws.poll_flush(cx)).ok();
        Poll::Ready(Ok(()))
    }
}
