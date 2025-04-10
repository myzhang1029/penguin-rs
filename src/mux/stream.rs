//! `AsyncRead + AsyncWrite` object returned by `*_new_stream_channel`.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::frame::{FinalizedFrame, Frame};
use bytes::Bytes;
use futures_util::task::AtomicWaker;
use std::io;
use std::io::ErrorKind::BrokenPipe;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// All parameters of a stream channel
pub struct MuxStream {
    /// Receive stream frames
    pub(super) frame_rx: mpsc::Receiver<Bytes>,
    /// Flow ID
    pub(super) flow_id: u32,
    /// Forwarding destination
    pub dest_host: Bytes,
    /// Forwarding destination port
    pub dest_port: u16,
    /// Whether writes should succeed
    pub(super) can_write: Arc<AtomicBool>,
    /// Number of frames we can still send before we need to wait for an `Acknowledge`
    pub(super) psh_send_remaining: Arc<AtomicU32>,
    /// Number of `Push` frames received after sending the previous `Acknowledge` frame
    /// `rwnd - psh_recvd_since` is approximately the peer's `psh_send_remaining`
    pub(super) psh_recvd_since: u32,
    /// Waker to wake up the task that sends frames
    pub(super) writer_waker: Arc<AtomicWaker>,
    /// Remaining bytes to be read
    pub(super) buf: Bytes,
    /// See `MultiplexorInner`.
    pub(super) frame_tx: mpsc::UnboundedSender<FinalizedFrame>,
    /// See `MultiplexorInner`.
    pub(super) dropped_ports_tx: mpsc::UnboundedSender<u32>,
    /// Number of `Push` frames between [`Acknowledge`](frame::OpCode::Acknowledge)s:
    /// If too low, `Acknowledge`s will consume too much bandwidth;
    /// If too high, writers may block.
    pub(super) rwnd_threshold: u32,
}

impl std::fmt::Debug for MuxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxStream")
            .field("flow_id", &self.flow_id)
            .field("dest_host", &self.dest_host)
            .field("dest_port", &self.dest_port)
            .field("can_write", &self.can_write)
            .field("psh_send_remaining", &self.psh_send_remaining)
            .field("psh_recvd_since", &self.psh_recvd_since)
            .field("rwnd_threshold", &self.rwnd_threshold)
            .field("buf.len", &self.buf.len())
            .finish_non_exhaustive()
    }
}

impl Drop for MuxStream {
    // Dropping the port should act like `close()` has been called.
    // Since `drop` is not async, this is handled by the mux task.
    /// Close the stream by instructing the mux task to send a [`Reset`](frame::OpCode::Reset) frame if
    /// the stream is still open. The associated port will be freed for reuse.
    fn drop(&mut self) {
        // Notify the task that this port is no longer in use
        self.dropped_ports_tx
            .send(self.flow_id)
            // Maybe the task has already exited, who knows
            .ok();
    }
}

impl AsyncRead for MuxStream {
    /// Read data from the stream.
    /// There are two cases where this function gives EOF:
    /// 1. One `Frame` contains an empty payload.
    /// 2. `Sink`'s sender is dropped.
    #[tracing::instrument(skip(cx, buf), level = "trace")]
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
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
            let new = self.psh_recvd_since + 1;
            self.psh_recvd_since = new;
            debug!("received a frame, psh_recvd_since: {new}");
            if new >= self.rwnd_threshold {
                // Reset the counter
                self.psh_recvd_since = 0;
                // Send an `Acknowledge` frame
                debug!("sending `Acknowledge` of {new} frames");
                self.frame_tx
                    .send(Frame::new_acknowledge(self.flow_id, new).finalize())
                    .ok();
                // If the previous line fails, the task has exited.
                // In this case, we don't care about the `Acknowledge` frame and the
                // user will discover the error when they try to write or read
                // to EOF.
            }
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

impl AsyncWrite for MuxStream {
    /// Write data to the stream. Each invocation of this method will send a
    /// separate frame in a new [`Message`](crate::ws::Message), so it may be
    /// beneficial to wrap it in a [`BufWriter`](tokio::io::BufWriter) where
    /// appropriate.
    #[tracing::instrument(skip(cx, buf), level = "trace")]
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Atomic ordering: if the operations around this line are reordered,
        // the sent frame will be `Rst`ed by the remote peer, which is harmless.
        // Both `close_port` and `shutdown` in `inner.rs` set this flag with
        // `Relaxed` ordering because they are not releasing any access, but
        // instead acting based on the WebSocket or the stream's states.
        if !self.can_write.load(Ordering::Relaxed) {
            // The stream has been closed. Return an error
            debug!("stream has been closed, returning `BrokenPipe`");
            return Poll::Ready(Err(BrokenPipe.into()));
        }
        loop {
            // Atomic ordering: we don't really have a critical section here,
            // so `Relaxed` should be enough.
            let original = self.psh_send_remaining.load(Ordering::Acquire);
            trace!("congestion window: {original}");
            if original == 0 {
                // We have reached the congestion window limit. Wait for an `Acknowledge`
                debug!("waiting for `Acknowledge`");
                // Make sure queued frames are flushed
                self.frame_tx
                    .send(FinalizedFrame::FLUSH)
                    .map_err(|_| BrokenPipe)?;
                self.writer_waker.register(cx.waker());
                // Since all writes start with `poll_flush`, we don't need to
                // flush here. There is actually no way to `poll_flush` without
                // magic.
                return Poll::Pending;
            }
            let new = original - 1;
            // Atomic ordering: see the comment above
            if self
                .psh_send_remaining
                .compare_exchange_weak(original, new, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // We have successfully decremented the congestion window
                break;
            }
            trace!("congestion window race condition, retrying");
        }
        let frame = Frame::new_push(self.flow_id, buf).finalize();
        self.frame_tx.send(frame).map_err(|_| BrokenPipe)?;
        trace!("sent a frame");
        Poll::Ready(Ok(buf.len()))
    }

    #[tracing::instrument(skip(_cx), level = "trace")]
    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.frame_tx
            .send(FinalizedFrame::FLUSH)
            .map_err(|_| BrokenPipe)?;
        Poll::Ready(Ok(()))
    }

    /// Close the write end of the stream (`shutdown(SHUT_WR)`).
    /// This function will send a [`Finish`](crate::frame::OpCode::Finish) frame
    /// to the remote peer.
    #[tracing::instrument(skip(_cx), level = "trace")]
    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // There is no need to send a `Finish` frame if the mux task has already removed the stream
        // because either:
        // 1. `MuxStream` was dropped before `poll_shutdown` is completed and the mux task should
        //    have already sent a `Reset` frame.
        // 2. The entire mux task has been dropped, so we will only get `BrokenPipe` error.
        // Atomic ordering: see `inner.rs` -> `close_port`.
        // As a summary, duplicate `Finish`/`Reset` frames are harmless.
        if self.can_write.load(Ordering::Relaxed) {
            self.frame_tx
                .send(Frame::new_finish(self.flow_id).finalize())
                .map_err(|_| BrokenPipe)?;
            // Atomic ordering: see `inner.rs` -> `shutdown` and `close_port`.
            self.can_write.store(false, Ordering::Relaxed);
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::setup_logging;
    use std::pin::pin;

    #[tokio::test]
    async fn test_mux_stream_read() {
        setup_logging();
        let (rx_frame_tx, rx_frame_rx) = mpsc::channel(10);
        let (tx_frame_tx, mut tx_frame_rx) = mpsc::unbounded_channel();
        let (dropped_ports_tx, _) = mpsc::unbounded_channel();
        let stream = MuxStream {
            frame_rx: rx_frame_rx,
            flow_id: 1,
            dest_host: Bytes::new(),
            dest_port: 8080,
            can_write: Arc::new(AtomicBool::new(true)),
            psh_send_remaining: Arc::new(AtomicU32::new(2)),
            psh_recvd_since: 0,
            writer_waker: Arc::new(AtomicWaker::new()),
            frame_tx: tx_frame_tx,
            buf: Bytes::new(),
            dropped_ports_tx,
            rwnd_threshold: 2,
        };
        let mut stream = pin!(stream);
        let mut buf = vec![0u8; 5];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
        assert!(matches!(rs, Poll::Pending));

        rx_frame_tx.send(Bytes::from("hello")).await.unwrap();
        let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
        assert!(matches!(rs, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 5);
        assert_eq!(&read_buf.filled()[..], b"hello");
        read_buf.clear();

        let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
        assert!(matches!(rs, Poll::Pending));

        rx_frame_tx.send(Bytes::from("world")).await.unwrap();
        let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
        assert!(matches!(rs, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 5);
        assert_eq!(&read_buf.filled()[..], b"world");
        read_buf.clear();

        // There should be an `Acknowledge` frame waiting for us now
        let frame = tx_frame_rx.recv().await.unwrap();
        assert_eq!(frame.opcode().unwrap(), crate::frame::OpCode::Acknowledge);
        let frame = Frame::try_from(frame).unwrap();
        assert_eq!(frame.id, 1);
        if let crate::frame::Payload::Acknowledge(ack) = frame.payload {
            assert_eq!(ack, 2);
        } else {
            panic!("Expected an `Acknowledge` frame");
        }

        // Try EOF
        rx_frame_tx.send(Bytes::new()).await.unwrap();
        let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
        assert!(matches!(rs, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 0);
        assert!(rx_frame_tx.is_closed());
    }
}
