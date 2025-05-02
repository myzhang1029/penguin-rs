//! `AsyncRead + AsyncWrite` object returned by `*_new_stream_channel`.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::frame::{FinalizedFrame, Frame};
use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use std::io;
use std::io::ErrorKind::BrokenPipe;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader};
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
    /// Whether writes should not succeed
    pub(super) finish_sent: Arc<AtomicBool>,
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
            .field("flow_id", &format_args!("{:08x}", self.flow_id))
            .field("dest_host", &self.dest_host)
            .field("dest_port", &self.dest_port)
            .field("finish_sent", &self.finish_sent)
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
    /// Close the stream by instructing the mux task to send a [`Reset`](crate::frame::OpCode::Reset) frame if
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
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let got = ready!(self.as_mut().poll_fill_buf(cx))?;
        let amt = std::cmp::min(got.len(), buf.remaining());
        buf.put_slice(&got[..amt]);
        self.consume(amt);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MuxStream {
    /// Write data to the stream. Each invocation of this method will send a
    /// separate frame in a new [`Message`](crate::ws::Message), so it may be
    /// beneficial to wrap it in a [`BufWriter`](tokio::io::BufWriter) where
    /// appropriate.
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_obtain_write_permission(cx))?;
        let frame = Frame::new_push(self.flow_id, buf).finalize();
        self.frame_tx.send(frame).map_err(|_| BrokenPipe)?;
        trace!("sent a frame");
        Poll::Ready(Ok(buf.len()))
    }

    #[tracing::instrument(skip(_cx), level = "trace")]
    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // All writes are flushed immediately, so we don't need to do anything
        Poll::Ready(Ok(()))
    }

    /// Close the write end of the stream (`shutdown(SHUT_WR)`).
    /// This function will send a [`Finish`](crate::frame::OpCode::Finish) frame
    /// to the remote peer.
    #[tracing::instrument(skip(_cx), level = "trace")]
    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.shutdown_inner())
    }
}

impl AsyncBufRead for MuxStream {
    /// Poll for another `Push` frame to fill the internal buffer.
    /// Returns a reference to the internal buffer on success.
    /// See [`AsyncBufRead::poll_fill_buf`].
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        if self.buf.is_empty() {
            trace!("polling the stream");
            let Some(next) = ready!(self.frame_rx.poll_recv(cx)) else {
                trace!("stream has been closed");
                // See `tokio::sync::mpsc`#clean-shutdown
                self.frame_rx.close();
                // There should be no code path sending more frames after an EOF
                // If this assertion fails, some code path is sending frames after EOF
                // and thus causing loss of data.
                // However, this is not an inconsistent state so we should not
                // panic a production setup.
                debug_assert!(self.frame_rx.try_recv().is_err());
                return Poll::Ready(Ok(&[]));
            };
            // Putting no data into the buffer is EOF, and other code should
            // already ensure that such frames are filtered out.
            debug_assert!(!next.is_empty());
            self.buf = next;
            self.increment_psh_recvd_since();
        } else {
            // There is some data left in `self.buf`.
            trace!("using the remaining buffer");
        }

        Poll::Ready(Ok(&self.get_mut().buf))
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.buf.advance(amt);
    }
}

impl MuxStream {
    /// Increment the number of `Push` frames received since the last `Acknowledge`
    /// and send an `Acknowledge` frame if the threshold is reached.
    #[tracing::instrument(skip_all, level = "trace", fields(flow_id = self.flow_id, count = self.psh_recvd_since + 1))]
    #[inline]
    fn increment_psh_recvd_since(&mut self) {
        trace!("received a frame");
        let new = self.psh_recvd_since + 1;
        self.psh_recvd_since = new;
        if new >= self.rwnd_threshold {
            // Reset the counter
            self.psh_recvd_since = 0;
            // Send an `Acknowledge` frame
            trace!("sending `Acknowledge` of {new} frames");
            self.frame_tx
                .send(Frame::new_acknowledge(self.flow_id, new).finalize())
                .ok();
            // If the previous line fails, the task has exited.
            // In this case, we don't care about the `Acknowledge` frame and the
            // user will discover the error when they try to write or read
            // to EOF.
        }
    }

    /// Attempt to obtain permission to send a [`Push`](crate::frame::OpCode::Push) frame.
    /// If we need an `Acknowledge` frame to continue, the task will be woken up
    /// once the `Acknowledge` frame is received.
    #[tracing::instrument(skip_all, level = "trace", fields(flow_id = self.flow_id))]
    #[inline]
    fn poll_obtain_write_permission(&self, cx: &Context<'_>) -> Poll<io::Result<()>> {
        // Atomic ordering: if the operations around this line are reordered,
        // the sent frame will be `Rst`ed by the remote peer, which is harmless.
        // Both `close_port` and `shutdown` in `inner.rs` set this flag with
        // `Relaxed` ordering because they are not releasing any access, but
        // instead acting based on the WebSocket or the stream's states.
        if self.finish_sent.load(Ordering::Relaxed) {
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
                break;
            }
            trace!("congestion window race condition, retrying");
        }
        // We have successfully decremented the congestion window
        Poll::Ready(Ok(()))
    }

    /// Send a [`Finish`](crate::frame::OpCode::Finish) frame to the remote peer
    /// and disallow further writes.
    #[inline]
    fn shutdown_inner(&self) -> io::Result<()> {
        // There is no need to send a `Finish` frame if the mux task has already removed the stream
        // because either:
        // 1. `MuxStream` was dropped before `poll_shutdown` is completed and the mux task should
        //    have already sent a `Reset` frame.
        // 2. The entire mux task has been dropped, so we will only get `BrokenPipe` error.
        // Atomic ordering: see `inner.rs` -> `close_port_local`.
        if self.finish_sent.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.frame_tx
            .send(Frame::new_finish(self.flow_id).finalize())
            .map_err(|_| BrokenPipe)?;
        Ok(())
    }

    /// A specialized version of [`tokio::io::copy_bidirectional`] that
    /// works better on a `MuxStream` because of the lack of an extra copy.
    ///
    /// The returned future will resolve to `io::Result<(u64, u64)>` where
    /// the first value is the number of bytes read from `self` and
    /// the second value is the number of bytes written to `self`.
    ///
    /// # Errors
    /// Returns the underlying error if any of the IO operations fail. When
    /// this happens, some data from the other side might be lost.
    ///
    /// # Cancel Safety
    /// This function is not cancel safe. Cancelling the future might cause
    /// data loss.
    #[inline]
    pub fn into_copy_bidirectional<RW>(self, other: RW) -> CopyBidirectional<BufReader<RW>>
    where
        RW: AsyncRead + AsyncWrite + Unpin,
    {
        let other_bufreader = BufReader::new(other);
        CopyBidirectional {
            us: self,
            other: other_bufreader,
            read_bytes: 0,
            wrote_bytes: 0,
            read_state: ReadState::Transferring,
            write_state: WriteState::Transferring,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadState {
    // We have data
    Transferring,
    // We are done and we are trying to shut down the other side
    ShuttingDown,
    // The other side is EOF'd
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteState {
    // Peer has more data
    Transferring,
    // Peer is done
    Done,
}

#[derive(Debug)]
pub struct CopyBidirectional<RW> {
    us: MuxStream,
    other: RW,
    read_bytes: u64,
    wrote_bytes: u64,
    read_state: ReadState,
    write_state: WriteState,
}

impl<RW> CopyBidirectional<RW>
where
    RW: AsyncBufRead + AsyncWrite + Unpin,
{
    fn poll_read_us(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        match self.read_state {
            ReadState::Transferring => {
                // Loop until we are done or that some of the polls return `Pending`
                loop {
                    trace!("poll_read_us loop");
                    let new_buf = ready!(Pin::new(&mut self.us).poll_fill_buf(cx))?;
                    if new_buf.is_empty() {
                        // Our side EOF
                        self.read_state = ReadState::ShuttingDown;
                        ready!(Pin::new(&mut self.other).poll_shutdown(cx))?;
                        // If they return `Poll::Ready(Ok(()))`, we are done
                        self.read_state = ReadState::Done;
                        break Poll::Ready(Ok(self.read_bytes));
                    }
                    // We either still have data or we got some new data. Try to
                    // write it to the other side.
                    let result = ready!(Pin::new(&mut self.other).poll_write(cx, new_buf))?;
                    Pin::new(&mut self.us).consume(result);
                    self.read_bytes += result as u64;
                    // If this write finished it, the next `poll_fill` will fetch
                    // more frames. Otherwise, the next loop will simply try to write
                    // the rest of the buffer.
                }
            }
            ReadState::ShuttingDown => {
                // We are done reading, but we need to shut down the other side
                // and wait for EOF
                ready!(Pin::new(&mut self.other).poll_shutdown(cx))?;
                self.read_state = ReadState::Done;
                Poll::Ready(Ok(self.read_bytes))
            }
            ReadState::Done => {
                // We are done reading and the other side is EOF'd
                // We don't need to do anything here
                Poll::Ready(Ok(self.read_bytes))
            }
        }
    }

    fn poll_write_us(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        match &mut self.write_state {
            WriteState::Transferring => {
                // Means that the peer still wants to send us data
                loop {
                    trace!("poll_write_us loop");
                    let new_buf = ready!(Pin::new(&mut self.other).poll_fill_buf(cx))?;
                    if new_buf.is_empty() {
                        // The other side is EOF'd
                        self.us.shutdown_inner()?;
                        self.write_state = WriteState::Done;
                        break Poll::Ready(Ok(self.wrote_bytes));
                    }
                    ready!(self.us.poll_obtain_write_permission(cx))?;
                    let frame = Frame::new_push(self.us.flow_id, new_buf).finalize();
                    self.us.frame_tx.send(frame).map_err(|_| BrokenPipe)?;
                    let size = new_buf.len();
                    Pin::new(&mut self.other).consume(size);
                    self.wrote_bytes += size as u64;
                }
            }
            WriteState::Done => {
                // We are done writing and the other side is EOF'd
                // We don't need to do anything here
                Poll::Ready(Ok(self.wrote_bytes))
            }
        }
    }
}

impl<RW> Future for CopyBidirectional<RW>
where
    RW: AsyncBufRead + AsyncWrite + Unpin,
{
    type Output = io::Result<(u64, u64)>;

    #[tracing::instrument(skip_all, level = "trace")]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let r = self.poll_read_us(cx);
        let w = self.poll_write_us(cx);
        Poll::Ready(Ok((ready!(r)?, ready!(w)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dupe, tests::setup_logging};
    use std::pin::pin;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

    const DEFAULT_RWND_THRESHOLD: u32 = 4;

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
            finish_sent: Arc::new(AtomicBool::new(false)),
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
        assert_eq!(read_buf.filled(), b"hello");
        read_buf.clear();

        let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
        assert!(matches!(rs, Poll::Pending));

        rx_frame_tx.send(Bytes::from("world")).await.unwrap();
        let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
        assert!(matches!(rs, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 5);
        assert_eq!(read_buf.filled(), b"world");
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
        drop(rx_frame_tx);
        let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
        assert!(matches!(rs, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 0);
    }

    #[tokio::test]
    async fn test_mux_stream_write() {
        setup_logging();
        let (_, rx_frame_rx) = mpsc::channel(DEFAULT_RWND_THRESHOLD as usize);
        let (tx_frame_tx, mut tx_frame_rx) = mpsc::unbounded_channel();
        let (dropped_ports_tx, _) = mpsc::unbounded_channel();
        let stream = MuxStream {
            frame_rx: rx_frame_rx,
            flow_id: 1,
            dest_host: Bytes::new(),
            dest_port: 8080,
            finish_sent: Arc::new(AtomicBool::new(false)),
            psh_send_remaining: Arc::new(AtomicU32::new(2)),
            psh_recvd_since: 0,
            writer_waker: Arc::new(AtomicWaker::new()),
            frame_tx: tx_frame_tx,
            buf: Bytes::new(),
            dropped_ports_tx,
            rwnd_threshold: DEFAULT_RWND_THRESHOLD,
        };
        let mut stream = pin!(stream);
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        let rs = stream.as_mut().poll_write(&mut cx, b"hello");
        assert!(matches!(rs, Poll::Ready(Ok(5))));
        let rs = stream.as_mut().poll_write(&mut cx, b"world");
        assert!(matches!(rs, Poll::Ready(Ok(5))));

        // Check the frame sent
        let frame1 = tx_frame_rx.recv().await.unwrap();
        assert_eq!(frame1.opcode().unwrap(), crate::frame::OpCode::Push);
        let frame1 = Frame::try_from(frame1).unwrap();
        assert_eq!(frame1.id, 1);
        if let crate::frame::Payload::Push(push) = frame1.payload {
            assert_eq!(&push.as_ref(), b"hello");
        } else {
            panic!("Expected a `Push` frame");
        }
        let frame2 = tx_frame_rx.recv().await.unwrap();
        assert_eq!(frame2.opcode().unwrap(), crate::frame::OpCode::Push);
        let frame2 = Frame::try_from(frame2).unwrap();
        assert_eq!(frame2.id, 1);
        if let crate::frame::Payload::Push(push) = frame2.payload {
            assert_eq!(&push.as_ref(), b"world");
        } else {
            panic!("Expected a `Push` frame");
        }

        // Try to write again
        let rs = stream.as_mut().poll_write(&mut cx, b"maybe");
        assert!(matches!(rs, Poll::Pending));

        // Simulate `Acknowledge`
        stream.psh_send_remaining.fetch_add(1, Ordering::Release);

        let rs = stream.as_mut().poll_write(&mut cx, b"maybe");
        assert!(matches!(rs, Poll::Ready(Ok(5))));

        let frame4 = tx_frame_rx.recv().await.unwrap();
        assert_eq!(frame4.opcode().unwrap(), crate::frame::OpCode::Push);
        let frame4 = Frame::try_from(frame4).unwrap();
        assert_eq!(frame4.id, 1);
        if let crate::frame::Payload::Push(push) = frame4.payload {
            assert_eq!(&push.as_ref(), b"maybe");
        } else {
            panic!("Expected a `Push` frame");
        }
    }

    #[tokio::test]
    async fn test_copy_bidirectional_normal() {
        const TX1: Bytes = Bytes::from_static(b"hello from mux");
        const RX1: Bytes = Bytes::from_static(b"hello from other");
        const TX2: Bytes = Bytes::from_static(b"short");
        const RX2: Bytes = Bytes::from_static(b"hello after half-close");
        const RX3: Bytes = Bytes::from_static(b"stout");
        setup_logging();
        let (rx_frame_tx, rx_frame_rx) = mpsc::channel(DEFAULT_RWND_THRESHOLD as usize);
        let (tx_frame_tx, mut tx_frame_rx) = mpsc::unbounded_channel();
        let (dropped_ports_tx, _) = mpsc::unbounded_channel();
        let (mut other_stream, mut check_side) = tokio::io::duplex(1024);

        let mux_stream = MuxStream {
            frame_rx: rx_frame_rx,
            flow_id: 1,
            dest_host: Bytes::new(),
            dest_port: 8080,
            finish_sent: Arc::new(AtomicBool::new(false)),
            psh_send_remaining: Arc::new(AtomicU32::new(10)), // Allow more frames for this test
            psh_recvd_since: 0,
            writer_waker: Arc::new(AtomicWaker::new()),
            frame_tx: tx_frame_tx.clone(),
            buf: Bytes::new(),
            dropped_ports_tx: dropped_ports_tx.clone(),
            rwnd_threshold: DEFAULT_RWND_THRESHOLD,
        };

        let copy_task =
            tokio::spawn(
                async move { mux_stream.into_copy_bidirectional(&mut other_stream).await },
            );

        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 14];
        let mut rbuf = ReadBuf::new(&mut buf);
        let rs = Pin::new(&mut check_side).poll_read(&mut cx, &mut rbuf);
        assert!(matches!(rs, Poll::Pending));

        // Send data to the MuxStream
        rx_frame_tx.send(TX1.dupe()).await.unwrap();
        let size = check_side.read(&mut buf).await.unwrap();
        // Should be ready
        assert_eq!(size, TX1.len());
        assert_eq!(&buf[..size], TX1);

        // Write to the AsyncWrite side
        check_side.write_all(&RX1).await.unwrap();
        // This side has buffering
        check_side.flush().await.unwrap();

        // Verify data was sent to the remote peer
        let frame = tx_frame_rx.recv().await.unwrap();
        let frame = Frame::try_from(frame).unwrap();
        assert_eq!(frame.id, 1);
        if let crate::frame::Payload::Push(push) = frame.payload {
            assert_eq!(push.as_ref(), RX1);
        } else {
            panic!("Expected a `Push` frame");
        }

        // Send some partial data before we go away to check that the
        // data isn't lost in the process
        rx_frame_tx.send(TX2.dupe()).await.unwrap();
        drop(rx_frame_tx);
        // Check that the data is not lost
        let read = check_side.read(&mut buf).await.unwrap();
        assert_eq!(read, TX2.len());
        assert_eq!(&buf[..read], TX2);
        // Make sure this side is getting EOF
        let m = check_side.read(&mut buf).await.unwrap();
        assert_eq!(m, 0);
        // Make sure that only this side is closed and not the other side
        check_side.write_all(&RX2).await.unwrap();
        check_side.flush().await.unwrap();
        // Check that this side is still open
        let frame = tx_frame_rx.recv().await.unwrap();
        let frame = Frame::try_from(frame).unwrap();
        assert_eq!(frame.id, 1);
        if let crate::frame::Payload::Push(push) = frame.payload {
            assert_eq!(push.as_ref(), RX2);
        } else {
            panic!("Expected a `Push` frame");
        }
        // Again short data before we go away
        check_side.write_all(&RX3).await.unwrap();
        check_side.shutdown().await.unwrap();
        // Check that the data is not lost
        let frame = tx_frame_rx.recv().await.unwrap();
        let frame = Frame::try_from(frame).unwrap();
        assert_eq!(frame.id, 1);
        if let crate::frame::Payload::Push(push) = frame.payload {
            assert_eq!(push.as_ref(), RX3);
        } else {
            panic!("Expected a `Push` frame");
        }

        // Get final results
        let (bytes_read, bytes_written) = copy_task.await.unwrap().unwrap();
        // TX is copied from MuxStream to other_stream, which is `read_bytes` in `copy_bidirectional`
        assert_eq!(bytes_read, (TX1.len() + TX2.len()) as u64);
        assert_eq!(bytes_written, (RX1.len() + RX2.len() + RX3.len()) as u64);
    }

    #[tokio::test]
    async fn test_flow_control() {
        const TEST_ACK_THRESHOLD: usize = 5;
        const TEST_ACK_THRESHOLD_U32: u32 = 5;
        assert_eq!(TEST_ACK_THRESHOLD, TEST_ACK_THRESHOLD_U32 as usize);
        setup_logging();
        let (rx_frame_tx, rx_frame_rx) = mpsc::channel(TEST_ACK_THRESHOLD);
        let (tx_frame_tx, mut tx_frame_rx) = mpsc::unbounded_channel();
        let (dropped_ports_tx, _) = mpsc::unbounded_channel();
        let (mut other_stream, mut check_side) = tokio::io::duplex(1024);
        let mut mux_stream = MuxStream {
            frame_rx: rx_frame_rx,
            flow_id: 1,
            dest_host: Bytes::new(),
            dest_port: 8080,
            finish_sent: Arc::new(AtomicBool::new(false)),
            psh_send_remaining: Arc::new(AtomicU32::new(10)), // Allow more frames for this test
            psh_recvd_since: 0,
            writer_waker: Arc::new(AtomicWaker::new()),
            frame_tx: tx_frame_tx.clone(),
            buf: Bytes::new(),
            dropped_ports_tx: dropped_ports_tx.clone(),
            rwnd_threshold: TEST_ACK_THRESHOLD_U32,
        };
        // First clog the congestion window
        for i in 0..TEST_ACK_THRESHOLD {
            debug!("sending frame {i}");
            rx_frame_tx
                .send(Bytes::from_static(b"hello"))
                .await
                .unwrap();
        }
        // Test that the `Acknowledge` frame has not arrived yet
        // The point is to confirm that the reader processed the frames
        // so if we get `Acknowledge` even before we started reading, then
        // it is pointless.
        tx_frame_rx.try_recv().unwrap_err();
        // First test with just `AsyncRead`
        let mut buf = [0u8; 5 * TEST_ACK_THRESHOLD];
        let n = mux_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(n, 5 * TEST_ACK_THRESHOLD);
        assert_eq!(&buf[..n], b"hello".repeat(TEST_ACK_THRESHOLD).as_slice());
        // Check that the `Acknowledge` frame has arrived
        let frame = tx_frame_rx.recv().await.unwrap();
        let frame = Frame::try_from(frame).unwrap();
        assert_eq!(frame.id, 1);
        if let crate::frame::Payload::Acknowledge(ack) = frame.payload {
            assert_eq!(ack, TEST_ACK_THRESHOLD_U32);
        } else {
            panic!("Expected an `Acknowledge` frame");
        }
        // Now test with `copy_bidirectional`
        let task = tokio::spawn(async move {
            mux_stream
                .into_copy_bidirectional(&mut other_stream)
                .await
                .unwrap()
        });
        for i in 0..2 * TEST_ACK_THRESHOLD {
            debug!("sending frame {i}");
            rx_frame_tx
                .send(Bytes::from_static(b"hello"))
                .await
                .unwrap();
        }
        let frame = tx_frame_rx.recv().await.unwrap();
        let frame = Frame::try_from(frame).unwrap();
        assert_eq!(frame.id, 1);
        if let crate::frame::Payload::Acknowledge(ack) = frame.payload {
            assert_eq!(ack, TEST_ACK_THRESHOLD_U32);
        } else {
            panic!("Expected an `Acknowledge` frame");
        }
        let frame = tx_frame_rx.recv().await.unwrap();
        let frame = Frame::try_from(frame).unwrap();
        assert_eq!(frame.id, 1);
        if let crate::frame::Payload::Acknowledge(ack) = frame.payload {
            assert_eq!(ack, TEST_ACK_THRESHOLD_U32);
        } else {
            panic!("Expected an `Acknowledge` frame");
        }
        // Check for data
        let mut buf = [0u8; 5 * 2 * TEST_ACK_THRESHOLD];
        let n = check_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(n, 5 * 2 * TEST_ACK_THRESHOLD);
        assert_eq!(
            &buf[..n],
            b"hello".repeat(2 * TEST_ACK_THRESHOLD).as_slice()
        );
        drop(rx_frame_tx);
        check_side.shutdown().await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn test_mux_stream_shutdown() {
        setup_logging();
        let (_, rx_frame_rx) = mpsc::channel(10);
        let (tx_frame_tx, mut tx_frame_rx) = mpsc::unbounded_channel();
        let (dropped_ports_tx, mut dropped_ports_rx) = mpsc::unbounded_channel();
        let mut stream = MuxStream {
            frame_rx: rx_frame_rx,
            flow_id: 15,
            dest_host: Bytes::new(),
            dest_port: 8080,
            finish_sent: Arc::new(AtomicBool::new(false)),
            psh_send_remaining: Arc::new(AtomicU32::new(2)),
            psh_recvd_since: 0,
            writer_waker: Arc::new(AtomicWaker::new()),
            frame_tx: tx_frame_tx,
            buf: Bytes::new(),
            dropped_ports_tx,
            rwnd_threshold: 2,
        };
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        let rs = Pin::new(&mut stream).as_mut().poll_shutdown(&mut cx);
        assert!(matches!(rs, Poll::Ready(Ok(()))));
        // Check the frame sent
        let frame = tx_frame_rx.recv().await.unwrap();
        assert_eq!(frame.opcode().unwrap(), crate::frame::OpCode::Finish);
        let frame = Frame::try_from(frame).unwrap();
        assert_eq!(frame.id, 15);

        drop(stream);
        // Check that `Drop` sends its information
        let dropped_port = dropped_ports_rx.recv().await.unwrap();
        assert_eq!(dropped_port, 15);
    }
}
