//! `AsyncRead + AsyncWrite` object returned by `*_new_stream_channel`.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

#[cfg(feature = "std")]
use crate::frame;
use crate::frame::Frame;
use crate::loom::{Arc, AtomicBool, AtomicU32, AtomicWaker, Ordering};
use crate::ws::Message;
#[cfg(feature = "std")]
use alloc::vec::Vec;
use bytes::Bytes;
#[cfg(feature = "std")]
use futures_util::future::FusedFuture;
use core::fmt;
#[cfg(feature = "std")]
use core::pin::Pin;
use core::task::{Context, Poll, ready};
#[cfg(feature = "std")]
use cow_bytes::CowBytes;
#[cfg(feature = "std")]
use std::io::{self, ErrorKind::BrokenPipe};
#[cfg(feature = "std")]
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// All parameters of a stream channel
pub struct MuxStream {
    /// Receive stream frames
    pub(super) rx_frame_rx: mpsc::Receiver<Bytes>,
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
    pub(super) tx_msg_tx: mpsc::UnboundedSender<Message>,
    /// See `MultiplexorInner`.
    pub(super) dropped_ports_tx: mpsc::UnboundedSender<u32>,
    /// Number of `Push` frames between [`Acknowledge`](frame::OpCode::Acknowledge)s:
    /// If too low, `Acknowledge`s will consume too much bandwidth;
    /// If too high, writers may block.
    pub(super) rwnd_threshold: u32,
}

impl fmt::Debug for MuxStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

#[cfg(feature = "std")]
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
        let amt = core::cmp::min(got.len(), buf.remaining());
        buf.put_slice(&got[..amt]);
        self.consume(amt);
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "std")]
impl AsyncWrite for MuxStream {
    /// Write data to the stream. Each invocation of this method will send a
    /// separate frame in a new [`Message`](crate::ws::Message), so it may be
    /// beneficial to wrap it in a [`BufWriter`](tokio::io::BufWriter) where
    /// appropriate.
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.as_ref().poll_write_push(cx, buf)).ok_or(BrokenPipe)?;
        trace!("sent a frame");
        Poll::Ready(Ok(buf.len()))
    }

    #[tracing::instrument(skip(_cx), level = "trace", fields(flow_id = self.flow_id))]
    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // All writes are flushed immediately, so we don't need to do anything
        Poll::Ready(Ok(()))
    }

    /// Close the write end of the stream (`shutdown(SHUT_WR)`).
    /// This function will send a [`Finish`](crate::frame::OpCode::Finish) frame
    /// to the remote peer.
    #[tracing::instrument(skip(_cx), level = "trace", fields(flow_id = self.flow_id))]
    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.do_shutdown();
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut slices = Vec::with_capacity(bufs.len());
        let mut total_len = 0;
        for buf in bufs {
            total_len += buf.len();
            slices.push(CowBytes::Temporary(buf));
        }
        let Some(()) = ready!(self.poll_obtain_write_permission(cx)) else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let frame = Frame::new_push_vectored(self.flow_id, slices).into();
        self.tx_msg_tx
            .send(frame)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Poll::Ready(Ok(total_len))
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }
}

#[cfg(feature = "std")]
impl AsyncBufRead for MuxStream {
    /// Poll for another `Push` frame to fill the internal buffer.
    /// Returns a reference to the internal buffer on success.
    /// See [`AsyncBufRead::poll_fill_buf`].
    #[inline]
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        if self.buf.is_empty() {
            trace!("polling the stream");
            if ready!(self.as_mut().poll_for_push(cx)) == 0 {
                return Poll::Ready(Ok(&[]));
            }
        } else {
            trace!("using the remaining buffer");
        }

        Poll::Ready(Ok(&self.get_mut().buf))
    }

    #[inline]
    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        use bytes::Buf;
        self.buf.advance(amt);
    }
}

impl MuxStream {
    /// Poll for another `Push` frame to fill the internal buffer.
    ///
    /// Returns the number of bytes read into the internal buffer.
    /// If `0` is returned, the stream has been closed and the user should interpret this as an EOF.
    ///
    /// # Panics
    /// This function will panic if the internal buffer still has data.
    #[tracing::instrument(skip_all, level = "trace", fields(flow_id = self.flow_id))]
    #[inline]
    pub fn poll_for_push(&mut self, cx: &mut Context<'_>) -> Poll<usize> {
        let Some(next) = ready!(self.rx_frame_rx.poll_recv(cx)) else {
            trace!("stream has been closed");
            // See `tokio::sync::mpsc`#clean-shutdown
            self.rx_frame_rx.close();
            // There should be no code path sending more frames after an EOF
            // If this assertion fails, some code path is sending frames after EOF
            // and thus causing loss of data.
            // However, this is not an inconsistent state so we should not
            // panic a production setup.
            debug_assert!(self.rx_frame_rx.try_recv().is_err());
            return Poll::Ready(0);
        };
        // Putting no data into the buffer is EOF, and other code should
        // already ensure that such frames are filtered out.
        debug_assert!(!next.is_empty());
        assert!(
            self.buf.is_empty(),
            "`poll_fill_buf_inner` should not be called unless the buffer is empty"
        );
        self.buf = next;
        self.increment_psh_recvd_since();
        Poll::Ready(self.buf.len())
    }

    /// Get a reference to the internal buffer.
    #[inline]
    pub fn buf(&self) -> Bytes {
        self.buf.clone() // cheap
    }

    /// Write a `Push` frame to the stream.
    #[tracing::instrument(skip_all, level = "trace", fields(flow_id = self.flow_id))]
    #[inline]
    pub fn poll_write_push(&self, cx: &Context<'_>, buf: &[u8]) -> Poll<Option<()>> {
        let Some(()) = ready!(self.poll_obtain_write_permission(cx)) else {
            return Poll::Ready(None);
        };
        let frame = Frame::new_push(self.flow_id, buf).into();
        Poll::Ready(self.tx_msg_tx.send(frame).ok())
    }

    /// Increment the number of `Push` frames received since the last `Acknowledge`
    /// and send an `Acknowledge` frame if the threshold is reached.
    #[tracing::instrument(skip_all, level = "trace", fields(count = self.psh_recvd_since + 1))]
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
            self.tx_msg_tx
                .send(Frame::new_acknowledge(self.flow_id, new).into())
                .ok();
            // If the previous line fails, the task has exited.
            // In this case, we don't care about the `Acknowledge` frame and the
            // user will discover the error when they try to write or read
            // to EOF.
        }
    }

    /// Attempt to obtain permission to send a [`Push`](crate::frame::OpCode::Push) frame.
    ///
    /// If we need an `Acknowledge` frame to continue, the task will be woken up
    /// once the `Acknowledge` frame is received.
    ///
    /// Returns `None` if the stream has been closed, and the user should interpret
    /// this as a `BrokenPipe` error.
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    pub fn poll_obtain_write_permission(&self, cx: &Context<'_>) -> Poll<Option<()>> {
        // Atomic ordering: if the operations around this line are reordered,
        // the sent frame will be `Rst`ed by the remote peer, which is harmless.
        // Both `close_port` and `shutdown` in `inner.rs` set this flag with
        // `Relaxed` ordering because they are not releasing any access, but
        // instead acting based on the WebSocket or the stream's states.
        if self.finish_sent.load(Ordering::Relaxed) {
            // The stream has been closed. Return an error
            debug!("stream has been closed, returning `BrokenPipe`");
            return Poll::Ready(None);
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
        Poll::Ready(Some(()))
    }

    /// Send a [`Finish`](crate::frame::OpCode::Finish) frame to the remote peer
    /// and disallow further writes.
    ///
    /// This method is named `do_shutdown` to avoid conflict with `AsyncWriteExt::shutdown`.
    ///
    /// Returns `None` if the task has exited, in which case the stream is already closed
    /// and it is safe to ignore the error.
    #[inline]
    pub fn do_shutdown(&self) -> Option<()> {
        // There is no need to send a `Finish` frame if the mux task has already removed the stream
        // because either:
        // 1. `MuxStream` was dropped before `poll_shutdown` is completed and the mux task should
        //    have already sent a `Reset` frame.
        // 2. The entire mux task has been dropped, so we will only get `BrokenPipe` error.
        // Atomic ordering: see `inner.rs` -> `close_port_local`.
        if self.finish_sent.swap(true, Ordering::AcqRel) {
            return Some(());
        }
        self.tx_msg_tx
            .send(Frame::new_finish(self.flow_id).into())
            .ok()?;
        Some(())
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
    #[cfg(all(feature = "std", feature = "tokio-io-util"))]
    pub fn into_copy_bidirectional<RW>(
        self,
        other: RW,
    ) -> CopyBidirectional<tokio::io::BufReader<RW>>
    where
        RW: AsyncRead + AsyncWrite + Unpin,
    {
        let other_bufreader = tokio::io::BufReader::new(other);
        self.into_copy_bidirectional_with_buf(other_bufreader)
    }

    /// See [`into_copy_bidirectional`](Self::into_copy_bidirectional). This version allows you to
    /// provide your own read buffer for the other side.
    #[inline]
    #[cfg(feature = "std")]
    pub const fn into_copy_bidirectional_with_buf<BRW>(self, other: BRW) -> CopyBidirectional<BRW>
    where
        BRW: AsyncBufRead + AsyncWrite + Unpin,
    {
        CopyBidirectional {
            us: self,
            other,
            read_state: ReadState::Transferring(0),
            write_state: WriteState::Transferring(0),
        }
    }
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadState {
    // We have data
    Transferring(usize),
    // We are done and we are trying to shut down the other side
    ShuttingDown(usize),
    // The other side is EOF'd
    Done(usize),
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteState {
    // Peer has more data
    Transferring(usize),
    // Peer is done
    Done(usize),
}

#[cfg(feature = "std")]
#[derive(Debug)]
pub struct CopyBidirectional<RW> {
    us: MuxStream,
    other: RW,
    read_state: ReadState,
    write_state: WriteState,
}

#[cfg(feature = "std")]
impl<RW> CopyBidirectional<RW>
where
    RW: AsyncBufRead + AsyncWrite + Unpin,
{
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    fn poll_read_us(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        match self.read_state {
            ReadState::Transferring(mut read_amt) => {
                // Loop until we are done or that some of the polls return `Pending`
                loop {
                    trace!("polling us");
                    let new_buf = ready!(Pin::new(&mut self.us).poll_fill_buf(cx))?;
                    if new_buf.is_empty() {
                        // Our side EOF
                        self.read_state = ReadState::ShuttingDown(read_amt);
                        ready!(Pin::new(&mut self.other).poll_shutdown(cx))?;
                        // If they return `Poll::Ready(Ok(()))`, we are done
                        self.read_state = ReadState::Done(read_amt);
                        break Poll::Ready(Ok(read_amt));
                    }
                    // We either still have data or we got some new data. Try to
                    // write it to the other side.
                    let processed = ready!(Pin::new(&mut self.other).poll_write(cx, new_buf))?;
                    Pin::new(&mut self.us).consume(processed);
                    read_amt += processed;
                    self.read_state = ReadState::Transferring(read_amt);
                    // If this write finished it, the next `poll_fill` will fetch
                    // more frames. Otherwise, the next loop will simply try to write
                    // the rest of the buffer.
                }
            }
            ReadState::ShuttingDown(read_amt) => {
                // We are done reading, but we need to shut down the other side
                // and wait for EOF
                ready!(Pin::new(&mut self.other).poll_shutdown(cx))?;
                self.read_state = ReadState::Done(read_amt);
                Poll::Ready(Ok(read_amt))
            }
            // We are done reading and the other side is EOF'd
            // We don't need to do anything here
            ReadState::Done(read_amt) => Poll::Ready(Ok(read_amt)),
        }
    }

    #[inline]
    fn poll_write_us(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        match self.write_state {
            WriteState::Transferring(mut written_amt) => {
                // Means that the peer still wants to send us data
                let mut other = Pin::new(&mut self.other);
                // Initial poll
                trace!("polling other");
                let Poll::Ready(res) = other.as_mut().poll_fill_buf(cx) else {
                    // Even the first poll returns `Pending`. Might want to flush away some data
                    trace!("flushing other");
                    ready!(other.as_mut().poll_flush(cx))?;
                    // Still fine to return `Pending` here because `poll_fill_buf` has our waker
                    return Poll::Pending;
                };
                let new_buf = res?;
                if new_buf.is_empty() {
                    // The other side is EOF'd
                    self.us.do_shutdown();
                    self.write_state = WriteState::Done(written_amt);
                    return Poll::Ready(Ok(written_amt));
                }
                // If we return `Pending` here, since we did not consume any data, the next
                // `poll_fill_buf` will return the same data and we will try to send it again.
                ready!(self.us.poll_obtain_write_permission(cx)).ok_or(BrokenPipe)?;
                let mut msg_payload =
                    Vec::from(Frame::new_push(self.us.flow_id, new_buf));
                let processed = new_buf.len();
                let mut cumulated_len = processed;
                other.as_mut().consume(processed);
                // Check if we can squeeze a bit more data from the other side to send in the same frame
                let mut should_shutdown = false;
                while let Poll::Ready(Ok(new_buf)) = other.as_mut().poll_fill_buf(cx) {
                    if new_buf.is_empty() {
                        // The other side is EOF'd, send what we have and then shutdown
                        should_shutdown = true;
                        break;
                    }
                    let processed = new_buf.len();
                    frame::append_push_data(&mut msg_payload, new_buf);
                    cumulated_len += processed;
                    other.as_mut().consume(processed);
                }
                self.us
                    .tx_msg_tx
                    .send(Message::Binary(msg_payload.into()))
                    .or(Err(BrokenPipe))?;
                written_amt += cumulated_len;
                if should_shutdown {
                    self.us.do_shutdown();
                    self.write_state = WriteState::Done(written_amt);
                    return Poll::Ready(Ok(written_amt));
                }
                // Else: we exited the loop because `poll_fill_buf` returned `Pending`
                // We return `Pending` and `poll_fill_buf` has our waker
                self.write_state = WriteState::Transferring(written_amt);
                Poll::Pending
            }
            WriteState::Done(written_amt) => Poll::Ready(Ok(written_amt)),
        }
    }
}

#[cfg(feature = "std")]
impl<RW> Future for CopyBidirectional<RW>
where
    RW: AsyncBufRead + AsyncWrite + Unpin,
{
    type Output = io::Result<(usize, usize)>;

    #[tracing::instrument(skip_all, level = "trace", fields(flow_id = self.us.flow_id))]
    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let r = self.poll_read_us(cx);
        let w = self.poll_write_us(cx);
        Poll::Ready(Ok((ready!(r)?, ready!(w)?)))
    }
}

#[cfg(feature = "std")]
impl<RW> FusedFuture for CopyBidirectional<RW>
where
    RW: AsyncBufRead + AsyncWrite + Unpin,
{
    #[inline]
    fn is_terminated(&self) -> bool {
        // the underlying state machine can always be polled again without undesired side effects
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Payload, PushPayload};
    use crate::tests::setup_logging;
    use crate::ws::Message::Binary;
    use alloc::vec;
    use core::pin::{Pin, pin};
    #[cfg(feature = "tokio-io-util")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

    const DEFAULT_RWND_THRESHOLD: u32 = 4;

    #[tokio::test]
    #[cfg(not(loom))]
    #[cfg(feature = "std")]
    async fn test_mux_stream_read() {
        setup_logging();
        test_mux_stream_read_inner().await;
    }

    #[test]
    #[cfg(loom)]
    #[cfg(feature = "std")]
    fn test_mux_stream_read_loom() {
        loom::model(|| {
            loom::future::block_on(test_mux_stream_read_inner());
        })
    }

    #[cfg(feature = "std")]
    async fn test_mux_stream_read_inner() {
        let (rx_frame_tx, rx_frame_rx) = mpsc::channel(10);
        let (tx_msg_tx, mut tx_msg_rx) = mpsc::unbounded_channel();
        let (dropped_ports_tx, _) = mpsc::unbounded_channel();
        let stream = MuxStream {
            rx_frame_rx,
            flow_id: 1,
            dest_host: Bytes::new(),
            dest_port: 8080,
            finish_sent: Arc::new(AtomicBool::new(false)),
            psh_send_remaining: Arc::new(AtomicU32::new(2)),
            psh_recvd_since: 0,
            writer_waker: Arc::new(AtomicWaker::new()),
            tx_msg_tx: tx_msg_tx,
            buf: Bytes::new(),
            dropped_ports_tx,
            rwnd_threshold: 2,
        };
        let mut stream = pin!(stream);
        let mut buf = vec![0u8; 5];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
        let waker = futures_util::task::noop_waker();
        {
            let mut cx = Context::from_waker(&waker);
            let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
            assert!(matches!(rs, Poll::Pending));
        }

        rx_frame_tx.send(Bytes::from("hello")).await.unwrap();
        {
            let mut cx = Context::from_waker(&waker);
            let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
            assert!(matches!(rs, Poll::Ready(Ok(()))));
            assert_eq!(read_buf.filled().len(), 5);
            assert_eq!(read_buf.filled(), b"hello");
            read_buf.clear();
        }

        {
            let mut cx = Context::from_waker(&waker);
            let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
            assert!(matches!(rs, Poll::Pending));
        }

        rx_frame_tx.send(Bytes::from("world")).await.unwrap();

        {
            let mut cx = Context::from_waker(&waker);
            let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
            assert!(matches!(rs, Poll::Ready(Ok(()))));
            assert_eq!(read_buf.filled().len(), 5);
            assert_eq!(read_buf.filled(), b"world");
            read_buf.clear();
        }

        // There should be an `Acknowledge` frame waiting for us now
        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame = Frame::try_from(msg).unwrap();
        assert_eq!(frame.id, 1);
        if let crate::frame::Payload::Acknowledge(ack) = frame.payload {
            assert_eq!(ack, 2);
        } else {
            panic!("Expected an `Acknowledge` frame");
        }

        // Try EOF
        drop(rx_frame_tx);
        {
            let mut cx = Context::from_waker(&waker);
            let rs = stream.as_mut().poll_read(&mut cx, &mut read_buf);
            assert!(matches!(rs, Poll::Ready(Ok(()))));
            assert_eq!(read_buf.filled().len(), 0);
        }
    }

    #[tokio::test]
    #[cfg(not(loom))]
    #[cfg(feature = "std")]
    async fn test_mux_stream_write() {
        setup_logging();
        test_mux_stream_write_inner().await;
    }

    #[test]
    #[cfg(loom)]
    #[cfg(feature = "std")]
    fn test_mux_stream_write_loom() {
        loom::model(|| {
            loom::future::block_on(test_mux_stream_write_inner());
        })
    }

    #[cfg(feature = "std")]
    async fn test_mux_stream_write_inner() {
        let (_, rx_frame_rx) = mpsc::channel(DEFAULT_RWND_THRESHOLD as usize);
        let (tx_msg_tx, mut tx_msg_rx) = mpsc::unbounded_channel();
        let (dropped_ports_tx, _) = mpsc::unbounded_channel();
        let stream = MuxStream {
            rx_frame_rx,
            flow_id: 1,
            dest_host: Bytes::new(),
            dest_port: 8080,
            finish_sent: Arc::new(AtomicBool::new(false)),
            psh_send_remaining: Arc::new(AtomicU32::new(2)),
            psh_recvd_since: 0,
            writer_waker: Arc::new(AtomicWaker::new()),
            tx_msg_tx,
            buf: Bytes::new(),
            dropped_ports_tx,
            rwnd_threshold: DEFAULT_RWND_THRESHOLD,
        };
        let mut stream = pin!(stream);
        let waker = futures_util::task::noop_waker();
        {
            let mut cx = Context::from_waker(&waker);
            let rs = stream.as_mut().poll_write(&mut cx, b"hello");
            assert!(matches!(rs, Poll::Ready(Ok(5))));
            let rs = stream.as_mut().poll_write(&mut cx, b"world");
            assert!(matches!(rs, Poll::Ready(Ok(5))));
        }

        // Check the frame sent
        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame1 = Frame::try_from(msg).unwrap();
        assert_eq!(frame1.id, 1);
        if let Payload::Push(PushPayload::Single(push)) = frame1.payload {
            assert_eq!(&push.as_ref(), b"hello");
        } else {
            panic!("Expected a `Push(Single)` frame");
        }
        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame2 = Frame::try_from(msg).unwrap();
        assert_eq!(frame2.id, 1);
        if let Payload::Push(PushPayload::Single(push)) = frame2.payload {
            assert_eq!(&push.as_ref(), b"world");
        } else {
            panic!("Expected a `Push(Single)` frame");
        }

        // Try to write again
        {
            let mut cx = Context::from_waker(&waker);
            let rs = stream.as_mut().poll_write(&mut cx, b"maybe");
            assert!(matches!(rs, Poll::Pending));
        }

        // Simulate `Acknowledge`
        stream.psh_send_remaining.fetch_add(1, Ordering::Release);

        {
            let mut cx = Context::from_waker(&waker);
            let rs = stream.as_mut().poll_write(&mut cx, b"maybe");
            assert!(matches!(rs, Poll::Ready(Ok(5))));
        }

        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame4 = Frame::try_from(msg).unwrap();
        assert_eq!(frame4.id, 1);
        if let Payload::Push(PushPayload::Single(push)) = frame4.payload {
            assert_eq!(&push.as_ref(), b"maybe");
        } else {
            panic!("Expected a `Push(Single)` frame");
        }
    }

    #[tokio::test]
    #[cfg(not(loom))]
    #[cfg(feature = "std")]
    async fn test_mux_stream_write_vectored() {
        setup_logging();
        test_mux_stream_write_vectored_inner().await;
    }

    #[test]
    #[cfg(loom)]
    #[cfg(feature = "std")]
    fn test_mux_stream_write_vectored_loom() {
        loom::model(|| {
            loom::future::block_on(test_mux_stream_write_vectored_inner());
        })
    }

    #[cfg(feature = "std")]
    async fn test_mux_stream_write_vectored_inner() {
        let (_, rx_frame_rx) = mpsc::channel(DEFAULT_RWND_THRESHOLD as usize);
        let (tx_msg_tx, mut tx_msg_rx) = mpsc::unbounded_channel();
        let (dropped_ports_tx, _) = mpsc::unbounded_channel();
        let stream = MuxStream {
            rx_frame_rx,
            flow_id: 1,
            dest_host: Bytes::new(),
            dest_port: 8080,
            finish_sent: Arc::new(AtomicBool::new(false)),
            psh_send_remaining: Arc::new(AtomicU32::new(2)),
            psh_recvd_since: 0,
            writer_waker: Arc::new(AtomicWaker::new()),
            tx_msg_tx,
            buf: Bytes::new(),
            dropped_ports_tx,
            rwnd_threshold: DEFAULT_RWND_THRESHOLD,
        };
        let mut stream = pin!(stream);
        let waker = futures_util::task::noop_waker();
        {
            let mut cx = Context::from_waker(&waker);
            let bufs = [io::IoSlice::new(b"hello"), io::IoSlice::new(b"world")];
            let rs = stream.as_mut().poll_write_vectored(&mut cx, &bufs);
            assert!(matches!(rs, Poll::Ready(Ok(10))));
        }

        // Check the frame sent
        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame1 = Frame::try_from(msg).unwrap();
        assert_eq!(frame1.id, 1);
        if let Payload::Push(PushPayload::Single(push)) = frame1.payload {
            assert_eq!(&push.as_ref(), b"helloworld");
        } else {
            panic!("Expected a `Push(Single)` frame");
        }
    }

    #[tokio::test]
    #[cfg(not(loom))]
    #[cfg(all(feature = "tokio-io-util", feature = "std"))]
    async fn test_copy_bidirectional_normal() {
        const TX1: Bytes = Bytes::from_static(b"hello from mux");
        const RX1: Bytes = Bytes::from_static(b"hello from other");
        const TX2: Bytes = Bytes::from_static(b"short");
        const RX2: Bytes = Bytes::from_static(b"hello after half-close");
        const RX3: Bytes = Bytes::from_static(b"stout");
        setup_logging();
        let (rx_frame_tx, rx_frame_rx) = mpsc::channel(DEFAULT_RWND_THRESHOLD as usize);
        let (tx_msg_tx, mut tx_msg_rx) = mpsc::unbounded_channel();
        let (dropped_ports_tx, _) = mpsc::unbounded_channel();
        let (other_stream, mut check_side) = tokio::io::duplex(1024);

        let mux_stream = MuxStream {
            rx_frame_rx,
            flow_id: 1,
            dest_host: Bytes::new(),
            dest_port: 8080,
            finish_sent: Arc::new(AtomicBool::new(false)),
            psh_send_remaining: Arc::new(AtomicU32::new(10)), // Allow more frames for this test
            psh_recvd_since: 0,
            writer_waker: Arc::new(AtomicWaker::new()),
            tx_msg_tx: tx_msg_tx.clone(),
            buf: Bytes::new(),
            dropped_ports_tx: dropped_ports_tx.clone(),
            rwnd_threshold: DEFAULT_RWND_THRESHOLD,
        };

        let copy_task = tokio::spawn(mux_stream.into_copy_bidirectional(other_stream));

        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 14];
        let mut rbuf = ReadBuf::new(&mut buf);
        let rs = Pin::new(&mut check_side).poll_read(&mut cx, &mut rbuf);
        assert!(matches!(rs, Poll::Pending));

        // Send data to the MuxStream
        rx_frame_tx.send(TX1.clone()).await.unwrap();
        let size = check_side.read(&mut buf).await.unwrap();
        // Should be ready
        assert_eq!(size, TX1.len());
        assert_eq!(&buf[..size], TX1);

        // Write to the AsyncWrite side
        check_side.write_all(&RX1).await.unwrap();
        // This side has buffering
        check_side.flush().await.unwrap();

        // Verify data was sent to the remote peer
        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame = Frame::try_from(msg).unwrap();
        assert_eq!(frame.id, 1);
        if let Payload::Push(PushPayload::Single(push)) = frame.payload {
            assert_eq!(push.as_ref(), RX1);
        } else {
            panic!("Expected a `Push(Single)` frame");
        }

        // Send some partial data before we go away to check that the
        // data isn't lost in the process
        rx_frame_tx.send(TX2.clone()).await.unwrap();
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
        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame = Frame::try_from(msg).unwrap();
        assert_eq!(frame.id, 1);
        if let Payload::Push(PushPayload::Single(push)) = frame.payload {
            assert_eq!(push.as_ref(), RX2);
        } else {
            panic!("Expected a `Push(Single)` frame");
        }
        // Again short data before we go away
        check_side.write_all(&RX3).await.unwrap();
        check_side.shutdown().await.unwrap();
        // Check that the data is not lost
        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame = Frame::try_from(msg).unwrap();
        assert_eq!(frame.id, 1);
        if let Payload::Push(PushPayload::Single(push)) = frame.payload {
            assert_eq!(push.as_ref(), RX3);
        } else {
            panic!("Expected a `Push(Single)` frame");
        }

        // Get final results
        let (bytes_read, bytes_written) = copy_task.await.unwrap().unwrap();
        // TX is copied from MuxStream to other_stream, which is `read_bytes` in `copy_bidirectional`
        assert_eq!(bytes_read, TX1.len() + TX2.len());
        assert_eq!(bytes_written, RX1.len() + RX2.len() + RX3.len());
    }

    #[tokio::test]
    #[cfg(not(loom))]
    #[cfg(all(feature = "tokio-io-util", feature = "std"))]
    async fn test_flow_control() {
        const TEST_ACK_THRESHOLD: usize = 5;
        const TEST_ACK_THRESHOLD_U32: u32 = 5;
        assert_eq!(TEST_ACK_THRESHOLD, TEST_ACK_THRESHOLD_U32 as usize);
        setup_logging();
        let (rx_frame_tx, rx_frame_rx) = mpsc::channel(TEST_ACK_THRESHOLD);
        let (tx_msg_tx, mut tx_msg_rx) = mpsc::unbounded_channel();
        let (dropped_ports_tx, _) = mpsc::unbounded_channel();
        let (other_stream, mut check_side) = tokio::io::duplex(1024);
        let mut mux_stream = MuxStream {
            rx_frame_rx,
            flow_id: 1,
            dest_host: Bytes::new(),
            dest_port: 8080,
            finish_sent: Arc::new(AtomicBool::new(false)),
            psh_send_remaining: Arc::new(AtomicU32::new(10)), // Allow more frames for this test
            psh_recvd_since: 0,
            writer_waker: Arc::new(AtomicWaker::new()),
            tx_msg_tx: tx_msg_tx.clone(),
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
        tx_msg_rx.try_recv().unwrap_err();
        // First test with just `AsyncRead`
        let mut buf = [0u8; 5 * TEST_ACK_THRESHOLD];
        let n = mux_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(n, 5 * TEST_ACK_THRESHOLD);
        assert_eq!(&buf[..n], b"hello".repeat(TEST_ACK_THRESHOLD).as_slice());
        // Check that the `Acknowledge` frame has arrived
        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame = Frame::try_from(msg).unwrap();
        assert_eq!(frame.id, 1);
        if let Payload::Acknowledge(ack) = frame.payload {
            assert_eq!(ack, TEST_ACK_THRESHOLD_U32);
        } else {
            panic!("Expected an `Acknowledge` frame");
        }
        // Now test with `copy_bidirectional`
        let task = tokio::spawn(mux_stream.into_copy_bidirectional(other_stream));
        for i in 0..2 * TEST_ACK_THRESHOLD {
            debug!("sending frame {i}");
            rx_frame_tx
                .send(Bytes::from_static(b"hello"))
                .await
                .unwrap();
        }
        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame = Frame::try_from(msg).unwrap();
        assert_eq!(frame.id, 1);
        if let Payload::Acknowledge(ack) = frame.payload {
            assert_eq!(ack, TEST_ACK_THRESHOLD_U32);
        } else {
            panic!("Expected an `Acknowledge` frame");
        }
        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame = Frame::try_from(msg).unwrap();
        assert_eq!(frame.id, 1);
        if let Payload::Acknowledge(ack) = frame.payload {
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
        // Write in the other side
        for i in 0..TEST_ACK_THRESHOLD {
            debug!("sending data chunk {i}");
            check_side.write_all(b"hello").await.unwrap();
            check_side.flush().await.unwrap();
        }
        check_side.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        // Check that the data has been sent
        let mut buf = [0u8; 5 * TEST_ACK_THRESHOLD];
        while let Some(Binary(msg)) = tx_msg_rx.recv().await {
            let frame = Frame::try_from(msg).unwrap();
            assert_eq!(frame.id, 1);
            match frame.payload {
                Payload::Push(PushPayload::Single(push)) => {
                    buf.copy_from_slice(push.as_ref());
                }
                Payload::Finish => {
                    break;
                }
                _ => panic!("Expected a `Push(Single)` frame"),
            }
        }
        assert_eq!(&buf[..], b"hello".repeat(TEST_ACK_THRESHOLD).as_slice());
    }

    #[tokio::test]
    #[cfg(not(loom))]
    #[cfg(feature = "std")]
    async fn test_mux_stream_shutdown() {
        test_mux_stream_shutdown_inner().await;
    }

    #[test]
    #[cfg(loom)]
    #[cfg(feature = "std")]
    fn test_mux_stream_shutdown_loom() {
        loom::model(|| {
            loom::future::block_on(test_mux_stream_shutdown_inner());
        })
    }

    #[cfg(feature = "std")]
    async fn test_mux_stream_shutdown_inner() {
        setup_logging();
        let (_, rx_frame_rx) = mpsc::channel(10);
        let (tx_msg_tx, mut tx_msg_rx) = mpsc::unbounded_channel();
        let (dropped_ports_tx, mut dropped_ports_rx) = mpsc::unbounded_channel();
        let mut stream = MuxStream {
            rx_frame_rx,
            flow_id: 15,
            dest_host: Bytes::new(),
            dest_port: 8080,
            finish_sent: Arc::new(AtomicBool::new(false)),
            psh_send_remaining: Arc::new(AtomicU32::new(2)),
            psh_recvd_since: 0,
            writer_waker: Arc::new(AtomicWaker::new()),
            tx_msg_tx,
            buf: Bytes::new(),
            dropped_ports_tx,
            rwnd_threshold: 2,
        };
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        let rs = Pin::new(&mut stream).as_mut().poll_shutdown(&mut cx);
        assert!(matches!(rs, Poll::Ready(Ok(()))));
        // Check the frame sent
        let Binary(msg) = tx_msg_rx.recv().await.unwrap() else {
            panic!("Expected a binary message");
        };
        let frame = Frame::try_from(msg).unwrap();
        assert_eq!(frame.id, 15);
        assert_eq!(frame.opcode(), crate::frame::OpCode::Finish);

        drop(stream);
        // Check that `Drop` sends its information
        let dropped_port = dropped_ports_rx.recv().await.unwrap();
        assert_eq!(dropped_port, 15);
    }
}
