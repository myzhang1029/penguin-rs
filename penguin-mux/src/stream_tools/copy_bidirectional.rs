use super::greedy_buf_reader::GreedyBufReader;
use crate::frame::Frame;
use crate::stream::MuxStream;
use core::pin::Pin;
use core::task::{Context, Poll, ready};
use futures_util::future::FusedFuture;
use std::io;
use std::io::ErrorKind::BrokenPipe;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite};
use tracing::trace;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadState {
    // We have data
    Transferring(usize),
    // We are done and we are trying to shut down the other side
    ShuttingDown(usize),
    // The other side is EOF'd
    Done(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteState {
    // Peer has more data
    Transferring(usize),
    // Peer is done
    Done(usize),
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    pub struct CopyBidirectional<RW> {
        us: MuxStream,
        #[pin]
        other: GreedyBufReader<RW>,
        read_state: ReadState,
        write_state: WriteState,
    }
}

impl<RW> CopyBidirectional<RW> {
    pub const fn new(us: MuxStream, other: GreedyBufReader<RW>) -> Self {
        Self {
            us,
            other,
            read_state: ReadState::Transferring(0),
            write_state: WriteState::Transferring(0),
        }
    }
}

impl<RW> CopyBidirectional<RW>
where
    RW: AsyncRead + AsyncWrite,
{
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    fn poll_read_us(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut this = self.project();
        match *this.read_state {
            ReadState::Transferring(mut read_amt) => {
                // Loop until we are done or that some of the polls return `Pending`
                loop {
                    trace!("polling us");
                    let new_buf = ready!(Pin::new(&mut *this.us).poll_fill_buf(cx))?;
                    if new_buf.is_empty() {
                        // Our side EOF
                        *this.read_state = ReadState::ShuttingDown(read_amt);
                        ready!(this.other.poll_shutdown(cx))?;
                        // If they return `Poll::Ready(Ok(()))`, we are done
                        *this.read_state = ReadState::Done(read_amt);
                        break Poll::Ready(Ok(read_amt));
                    }
                    // We either still have data or we got some new data. Try to
                    // write it to the other side.
                    let processed = ready!(this.other.as_mut().poll_write(cx, new_buf))?;
                    Pin::new(&mut *this.us).consume(processed);
                    read_amt += processed;
                    *this.read_state = ReadState::Transferring(read_amt);
                    // If this write finished it, the next `poll_fill` will fetch
                    // more frames. Otherwise, the next loop will simply try to write
                    // the rest of the buffer.
                }
            }
            ReadState::ShuttingDown(read_amt) => {
                // We are done reading, but we need to shut down the other side
                // and wait for EOF
                ready!(this.other.poll_shutdown(cx))?;
                *this.read_state = ReadState::Done(read_amt);
                Poll::Ready(Ok(read_amt))
            }
            // We are done reading and the other side is EOF'd
            // We don't need to do anything here
            ReadState::Done(read_amt) => Poll::Ready(Ok(read_amt)),
        }
    }

    #[inline]
    fn poll_write_us(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let this = self.project();
        match *this.write_state {
            WriteState::Transferring(mut written_amt) => {
                // Means that the peer still wants to send us data
                let mut other = this.other;
                loop {
                    trace!("polling other");
                    let r = other.as_mut().poll_fill_buf(cx);
                    // No matter what the return value is, check if we have data to send to the peer
                    let buf = other.buf();
                    // If there is no data and we got `Pending`, we might need to flush away some data to the peer
                    if buf.is_empty() && r.is_pending() {
                        trace!("flushing other");
                        ready!(other.as_mut().poll_flush(cx))?;
                        // Still fine to return `Pending` here because `poll_fill_buf` has our waker
                        return Poll::Pending;
                    }
                    if !buf.is_empty() {
                        // If we return `Pending` here, since we did not consume any data, the next
                        // time the user calls `poll_write_us`, we will call `poll_fill_buf` again
                        // and it will return the same data (or a bit more).
                        // Then, we try to write a frame again when that happens. No data will be lost.
                        ready!(this.us.poll_obtain_write_permission(cx)).ok_or(BrokenPipe)?;
                        let msg = Frame::new_push(this.us.flow_id, buf).into();
                        this.us.tx_msg_tx.send(msg).or(Err(BrokenPipe))?;
                        written_amt += buf.len();
                        *this.write_state = WriteState::Transferring(written_amt);
                        other.as_mut().consume_all();
                    }
                    // Now, if `r` is `Pending`, we return `Pending` because they'll wake us up when more data comes
                    // Finally, in the EOF case, shut us down, in the error case, return the error, and in the
                    // `Ok(false)` case, more data may be available, so loop over
                    match ready!(r) {
                        Ok(true) => {
                            // EOF
                            this.us.do_shutdown();
                            *this.write_state = WriteState::Done(written_amt);
                            break Poll::Ready(Ok(written_amt));
                        }
                        Ok(false) => (),
                        Err(e) => {
                            *this.write_state = WriteState::Done(written_amt);
                            break Poll::Ready(Err(e));
                        }
                    }
                }
            }
            WriteState::Done(written_amt) => Poll::Ready(Ok(written_amt)),
        }
    }
}

impl<RW> Future for CopyBidirectional<RW>
where
    RW: AsyncRead + AsyncWrite,
{
    type Output = io::Result<(usize, usize)>;

    #[tracing::instrument(skip_all, level = "trace", fields(flow_id = %format_args!("{:08x}", self.us.flow_id)))]
    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let r = self.as_mut().poll_read_us(cx)?;
        let w = self.poll_write_us(cx)?;
        Poll::Ready(Ok((ready!(r), ready!(w))))
    }
}

impl<RW> FusedFuture for CopyBidirectional<RW>
where
    RW: AsyncRead + AsyncWrite,
{
    #[inline]
    fn is_terminated(&self) -> bool {
        // the underlying state machine can always be polled again without undesired side effects
        false
    }
}

#[cfg(test)]
#[cfg(feature = "tokio-io-util")]
mod tests {
    use crate::frame::{Frame, Payload, PushPayload};
    use crate::loom::{Arc, AtomicBool, AtomicU32, AtomicWaker};
    use crate::stream::MuxStream;
    use crate::tests::setup_logging;
    use crate::ws::Message::Binary;
    use bytes::Bytes;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use tokio::io::{AsyncRead, ReadBuf};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    const DEFAULT_RWND_THRESHOLD: u32 = 4;

    #[tokio::test]
    #[cfg(not(loom))]
    async fn test_copy_bidirectional_normal() {
        setup_logging();
        test_copy_bidirectional_normal_inner().await;
    }

    #[test]
    #[cfg(loom)]
    fn test_copy_bidirectional_normal_loom() {
        loom::model(|| {
            loom::future::block_on(test_copy_bidirectional_normal_inner());
        })
    }

    async fn test_copy_bidirectional_normal_inner() {
        const TX1: Bytes = Bytes::from_static(b"hello from mux");
        const RX1: Bytes = Bytes::from_static(b"hello from other");
        const TX2: Bytes = Bytes::from_static(b"short");
        const RX2: Bytes = Bytes::from_static(b"hello after half-close");
        const RX3: Bytes = Bytes::from_static(b"stout");
        let (rx_frame_tx, rx_frame_rx) = mpsc::channel(DEFAULT_RWND_THRESHOLD as usize);
        let (tx_msg_tx, mut tx_msg_rx) = mpsc::unbounded_channel();
        let (dropped_flows_tx, _) = mpsc::unbounded_channel();
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
            dropped_flows_tx: dropped_flows_tx.clone(),
            rwnd_threshold: DEFAULT_RWND_THRESHOLD,
        };

        let copy_task = mux_stream.into_copy_bidirectional(other_stream);

        let main_task = async {
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
        };

        // Get final results
        let ((), r) = tokio::join!(main_task, copy_task);
        let (bytes_read, bytes_written) = r.unwrap();
        // TX is copied from MuxStream to other_stream, which is `read_bytes` in `copy_bidirectional`
        assert_eq!(bytes_read, TX1.len() + TX2.len());
        assert_eq!(bytes_written, RX1.len() + RX2.len() + RX3.len());
    }
}
