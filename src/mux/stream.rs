//! `AsyncRead + AsyncWrite` object returned by `*_new_stream_channel`.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{Frame, StreamFrame};
use super::inner::MultiplexorInner;
use super::locked_sink::tungstenite_error_to_io_error;
use bytes::{Buf, Bytes};
use futures_util::{Sink as FutureSink, Stream as FutureStream};
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
pub struct MuxStream<Sink, Stream> {
    /// Receive stream frames
    pub stream_rx: mpsc::Receiver<Vec<u8>>,
    /// Our port
    pub our_port: u16,
    /// Port of the other end
    pub their_port: u16,
    /// Forwarding destination. Only used on `Role::Server`
    pub dest_host: Vec<u8>,
    /// Forwarding destination port. Only used on `Role::Server`
    pub dest_port: u16,
    /// Whether `Fin` has been sent
    pub fin_sent: AtomicBool,
    /// Remaining bytes to be read
    pub(super) buf: Option<Bytes>,
    pub(super) inner: Arc<MultiplexorInner<Sink, Stream>>,
}

impl<Sink, Stream> std::fmt::Debug for MuxStream<Sink, Stream> {
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

impl<Sink, Stream> Drop for MuxStream<Sink, Stream> {
    fn drop(&mut self) {
        // Notify the task that this port is no longer in use
        self.inner
            .dropped_ports_tx
            .send(self.our_port)
            // Maybe the task has already exited, who knows
            .unwrap_or_else(|_| warn!("Failed to notify task of dropped port"));
    }
}

// Proxy the AsyncRead trait to the underlying stream so that users don't access `stream`
impl<Sink, Stream> AsyncRead for MuxStream<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Sync + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Sync + Unpin + 'static,
{
    #[tracing::instrument(skip(cx, buf), level = "trace")]
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let remaining = buf.remaining();
        if let Some(mut our_buf) = self.buf.take() {
            // There is some data left in `self.buf`. Copy it into `buf`
            trace!("using the remaining buffer");
            if remaining < our_buf.len() {
                // The buffer is too small. Fill it and advance `self.buf`
                buf.put_slice(&our_buf[..remaining]);
                our_buf.advance(remaining);
                self.buf = Some(our_buf);
            } else {
                // The buffer is large enough. Copy the frame into it
                buf.put_slice(&our_buf);
            }
            return Poll::Ready(Ok(()));
        }
        trace!("polling the stream");
        let next = ready!(self.stream_rx.poll_recv(cx));
        if let Some(frame) = next {
            // We have received a new frame. Copy it into `buf`
            if remaining < frame.len() {
                // The buffer is too small. Fill it and advance `self.buf`
                let mut our_buf = Bytes::from(frame);
                buf.put_slice(&our_buf[..remaining]);
                our_buf.advance(remaining);
                self.buf = Some(our_buf);
            } else {
                // The buffer is large enough. Copy the frame into it
                buf.put_slice(&frame);
            }
            Poll::Ready(Ok(()))
        } else {
            // The stream has been closed, just return 0 bytes read
            trace!("stream has been closed");
            Poll::Ready(Ok(()))
        }
    }
}

impl<Sink, Stream> AsyncWrite for MuxStream<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Sync + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Sync + Unpin + 'static,
{
    #[tracing::instrument(skip(cx, buf), level = "trace")]
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.inner.streams.try_read() {
            Ok(streams) => {
                if streams.contains_key(&self.our_port) {
                    // The stream is open. Send the frame
                    ready!(self.inner.sink.poll_send_stream_buf(
                        cx,
                        buf,
                        self.our_port,
                        self.their_port
                    ))?;
                    Poll::Ready(Ok(buf.len()))
                } else {
                    // The stream has been closed or does not exist. Return an error
                    debug!("stream has been closed, returning `BrokenPipe`");
                    Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
                }
            }
            Err(_) => Poll::Pending,
        }
    }

    #[tracing::instrument(skip(cx), level = "trace")]
    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        ready!(self.inner.sink.poll_flush(cx)).map_err(tungstenite_error_to_io_error)?;
        Poll::Ready(Ok(()))
    }

    #[tracing::instrument(skip(cx), level = "trace")]
    #[inline]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.fin_sent.load(Ordering::Relaxed) {
            let message = Frame::Stream(StreamFrame::new_fin(self.our_port, self.their_port))
                .try_into()
                .expect("Frame should be representable as a message");
            ready!(self.inner.sink.poll_send_message(cx, &message))
                .map_err(tungstenite_error_to_io_error)?;
            self.fin_sent.store(true, Ordering::Relaxed);
        }
        // We don't want to `close()` the sink here!!!
        // This line is allowed to fail, because the sink might have been closed altogether
        ready!(self.inner.sink.poll_flush(cx))
            .map_err(tungstenite_error_to_io_error)
            .ok();
        Poll::Ready(Ok(()))
    }
}
