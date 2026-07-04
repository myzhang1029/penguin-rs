//! [`AsyncAcceptable`] implementation for a stream that can be repeatedly created
//! using a factory function and only one instance can be in use at a time.
//!
//! A particular use case is to wrap [`tokio::io::stdin`] and [`tokio::io::stdout`].
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::async_acceptable::AsyncAcceptable;
use futures_util::task::AtomicWaker;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{self as tio, AsyncRead, AsyncWrite, ReadBuf};

/// A psudo-listener that repeatedly produces an `AsyncRead + AsyncWrite`
/// using a factory function.
#[derive(Debug)]
pub struct ReusableListener<F> {
    in_use: Arc<AtomicBool>,
    end_waker: Arc<AtomicWaker>,
    factory: F,
}

impl<F> ReusableListener<F> {
    /// Create a new `ReusableListener` with the given factory function.
    #[must_use]
    #[inline]
    pub fn new(factory: F) -> Self {
        Self {
            in_use: Arc::new(AtomicBool::new(false)),
            end_waker: Arc::new(AtomicWaker::new()),
            factory,
        }
    }
}

impl ReusableListener<fn() -> (tio::Stdin, tio::Stdout)> {
    /// Produce a `ReusableListener` with [`tokio::io::stdin`] and [`tokio::io::stdout`]
    /// as the underlying streams.
    #[must_use]
    #[inline]
    pub fn new_stdio() -> Self {
        Self::new(|| (tio::stdin(), tio::stdout()))
    }
}

impl<R, W, F> AsyncAcceptable for ReusableListener<F>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    F: Fn() -> (R, W),
{
    type Stream = ReusableListenerStream<R, W>;

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<Self::Stream>> {
        if self.in_use.swap(true, Ordering::Acquire) {
            self.end_waker.register(cx.waker());
            Poll::Pending
        } else {
            let (reader, writer) = (self.factory)();
            Poll::Ready(Ok(ReusableListenerStream {
                reader,
                writer,
                in_use: self.in_use.clone(),
                end_waker: self.end_waker.clone(),
            }))
        }
    }
}

/// A stream produced by calling [`accept`](`crate::AsyncAcceptableExt::accept`) on a [`ReusableListener`].
#[derive(Debug)]
pub struct ReusableListenerStream<R, W> {
    reader: R,
    writer: W,
    in_use: Arc<AtomicBool>,
    end_waker: Arc<AtomicWaker>,
}

macro_rules! impl_fn_by_pin_delegate {
    ($fn:ident, $ret:ty, $field:ident$(,)? $($arg_name:ident: $arg_ty:ty),*) => {
        #[inline]
        fn $fn(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            $($arg_name: $arg_ty),*
        ) -> Poll<$ret> {
            Pin::new(&mut self.$field).$fn(cx, $($arg_name),*)
        }
    };
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for ReusableListenerStream<R, W> {
    impl_fn_by_pin_delegate! { poll_read, io::Result<()>, reader, buf: &mut ReadBuf<'_> }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for ReusableListenerStream<R, W> {
    impl_fn_by_pin_delegate! { poll_write, io::Result<usize>, writer, buf: &[u8] }
    impl_fn_by_pin_delegate! { poll_flush, io::Result<()>, writer }
    impl_fn_by_pin_delegate! { poll_shutdown, io::Result<()>, writer }
    impl_fn_by_pin_delegate! { poll_write_vectored, io::Result<usize>, writer, bufs: &[io::IoSlice<'_>] }
    fn is_write_vectored(&self) -> bool {
        self.writer.is_write_vectored()
    }
}

impl<R, W> Drop for ReusableListenerStream<R, W> {
    fn drop(&mut self) {
        self.in_use.store(false, Ordering::Release);
        self.end_waker.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AsyncAcceptableExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn test_reusable_listener() {
        let listener = ReusableListener {
            in_use: Arc::new(AtomicBool::new(false)),
            end_waker: Arc::new(AtomicWaker::new()),
            factory: || duplex(64),
        };
        let mut accepted_stream = listener.accept().await.expect("Failed to accept stream");
        let mut test_cx = Context::from_waker(futures_util::task::noop_waker_ref());
        let res2 = listener.poll_accept(&mut test_cx);
        assert!(res2.is_pending(), "Listener should be busy");
        accepted_stream
            .write_all(b"Hello")
            .await
            .expect("Failed to write to stream");
        let mut buf = [0u8; 5];
        accepted_stream
            .read_exact(&mut buf)
            .await
            .expect("Failed to read from stream");
        assert_eq!(&buf, b"Hello", "Data read does not match data written");
        drop(accepted_stream);
        let mut accepted_stream2 = listener
            .accept()
            .await
            .expect("Failed to accept stream after previous stream dropped");
        accepted_stream2
            .write_all(b"World")
            .await
            .expect("Failed to write to stream");
        let mut buf2 = [0u8; 5];
        accepted_stream2
            .read_exact(&mut buf2)
            .await
            .expect("Failed to read from stream");
        assert_eq!(&buf2, b"World", "Data read does not match data written");
    }
}
