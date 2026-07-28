//! Like [`tokio::io::BufReader`], but it tries harder to fill the buffer
//! and the memory footprint is slightly smaller for our use case.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
use alloc::boxed::Box;
use core::pin::Pin;
use core::task::{Context, Poll, ready};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(feature = "tokio-io-util")]
use tokio::io::{BufReader, ReadBuf};

const DEFAULT_BUF_CAPACITY: usize = 8192;

pin_project_lite::pin_project! {
    /// Like `BufReader`, but tries to pull a bit more data
    ///
    /// We can technically implement `AsyncBufRead` for `GreedyBufReader`
    /// but it is not necessary since this struct is just an internal detail.
    #[derive(Debug)]
    pub struct GreedyBufReader<R> {
        #[pin]
        inner: R,
        buf: Box<[u8]>,
        pos: usize,
        capacity: usize,
    }
}

impl<R> GreedyBufReader<R> {
    /// Create a new `GreedyBufReader` with the default buffer size wrapping the given reader.
    #[inline]
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self::with_capacity(DEFAULT_BUF_CAPACITY, inner)
    }

    /// Create a new `GreedyBufReader` with the given buffer size wrapping the given reader.
    #[inline]
    #[must_use]
    pub fn with_capacity(capacity: usize, inner: R) -> Self {
        Self {
            inner,
            buf: alloc::vec![0; capacity].into_boxed_slice(),
            pos: 0,
            capacity,
        }
    }
}

impl<R: AsyncRead> GreedyBufReader<R> {
    /// Create a new `GreedyBufReader`, initializing the buffer with the leftover data
    /// from the given [`BufReader`].
    #[cfg(feature = "tokio-io-util")]
    #[inline]
    #[must_use]
    pub fn from_tokio_bufreader(bufreader: BufReader<R>) -> Self {
        Self::from_tokio_bufreader_with_capacity(DEFAULT_BUF_CAPACITY, bufreader)
    }

    /// Create a new `GreedyBufReader`, initializing the buffer with the leftover data
    /// from the given [`BufReader`] and allocating a buffer of the given capacity.
    #[cfg(feature = "tokio-io-util")]
    #[inline]
    #[must_use]
    pub fn from_tokio_bufreader_with_capacity(capacity: usize, bufreader: BufReader<R>) -> Self {
        let mut buf = bufreader.buffer().to_vec();
        let pos = buf.len();
        buf.resize(capacity, 0);
        Self {
            inner: bufreader.into_inner(),
            buf: buf.into_boxed_slice(),
            pos,
            capacity,
        }
    }

    /// Poll for more data to fill the internal buffer.
    ///
    /// # Returns
    /// - `Poll::Ready(Ok(true))` if EOF is reached.
    /// - `Poll::Ready(Ok(false))` if more data may be available, but the internal buffer is full.
    ///   In this case, the user will not necessarily be woken up by us, so the user must call
    ///   this function again after consuming the buffer.
    /// - `Poll::Ready(Err(e))` if an error occurred while reading.
    /// - `Poll::Pending` if the buffer couldn't be fully filled due to the underlying reader not
    ///   having enough data available. In this case, the user will be woken up via the waker by
    ///   the underlying reader's `poll_read`.
    ///
    /// In all of the four cases, the internal buffer may have been filled with new data.
    pub fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut this = self.project();
        let mut readbuf = ReadBuf::new(&mut this.buf);
        let orig_pos = *this.pos;
        readbuf.set_filled(orig_pos);
        let mut last_filled = orig_pos;
        loop {
            if *this.pos >= *this.capacity {
                debug_assert_eq!(*this.pos, *this.capacity);
                // Full buffer
                return Poll::Ready(Ok(false));
            }
            ready!(this.inner.as_mut().poll_read(cx, &mut readbuf)?);
            *this.pos = readbuf.filled().len();
            // Not pending, so we read something or got EOF
            if *this.pos == last_filled {
                // EOF
                return Poll::Ready(Ok(true));
            }
            last_filled = *this.pos;
        }
    }

    /// Get a reference to the internal buffer containing the data read so far.
    pub fn buf(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Consume all the data in the internal buffer, resetting the position to 0.
    ///
    /// It is not possible to consume only part of the buffer, since unlike [`BufReader`],
    /// we do not keep track of how much the user has consumed.
    pub fn consume_all(self: Pin<&mut Self>) {
        *self.project().pos = 0;
    }
}

macro_rules! impl_fn_by_pin_delegate {
    ($fn:ident, $ret:ty$(, $($arg_name:ident: $arg_ty:ty),*)?) => {
        #[inline]
        fn $fn(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            $($($arg_name: $arg_ty),*)?
        ) -> Poll<$ret> {
            self.project().inner.$fn(cx$(, $($arg_name),*)?)
        }
    };
}

impl<RW: AsyncWrite> AsyncWrite for GreedyBufReader<RW> {
    impl_fn_by_pin_delegate! { poll_write, io::Result<usize>, buf: &[u8] }
    impl_fn_by_pin_delegate! { poll_flush, io::Result<()> }
    impl_fn_by_pin_delegate! { poll_shutdown, io::Result<()> }
    impl_fn_by_pin_delegate! { poll_write_vectored, io::Result<usize>, bufs: &[io::IoSlice<'_>] }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::setup_logging;
    use alloc::vec::Vec;

    #[tokio::test]
    #[cfg(not(loom))]
    async fn test_greedy_buf_reader_on_slice() {
        setup_logging();
        test_greedy_buf_reader_on_slice_inner().await;
    }

    #[test]
    #[cfg(loom)]
    fn test_greedy_buf_reader_on_slice_loom() {
        loom::model(|| {
            loom::future::block_on(test_greedy_buf_reader_on_slice_inner());
        });
    }

    async fn test_greedy_buf_reader_on_slice_inner() {
        let data = b"Hello, world!";
        let mut gbr = GreedyBufReader::with_capacity(8, &data[..]);
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        let mut pin = Pin::new(&mut gbr);
        let mut buf = Vec::with_capacity(13);

        let Poll::Ready(Ok(false)) = pin.as_mut().poll_fill_buf(&mut cx) else {
            panic!("Expected to get Poll::Ready(Ok(false))");
        };
        assert_eq!(pin.buf(), b"Hello, w");
        buf.extend_from_slice(pin.buf());
        pin.as_mut().consume_all();
        let Poll::Ready(Ok(true)) = pin.as_mut().poll_fill_buf(&mut cx) else {
            panic!("Expected to get Poll::Ready(Ok(true))");
        };
        assert_eq!(pin.buf(), b"orld!");
        buf.extend_from_slice(pin.buf());
        pin.as_mut().consume_all();
    }

    #[tokio::test]
    #[cfg(feature = "tokio-io-util")]
    #[cfg(not(loom))]
    async fn test_greedy_buf_reader_on_simplex() {
        setup_logging();
        test_greedy_buf_reader_on_simplex_inner().await;
    }

    #[test]
    #[cfg(feature = "tokio-io-util")]
    #[cfg(loom)]
    fn test_greedy_buf_reader_on_simplex_loom() {
        loom::model(|| {
            loom::future::block_on(test_greedy_buf_reader_on_simplex_inner());
        });
    }

    #[cfg(feature = "tokio-io-util")]
    async fn test_greedy_buf_reader_on_simplex_inner() {
        use tokio::io::AsyncWriteExt;
        let (rx, mut tx) = tokio::io::simplex(64);
        let br = BufReader::new(rx);
        let mut gbr = GreedyBufReader::from_tokio_bufreader_with_capacity(8, br);
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        let mut pin = Pin::new(&mut gbr);

        tx.write_all(b"abc").await.unwrap();
        // will get a pending since the buffer didn't get filled up
        let Poll::Pending = pin.as_mut().poll_fill_buf(&mut cx) else {
            panic!("Expected to get Poll::Pending");
        };
        assert_eq!(pin.buf(), b"abc");
        pin.as_mut().consume_all();
        let Poll::Pending = pin.as_mut().poll_fill_buf(&mut cx) else {
            panic!("Expected to get Poll::Pending");
        };
        assert_eq!(pin.buf(), b"");
        tx.write_all(b"defg.hijk.lmno").await.unwrap();
        // will get ready since the buffer got filled up
        let Poll::Ready(Ok(false)) = pin.as_mut().poll_fill_buf(&mut cx) else {
            panic!("Expected to get Poll::Ready(Ok(false))");
        };
        assert_eq!(pin.buf(), b"defg.hij");
        // Try to read without consuming the buffer, which should just return the same buffer
        let Poll::Ready(Ok(false)) = pin.as_mut().poll_fill_buf(&mut cx) else {
            panic!("Expected to get Poll::Ready(Ok(false))");
        };
        assert_eq!(pin.buf(), b"defg.hij");
        pin.as_mut().consume_all();
        // will get a pending since the buffer didn't get filled up
        let Poll::Pending = pin.as_mut().poll_fill_buf(&mut cx) else {
            panic!("Expected to get Poll::Pending");
        };
        assert_eq!(pin.buf(), b"k.lmno");
        tx.write_all(b"pqr").await.unwrap();
        tx.shutdown().await.unwrap();
        drop(tx);
        let Poll::Ready(Ok(false)) = pin.as_mut().poll_fill_buf(&mut cx) else {
            panic!("Expected to get Poll::Ready(Ok(false))");
        };
        assert_eq!(pin.buf(), b"k.lmnopq");
        pin.as_mut().consume_all();
        let Poll::Ready(Ok(true)) = pin.as_mut().poll_fill_buf(&mut cx) else {
            panic!("Expected to get Poll::Ready(Ok(true))");
        };
        assert_eq!(pin.buf(), b"r");
        pin.as_mut().consume_all();
        // tokio's simplex reader can't ever return an error even if we
        // read after EOF, so we can't test that case here
    }
}
