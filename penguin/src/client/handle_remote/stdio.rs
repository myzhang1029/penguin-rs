use super::common::AsyncAcceptable;
use futures_util::task::AtomicWaker;
use penguin_mux::Dupe;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{self as tio, AsyncRead, AsyncWrite, ReadBuf};

#[derive(derive_more::Debug)]
pub struct ReusableListener<R, W> {
    in_use: Arc<AtomicBool>,
    end_waker: Arc<AtomicWaker>,
    #[debug(skip)]
    factory: Box<dyn (Fn() -> (R, W)) + Send + Sync>,
}

impl ReusableListener<tio::Stdin, tio::Stdout> {
    pub fn new_stdio() -> Self {
        Self {
            in_use: Arc::new(AtomicBool::new(false)),
            end_waker: Arc::new(AtomicWaker::new()),
            factory: Box::new(|| (tio::stdin(), tio::stdout())),
        }
    }
}

impl<R, W> ReusableListener<R, W> {
    fn poll_accept(&self, cx: &Context<'_>) -> Poll<io::Result<ReusableListenerStream<R, W>>> {
        if self.in_use.swap(true, Ordering::Acquire) {
            self.end_waker.register(cx.waker());
            Poll::Pending
        } else {
            let (reader, writer) = (self.factory)();
            Poll::Ready(Ok(ReusableListenerStream {
                reader,
                writer,
                in_use: self.in_use.dupe(),
                end_waker: self.end_waker.dupe(),
            }))
        }
    }
}

impl<R, W> AsyncAcceptable for ReusableListener<R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    type Stream = ReusableListenerStream<R, W>;
    async fn accept(&self) -> io::Result<(Self::Stream, SocketAddr)> {
        let stdio = poll_fn(|cx| self.poll_accept(cx)).await?;
        Ok((stdio, SocketAddr::from(([0, 0, 0, 0], 0))))
    }
}

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
        ) -> std::task::Poll<$ret> {
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
    impl_fn_by_pin_delegate! { poll_write_vectored, io::Result<usize>, writer, bufs: &[std::io::IoSlice<'_>] }
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn test_reusable_listener() {
        let listener = ReusableListener {
            in_use: Arc::new(AtomicBool::new(false)),
            end_waker: Arc::new(AtomicWaker::new()),
            factory: Box::new(|| duplex(64)),
        };
        let (mut accepted_stream, _) = listener.accept().await.expect("Failed to accept stream");
        let test_cx = Context::from_waker(futures_util::task::noop_waker_ref());
        let res2 = listener.poll_accept(&test_cx);
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
        let (mut accepted_stream2, _) = listener
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
