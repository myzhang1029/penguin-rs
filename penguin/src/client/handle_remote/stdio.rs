use super::common::AsyncAcceptable;
use futures_util::task::AtomicWaker;
use penguin_mux::Dupe;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use tokio::io::{self as tio, AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Default)]
pub struct StdioListener {
    in_use: Arc<AtomicBool>,
    end_waker: Arc<AtomicWaker>,
}

impl StdioListener {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StdioListener {
    fn poll_accept(&self, cx: &mut std::task::Context<'_>) -> Poll<io::Result<Stdio>> {
        if self.in_use.swap(true, Ordering::Acquire) {
            self.end_waker.register(cx.waker());
            Poll::Pending
        } else {
            Poll::Ready(Ok(Stdio {
                reader: tio::stdin(),
                writer: tio::stdout(),
                in_use: self.in_use.dupe(),
                end_waker: self.end_waker.dupe(),
            }))
        }
    }
}

impl AsyncAcceptable for StdioListener {
    type Stream = Stdio;
    async fn accept(&self) -> io::Result<(Self::Stream, SocketAddr)> {
        let stdio = poll_fn(|cx| self.poll_accept(cx)).await?;
        Ok((stdio, SocketAddr::from(([0, 0, 0, 0], 0))))
    }
}

#[derive(Debug)]
pub struct Stdio {
    reader: tio::Stdin,
    writer: tio::Stdout,
    in_use: Arc<AtomicBool>,
    end_waker: Arc<AtomicWaker>,
}

macro_rules! impl_fn_by_pin_delegate {
    ($fn:ident, $ret:ty, $field:ident$(,)? $($arg_name:ident: $arg_ty:ty),*) => {
        #[inline]
        fn $fn(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            $($arg_name: $arg_ty),*
        ) -> std::task::Poll<$ret> {
            Pin::new(&mut self.$field).$fn(cx, $($arg_name),*)
        }
    };
}

impl AsyncRead for Stdio {
    impl_fn_by_pin_delegate! { poll_read, io::Result<()>, reader, buf: &mut ReadBuf<'_> }
}

impl AsyncWrite for Stdio {
    impl_fn_by_pin_delegate! { poll_write, io::Result<usize>, writer, buf: &[u8] }
    impl_fn_by_pin_delegate! { poll_flush, io::Result<()>, writer }
    impl_fn_by_pin_delegate! { poll_shutdown, io::Result<()>, writer }
}

impl Drop for Stdio {
    fn drop(&mut self) {
        self.in_use.store(false, Ordering::Release);
        self.end_waker.wake();
    }
}
