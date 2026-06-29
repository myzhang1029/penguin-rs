//! Abstraction `AsyncAcceptable` over tokio listeners with an async `accept()` method
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite};

/// A Listener that can accept connections asynchronously.
pub trait AsyncAcceptable {
    /// The type of stream that will be returned by `accept()`
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Poll accept a connection asynchronously.
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<Self::Stream>>;

    /// Poll accept a connection asynchronously, returning the stream and the peer address.
    fn poll_accept_with_sockaddr(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(Self::Stream, SocketAddr)>> {
        let stream = ready!(self.poll_accept(cx))?;
        let peer = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        Poll::Ready(Ok((stream, peer)))
    }
}

#[cfg(feature = "tokio-net")]
impl AsyncAcceptable for tokio::net::TcpListener {
    type Stream = tokio::net::TcpStream;

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<Self::Stream>> {
        let stream = ready!(self.poll_accept(cx))?.0;
        Poll::Ready(Ok(stream))
    }

    fn poll_accept_with_sockaddr(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(Self::Stream, SocketAddr)>> {
        self.poll_accept(cx)
    }
}

#[cfg(unix)]
#[cfg(feature = "tokio-net")]
impl AsyncAcceptable for tokio::net::UnixListener {
    type Stream = tokio::net::UnixStream;

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<Self::Stream>> {
        let stream = ready!(self.poll_accept(cx))?.0;
        Poll::Ready(Ok(stream))
    }
}

/// Extension trait for `AsyncAcceptable` that provides async methods.
pub trait AsyncAcceptableExt: AsyncAcceptable + Send + Sync {
    /// Accept a connection asynchronously.
    fn accept(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send {
        poll_fn(|cx| self.poll_accept(cx))
    }

    /// Accept a connection asynchronously, returning the stream and the peer address.
    fn accept_with_sockaddr(
        &self,
    ) -> impl Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send {
        poll_fn(|cx| self.poll_accept_with_sockaddr(cx))
    }
}

impl<T: AsyncAcceptable + Send + Sync> AsyncAcceptableExt for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tokio-net")]
    #[tokio::test]
    async fn test_async_acceptable() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector_task = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(b"test").await.unwrap();
            stream
        });
        let (mut s, a) = AsyncAcceptableExt::accept_with_sockaddr(&listener)
            .await
            .unwrap();
        let stream = connector_task.await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"test");
        assert_eq!(a, stream.local_addr().unwrap());
    }
}
