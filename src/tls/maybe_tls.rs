use super::TlsStream;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream that may be encrypted with TLS
pub enum MaybeTlsStream<T> {
    Tls(TlsStream<T>),
    Plain(T),
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeTlsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeTlsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_flush(cx),
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(feature = "__rustls")]
impl<S> From<tokio_rustls::server::TlsStream<S>> for MaybeTlsStream<S> {
    fn from(stream: tokio_rustls::server::TlsStream<S>) -> Self {
        MaybeTlsStream::Tls(tokio_rustls::TlsStream::Server(stream))
    }
}

#[cfg(feature = "__rustls")]
impl<S> From<tokio_rustls::client::TlsStream<S>> for MaybeTlsStream<S> {
    fn from(stream: tokio_rustls::client::TlsStream<S>) -> Self {
        MaybeTlsStream::Tls(tokio_rustls::TlsStream::Client(stream))
    }
}

#[cfg(feature = "nativetls")]
impl<S> From<tokio_native_tls::TlsStream<S>> for MaybeTlsStream<S> {
    fn from(stream: tokio_native_tls::TlsStream<S>) -> Self {
        MaybeTlsStream::Tls(stream)
    }
}
