//! Based on `hyper-rustls` example
//!

use super::TlsIdentity;
use futures_util::Future;
use hyper::server::{
    accept::Accept,
    conn::{AddrIncoming, AddrStream},
};
#[cfg(feature = "__rustls")]
use rustls::ServerConfig;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "__rustls")]
enum State {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}
#[cfg(feature = "nativetls")]
enum State {
    Handshaking(
        Pin<
            Box<
                dyn Future<Output = Result<tokio_native_tls::TlsStream<AddrStream>, std::io::Error>>
                    + Send,
            >,
        >,
    ),
    Streaming(tokio_native_tls::TlsStream<AddrStream>),
}

pub struct TlsStream {
    state: State,
}

impl TlsStream {
    #[cfg(feature = "__rustls")]
    fn new(stream: AddrStream, config: Arc<ServerConfig>) -> TlsStream {
        let accept = tokio_rustls::TlsAcceptor::from(config).accept(stream);
        TlsStream {
            state: State::Handshaking(accept),
        }
    }
    #[cfg(feature = "nativetls")]
    fn new(stream: AddrStream, acceptor: Arc<tokio_native_tls::TlsAcceptor>) -> TlsStream {
        let accept = async move {
            acceptor
                .accept(stream)
                .await
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        };
        TlsStream {
            state: State::Handshaking(Box::pin(accept)),
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_read(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_write(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub struct TlsAcceptor {
    identity: TlsIdentity,
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub fn new(identity: TlsIdentity, incoming: AddrIncoming) -> TlsAcceptor {
        TlsAcceptor { identity, incoming }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.identity.load_full())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}
