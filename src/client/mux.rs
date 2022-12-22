//! Client-side connection multiplexing and processing
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use futures_util::{Sink, Stream};
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_stream_multiplexor::{StreamMultiplexor, StreamMultiplexorConfig};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// WebSocket connection
#[derive(Debug)]
pub struct ClientWebSocket(WebSocketStream<MaybeTlsStream<TcpStream>>);

impl ClientWebSocket {
    /// Create a new `ClientListener` from a `WebSocket`
    pub fn new(ws: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self(ws)
    }
}

/// The actual multiplexor on the client side
#[derive(Debug)]
pub struct ClientMultiplexor {
    mux: StreamMultiplexor<ClientWebSocket>,
}

impl ClientMultiplexor {
    /// Create a new `ClientMultiplexor` from a `ClientWebSocket`
    pub fn new(s: ClientWebSocket) -> Self {
        let config = StreamMultiplexorConfig::default();
        let mux = StreamMultiplexor::new(s, config);
        Self { mux }
    }
}

impl Deref for ClientMultiplexor {
    type Target = StreamMultiplexor<ClientWebSocket>;

    fn deref(&self) -> &Self::Target {
        &self.mux
    }
}

impl AsyncRead for ClientWebSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_next(cx).map(|x| match x {
            Some(Ok(message)) => {
                buf.put_slice(&message.into_data());
                Ok(())
            }
            Some(Err(e)) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            None => Ok(()),
        })
    }
}

impl AsyncWrite for ClientWebSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match Pin::new(&mut self.0).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let msg = Message::binary(data.to_vec());
                Pin::new(&mut self.0)
                    .start_send(msg)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Poll::Ready(Ok(data.len()))
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().0)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().0)
            .poll_close(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}
