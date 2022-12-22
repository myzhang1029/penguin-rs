//! Server-side connection multiplexing and processing
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use futures_util::{Sink, Stream};
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_stream_multiplexor::{StreamMultiplexor, StreamMultiplexorConfig};
use warp::ws::{Message, WebSocket};

/// WebSocket connection
#[derive(Debug)]
pub struct ServerWebSocket(WebSocket);

impl ServerWebSocket {
    /// Create a new `ServerListener` from a `WebSocket`
    pub fn new(ws: WebSocket) -> Self {
        Self(ws)
    }
}

/// The actual multiplexor on the server side
#[derive(Debug)]
pub struct ServerMultiplexor {
    mux: StreamMultiplexor<ServerWebSocket>,
}

impl ServerMultiplexor {
    /// Create a new `ServerMultiplexor` from a `ServerWebSocket`
    pub fn new(s: ServerWebSocket) -> Self {
        let config = StreamMultiplexorConfig::default();
        let mux = StreamMultiplexor::new(s, config);
        Self { mux }
    }
}

impl Deref for ServerMultiplexor {
    type Target = StreamMultiplexor<ServerWebSocket>;

    fn deref(&self) -> &Self::Target {
        &self.mux
    }
}

impl AsyncRead for ServerWebSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_next(cx).map(|x| match x {
            Some(Ok(message)) => {
                buf.put_slice(message.as_bytes());
                Ok(())
            }
            Some(Err(e)) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            None => Ok(()),
        })
    }
}

impl AsyncWrite for ServerWebSocket {
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
