//! Client- and server-side connection multiplexing and processing
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use futures_util::{Sink, Stream};
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_stream_multiplexor::{StreamMultiplexor, StreamMultiplexorConfig};
use tokio_tungstenite::tungstenite::protocol::Message as ClientMessage;
use warp::ws::Message as ServerMessage;

/// Generic representation of a WebSocket message
pub trait WebSocketMessage {
    fn from_data(data: Vec<u8>) -> Self;
    fn into_data(self) -> Vec<u8>;
}

impl WebSocketMessage for ClientMessage {
    fn from_data(data: Vec<u8>) -> Self {
        Self::binary(data)
    }

    fn into_data(self) -> Vec<u8> {
        self.into_data()
    }
}

impl WebSocketMessage for ServerMessage {
    fn from_data(data: Vec<u8>) -> Self {
        Self::binary(data)
    }

    fn into_data(self) -> Vec<u8> {
        self.into_bytes()
    }
}

/// A generic WebSocket connection
pub struct WebSocket<Inner, Msg, Err>(Inner)
where
    Err: std::error::Error + Sync + Send + 'static,
    Msg: WebSocketMessage + 'static,
    Inner:
        Stream<Item = Result<Msg, Err>> + Sink<Msg, Error = Err> + Unpin + Send + Sized + 'static;

impl<Inner, Msg, Err> WebSocket<Inner, Msg, Err>
where
    Err: std::error::Error + Sync + Send + 'static,
    Msg: WebSocketMessage + 'static,
    Inner:
        Stream<Item = Result<Msg, Err>> + Sink<Msg, Error = Err> + Unpin + Send + Sized + 'static,
{
    /// Create a new `WebSocket` from a `WebSocketStream`
    pub fn new(ws: Inner) -> Self {
        Self(ws)
    }
}

impl<Inner, Msg, Err> AsyncRead for WebSocket<Inner, Msg, Err>
where
    Err: std::error::Error + Sync + Send + 'static,
    Msg: WebSocketMessage + 'static,
    Inner:
        Stream<Item = Result<Msg, Err>> + Sink<Msg, Error = Err> + Unpin + Send + Sized + 'static,
{
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

impl<Inner, Msg, Err> Deref for WebSocket<Inner, Msg, Err>
where
    Err: std::error::Error + Sync + Send + 'static,
    Msg: WebSocketMessage + 'static,
    Inner:
        Stream<Item = Result<Msg, Err>> + Sink<Msg, Error = Err> + Unpin + Send + Sized + 'static,
{
    type Target = Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Inner, Msg, Err> AsyncWrite for WebSocket<Inner, Msg, Err>
where
    Err: std::error::Error + Sync + Send + 'static,
    Msg: WebSocketMessage + 'static,
    Inner:
        Stream<Item = Result<Msg, Err>> + Sink<Msg, Error = Err> + Unpin + Send + Sized + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match Pin::new(&mut self.0).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let msg = Msg::from_data(data.to_vec());
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

/// The actual multiplexor
#[derive(Debug)]
pub struct Multiplexor<I, M, E>
where
    E: std::error::Error + Sync + Send + 'static,
    M: WebSocketMessage + 'static,
    I: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin + Send + Sized + 'static,
{
    mux: StreamMultiplexor<WebSocket<I, M, E>>,
}

impl<I, M, E> Multiplexor<I, M, E>
where
    E: std::error::Error + Sync + Send + 'static,
    M: WebSocketMessage + 'static,
    I: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin + Send + Sized + 'static,
{
    /// Create a new `ClientMultiplexor` from a `ClientWebSocket`
    pub fn new(s: WebSocket<I, M, E>) -> Self {
        let config = StreamMultiplexorConfig::default();
        let mux = StreamMultiplexor::new(s, config);
        Self { mux }
    }
}

impl<I, M, E> Deref for Multiplexor<I, M, E>
where
    E: std::error::Error + Sync + Send + 'static,
    M: WebSocketMessage + 'static,
    I: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin + Send + Sized + 'static,
{
    type Target = StreamMultiplexor<WebSocket<I, M, E>>;

    fn deref(&self) -> &Self::Target {
        &self.mux
    }
}
