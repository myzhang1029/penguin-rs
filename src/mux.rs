//! Client- and server-side connection multiplexing and processing
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use futures_util::{Sink, Stream};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_stream_multiplexor::{StreamMultiplexor, StreamMultiplexorConfig};
use tungstenite::Message as ClientMessage;
use warp::ws::Message as ServerMessage;

/// Generic representation of a WebSocket message
pub trait WebSocketMessage: Unpin + Send + Sync + 'static {
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

/// `std::error::Error` + Sync + Send + 'static. Just for saving ink.
pub trait AsyncIoError: std::error::Error + Unpin + Sync + Send + Sized + 'static {
    fn into_io_error(self) -> std::io::Error {
        // Takes ownership of self
        std::io::Error::new(std::io::ErrorKind::Other, self)
    }
}

impl<T> AsyncIoError for T where T: std::error::Error + Unpin + Sync + Send + 'static {}

/// A generic WebSocket connection
#[derive(Debug)]
pub struct WebSocket<Inner, Msg, Err>
where
    Msg: WebSocketMessage,
    Err: AsyncIoError,
    Inner:
        Stream<Item = Result<Msg, Err>> + Sink<Msg, Error = Err> + Unpin + Send + Sized + 'static,
{
    inner: Inner,
    buffer: Option<Vec<u8>>,
}

impl<Inner, Msg, Err> WebSocket<Inner, Msg, Err>
where
    Msg: WebSocketMessage,
    Err: AsyncIoError,
    Inner:
        Stream<Item = Result<Msg, Err>> + Sink<Msg, Error = Err> + Unpin + Send + Sized + 'static,
{
    /// Create a new `WebSocket` from a `WebSocketStream`
    pub fn new(ws: Inner) -> Self {
        Self {
            inner: ws,
            buffer: None,
        }
    }
}

impl<Inner, Msg, Err> AsyncRead for WebSocket<Inner, Msg, Err>
where
    Msg: WebSocketMessage,
    Err: AsyncIoError,
    Inner:
        Stream<Item = Result<Msg, Err>> + Sink<Msg, Error = Err> + Unpin + Send + Sized + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        /// Fill `buf` from `data` and save the remaining data back in `data`
        fn fill_save_extra(buf: &mut ReadBuf<'_>, data: &mut Vec<u8>) {
            let buf_remaining = buf.remaining();
            if buf_remaining < data.len() {
                let remaining_data = data.split_off(buf_remaining);
                buf.put_slice(data);
                *data = remaining_data;
            } else {
                buf.put_slice(data);
                data.clear();
            }
        }
        if let Some(mut data) = self.buffer.take() {
            // Fill `buf` from leftover data
            fill_save_extra(buf, &mut data);
            if !data.is_empty() {
                // Save leftover data
                self.buffer = Some(data);
            }
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.inner).poll_next(cx).map(|x| match x {
                Some(Ok(message)) => {
                    let mut data = message.into_data();
                    fill_save_extra(buf, &mut data);
                    if !data.is_empty() {
                        // Save leftover data
                        self.buffer = Some(data);
                    }
                    Ok(())
                }
                Some(Err(e)) => Err(e.into_io_error()),
                None => Ok(()),
            })
        }
    }
}

impl<Inner, Msg, Err> Deref for WebSocket<Inner, Msg, Err>
where
    Msg: WebSocketMessage,
    Err: AsyncIoError,
    Inner:
        Stream<Item = Result<Msg, Err>> + Sink<Msg, Error = Err> + Unpin + Send + Sized + 'static,
{
    type Target = Inner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<Inner, Msg, Err> DerefMut for WebSocket<Inner, Msg, Err>
where
    Msg: WebSocketMessage,
    Err: AsyncIoError,
    Inner:
        Stream<Item = Result<Msg, Err>> + Sink<Msg, Error = Err> + Unpin + Send + Sized + 'static,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<Inner, Msg, Err> AsyncWrite for WebSocket<Inner, Msg, Err>
where
    Msg: WebSocketMessage,
    Err: AsyncIoError,
    Inner:
        Stream<Item = Result<Msg, Err>> + Sink<Msg, Error = Err> + Unpin + Send + Sized + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                // XXX: warp::ws::Message has a default max size of 64MB,
                // so we can safely assume that no one will send a message
                // larger than that. Prove me wrong.
                let msg = Msg::from_data(data.to_vec());
                Pin::new(&mut self.inner)
                    .start_send(msg)
                    .map_err(AsyncIoError::into_io_error)?;
                Poll::Ready(Ok(data.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into_io_error())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_flush(cx)
            .map_err(AsyncIoError::into_io_error)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_close(cx)
            .map_err(AsyncIoError::into_io_error)
    }
}

/// The actual multiplexor
#[derive(Debug)]
pub struct Multiplexor<I, M, E>
where
    E: AsyncIoError,
    M: WebSocketMessage,
    I: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin + Send + Sized + 'static,
{
    mux: StreamMultiplexor<WebSocket<I, M, E>>,
}

impl<I, M, E> Multiplexor<I, M, E>
where
    E: AsyncIoError,
    M: WebSocketMessage,
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
    E: AsyncIoError,
    M: WebSocketMessage,
    I: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin + Send + Sized + 'static,
{
    type Target = StreamMultiplexor<WebSocket<I, M, E>>;

    fn deref(&self) -> &Self::Target {
        &self.mux
    }
}

impl<I, M, E> DerefMut for Multiplexor<I, M, E>
where
    E: AsyncIoError,
    M: WebSocketMessage,
    I: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin + Send + Sized + 'static,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mux
    }
}
