//! Client- and server-side connection multiplexing and processing
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use futures_util::{pin_mut, FutureExt, Sink, Stream};
use log::{debug, trace};
use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_stream_multiplexor::{DuplexStream, StreamMultiplexor, StreamMultiplexorConfig};
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
#[derive(Clone, Debug)]
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

/// Multiplexor error
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("no available ports")]
    NoAvailablePorts,
    #[error("control channel not established")]
    ControlChannelNotEstablished,
    #[error("server not in sync")]
    ServerNotInSync,
}
/// Multiplexor role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client role
    Client,
    /// Server role
    Server,
}

/// The actual multiplexor, which is a wrapper around a `StreamMultiplexor`
/// and a `WebSocket` instance.
/// When we need a new channel, both ends synchronize on the `ctrl_chan`
/// channel.
#[derive(Debug)]
pub struct Multiplexor<I, M, E>
where
    E: AsyncIoError,
    M: WebSocketMessage,
    I: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin + Send + Sized + 'static,
{
    /// The underlying `StreamMultiplexor`
    mux: StreamMultiplexor<WebSocket<I, M, E>>,
    /// The role of this multiplexor
    role: Role,
    /// The control channel
    pub ctrl_chan: Option<DuplexStream>,
    /// The set of ports that are currently in use. Only used by the client though.
    /// TODO: remove port from this set when the channel is closed
    used_ports: HashSet<u16>,
}

impl<I, M, E> Multiplexor<I, M, E>
where
    E: AsyncIoError,
    M: WebSocketMessage,
    I: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin + Send + Sized + 'static,
{
    /// Create a new `ClientMultiplexor` from a `ClientWebSocket`
    pub fn new(s: WebSocket<I, M, E>, role: Role) -> Self {
        let config = StreamMultiplexorConfig::default();
        let mux = StreamMultiplexor::new(s, config);
        Self {
            mux,
            role,
            ctrl_chan: None,
            used_ports: HashSet::new(),
        }
    }

    /// Establish the new control channel
    pub async fn establish_control_channel(&mut self) -> std::io::Result<()> {
        let ctrl_chan = match self.role {
            Role::Client => self.mux.connect(1).await?,
            Role::Server => self.mux.bind(1).await?.accept().await?,
        };
        self.ctrl_chan = Some(ctrl_chan);
        Ok(())
    }

    /// Attempt to claim the next usable port
    fn claim_next_usable_port(&mut self) -> Option<u16> {
        let mut port = 2;
        loop {
            while self.used_ports.contains(&port) {
                port += 1;
                if port == u16::MAX {
                    return None;
                }
            }
            // crude synchronization
            if self.used_ports.insert(port) {
                return Some(port);
            }
        }
    }

    /// Ask to open a new channel on the client side,
    /// or accept a new channel on the server side.
    /// Note that on the server side, this server will block until
    /// a new channel is requested.
    pub async fn open_channel(&mut self) -> Result<DuplexStream, Error> {
        let port = self
            .claim_next_usable_port()
            .ok_or(Error::NoAvailablePorts)?;
        // TODO: mutex on ctrl_chan and concurrent access
        let ctrl_chan = self
            .ctrl_chan
            .as_mut()
            .ok_or(Error::ControlChannelNotEstablished)?;
        match self.role {
            Role::Client => {
                debug!("Requesting channel on port {port}");
                ctrl_chan.write_u16(port).await?;
                // Sync with the server: wait for it to tell us to connect
                if ctrl_chan.read_u16().await? != port {
                    return Err(Error::ServerNotInSync);
                }
                trace!("Server is in sync, connecting to port {port}");
                // A psuedo sleep for the server to accept()
                tokio::task::yield_now().await;
                Ok(self.mux.connect(port).await?)
            }
            Role::Server => {
                loop {
                    let port = ctrl_chan.read_u16().await?;
                    if port == 0 {
                        // Ping
                        ctrl_chan.write_u16(0).await?;
                    } else {
                        let listener = self.mux.bind(port).await?;
                        debug!("Listening on port {port}");
                        // Tell the client that we are ready and they can connect to this port
                        ctrl_chan.write_u16(port).await?;
                        break Ok(listener.accept().await?);
                    }
                }
            }
        }
    }

    /// Ping the other side
    pub async fn ping(&mut self) -> Result<(), Error> {
        let ctrl_chan = self
            .ctrl_chan
            .as_mut()
            .ok_or(Error::ControlChannelNotEstablished)?;
        if self.role == Role::Client {
            ctrl_chan.write_u16(0).await?;
            ctrl_chan.read_u16().await?;
        }
        // Nothing to do on the server side
        Ok(())
    }

    /// Close the multiplexor
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        if let Some(mut ctrl_chan) = self.ctrl_chan.take() {
            ctrl_chan.shutdown().await?;
        }
        Ok(())
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

pub async fn pipe_streams<R1, W1, R2, W2>(
    mut reader1: R1,
    mut writer1: W1,
    mut reader2: R2,
    mut writer2: W2,
) -> std::io::Result<u64>
where
    R1: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let pipe1 = tokio::io::copy(&mut reader1, &mut writer2).fuse();
    let pipe2 = tokio::io::copy(&mut reader2, &mut writer1).fuse();

    pin_mut!(pipe1, pipe2);

    tokio::select! {
        res = pipe1 => res,
        res = pipe2 => res
    }
}
