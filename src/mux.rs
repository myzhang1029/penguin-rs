//! Client- and server-side connection multiplexing and processing
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use futures::stream::{SplitSink, SplitStream};
use futures::StreamExt;
use futures_util::{pin_mut, FutureExt};
use futures_util::{Sink as FutureSink, Stream as FutureStream};
pub use penguin_tokio_stream_multiplexor::DuplexStream;
use penguin_tokio_stream_multiplexor::{Config, WebSocketMultiplexor};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error};
use tungstenite::Message;

pub use tungstenite::protocol::Role;

/// Multiplexor error
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("no available ports")]
    NoAvailablePorts,
    #[error("control channel not established")]
    ControlChannelNotEstablished,
    #[error("invalid control channel message")]
    InvalidControlChannelMessage,
}

/// The actual multiplexor, which is a wrapper around a `WebSocketMultiplexor`
/// and a `WebSocket` instance.
/// When we need a new channel, both ends synchronize on the `ctrl_chan`
/// channel.
/// ctrl client commands:
/// - 0: ping; server responds with 0
/// - 1: open a new channel; server responds with a port number, or 0 if no ports are available.
#[derive(Debug)]
pub struct Multiplexor<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Unpin + 'static,
{
    /// The underlying `WebSocketMultiplexor`
    mux: WebSocketMultiplexor<Sink, Stream>,
    /// The role of this multiplexor
    role: Role,
    /// The control channel
    ctrl_chan: Option<DuplexStream>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send>
    Multiplexor<SplitSink<WebSocketStream<S>, Message>, SplitStream<WebSocketStream<S>>>
{
    /// Create a new `WebSocketMultiplexor` from a `WebSocketStream`
    pub fn new(ws_stream: WebSocketStream<S>, role: Role) -> Self {
        let (sink, stream) = ws_stream.split();
        let mut config = Config::default();
        config.max_frame_size = tungstenite::protocol::WebSocketConfig::default()
            .max_message_size
            .unwrap();
        config.buf_size = config.max_frame_size - 1024;
        let mux = WebSocketMultiplexor::new(sink, stream, config);
        Self {
            mux,
            role,
            ctrl_chan: None,
        }
    }
}

impl<Sink, Stream> Multiplexor<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Unpin + 'static,
{
    /// Establish the new control channel
    pub async fn establish_control_channel(&mut self) -> std::io::Result<()> {
        let ctrl_chan = match self.role {
            Role::Client => self.mux.connect(1).await?,
            Role::Server => self.mux.bind(1).await?.accept().await?,
        };
        self.ctrl_chan = Some(ctrl_chan);
        Ok(())
    }

    /// Ask to open a new channel on the client side,
    /// or offer a new channel on the server side.
    /// Note that on the server side, this server will block until
    /// a new channel is requested.
    pub async fn open_channel(&mut self) -> Result<DuplexStream, Error> {
        match self.role {
            Role::Client => self.client_side_open_channel().await,
            Role::Server => self.server_side_open_channel().await,
        }
    }

    /// Ask server to open a new channel
    #[tracing::instrument(skip(self), level = "debug")]
    async fn client_side_open_channel(&mut self) -> Result<DuplexStream, Error> {
        let ctrl_chan = self
            .ctrl_chan
            .as_mut()
            .ok_or(Error::ControlChannelNotEstablished)?;
        ctrl_chan.write_u16(1).await?;
        // Sync with the server: wait for it to tell us to connect
        let port = ctrl_chan.read_u16().await?;
        if port == 0 {
            error!("Server returned no available ports");
            Err(Error::NoAvailablePorts)
        } else {
            debug!("connecting to port {port}");
            // A psuedo sleep for the server to accept()
            tokio::task::yield_now().await;
            Ok(self.mux.connect(port).await?)
        }
    }

    /// Offer a new channel to the client
    #[tracing::instrument(skip(self), level = "debug")]
    async fn server_side_open_channel(&mut self) -> Result<DuplexStream, Error> {
        let ctrl_chan = self
            .ctrl_chan
            .as_mut()
            .ok_or(Error::ControlChannelNotEstablished)?;
        loop {
            match ctrl_chan.read_u16().await? {
                0 => {
                    // Ping
                    ctrl_chan.write_u16(0).await?;
                }
                1 => {
                    // Open a new channel
                    // `unwrap` is safe because we have already checked that the control channel is
                    // established
                    let ctrl_chan = self.ctrl_chan.as_mut().unwrap();
                    let listener = self.mux.bind(0).await?;
                    let port = listener.port();
                    debug!("listening on port {port}");
                    // Tell the client that we are ready and they can connect to this port
                    ctrl_chan.write_u16(port).await?;
                    break Ok(listener.accept().await?);
                }
                _ => {
                    error!("Invalid command received on control channel");
                    break Err(Error::InvalidControlChannelMessage);
                }
            }
        }
    }

    /// Ping the other side
    #[tracing::instrument(skip(self), level = "trace")]
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
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        if let Some(mut ctrl_chan) = self.ctrl_chan.take() {
            ctrl_chan.shutdown().await?;
        }
        Ok(())
    }
}

#[tracing::instrument(skip_all, level = "debug")]
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
