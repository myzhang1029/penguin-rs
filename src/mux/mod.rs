//! Client- and server-side connection multiplexing and processing
//!
//! This is not a general-purpose `WebSocket` multiplexing library.
//! It is tailored to the needs of `penguin`.
//!
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod frame;
mod inner;
mod locked_sink;
mod stream;
#[cfg(test)]
mod test;

use crate::config;
use crate::dupe::Dupe;
use futures_util::stream::SplitSink;
use futures_util::{Sink as FutureSink, Stream as FutureStream, StreamExt};
use inner::MultiplexorInner;
use rand::distributions::uniform::SampleUniform;
use rand::Rng;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::WebSocketStream;
use tracing::{error, trace, warn};
use tungstenite::Message;

pub use frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
pub use stream::MuxStream;
pub use tungstenite::protocol::Role;

/// Multiplexor error
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Tungstenite(#[from] tungstenite::Error),
    #[error("datagram invalid: {0}")]
    InvalidDatagramFrame(#[from] <Vec<u8> as TryFrom<DatagramFrame>>::Error),
    #[error("received `Text` message")]
    TextMessage,
    #[error("server received `Ack` frame")]
    ServerReceivedAck,
    #[error("client received `Syn` frame")]
    ClientReceivedSyn,
    #[error(transparent)]
    SendFrameToChannel(#[from] tokio::sync::mpsc::error::SendError<Vec<u8>>),
    #[error(transparent)]
    SendDatagramToClient(#[from] tokio::sync::mpsc::error::SendError<DatagramFrame>),
    #[error("cannot send stream to client: {0}")]
    SendStreamToClient(String),
    #[error("Mux received no stream")]
    StreamTxClosed,
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            Error::Tungstenite(e) => tungstenite_error_to_io_error(e),
            e => Self::new(std::io::ErrorKind::Other, e),
        }
    }
}

fn tungstenite_error_to_io_error(e: tungstenite::Error) -> std::io::Error {
    match e {
        tungstenite::Error::Io(e) => e,
        e => std::io::Error::new(std::io::ErrorKind::Other, e),
    }
}

#[derive(Debug)]
pub struct Multiplexor<Sink> {
    inner: MultiplexorInner<Sink>,
    /// Channel of received datagram frames for processing
    datagram_rx: RwLock<mpsc::Receiver<DatagramFrame>>,
    /// Channel of established streams for processing
    stream_rx: RwLock<mpsc::Receiver<MuxStream<Sink>>>,
}

impl<Sink> Multiplexor<Sink>
where
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Sync + Unpin + 'static,
{
    /// Create a new `Multiplexor`
    #[tracing::instrument(skip_all, level = "debug")]
    pub fn new_with_sink_stream<Stream>(
        sink: Sink,
        stream: Stream,
        keepalive_interval: Option<std::time::Duration>,
        role: Role,
    ) -> Self
    where
        Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Sync + Unpin + 'static,
    {
        let (datagram_tx, datagram_rx) = tokio::sync::mpsc::channel(config::DATAGRAM_BUFFER_SIZE);
        let (stream_tx, stream_rx) = tokio::sync::mpsc::channel(config::STREAM_BUFFER_SIZE);
        let (dropped_ports_tx, dropped_ports_rx) = tokio::sync::mpsc::unbounded_channel();

        let inner = MultiplexorInner {
            role,
            sink: locked_sink::LockedSink::new(sink),
            keepalive_interval,
            streams: Arc::new(RwLock::new(HashMap::new())),
            dropped_ports_tx,
        };
        tokio::spawn(
            inner
                .dupe()
                .task_wrapper(datagram_tx, stream_tx, dropped_ports_rx, stream),
        );
        trace!("Multiplexor task spawned");

        Self {
            inner,
            datagram_rx: RwLock::new(datagram_rx),
            stream_rx: RwLock::new(stream_rx),
        }
    }

    /// Request a channel for `host` and `port`
    /// Returns `None` if the connection is closed
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn client_new_stream_channel(
        &self,
        host: Vec<u8>,
        port: u16,
    ) -> Result<MuxStream<Sink>, Error> {
        assert_eq!(self.inner.role, Role::Client);
        // Allocate a new port
        let sport = u16::next_available_key(&*self.inner.streams.read().await);
        trace!("sport = {sport}");
        let syn_frame = StreamFrame::new_syn(&host, port, sport)?;
        trace!("sending syn");
        self.inner.send_message(syn_frame.into()).await?;
        trace!("sending stream to user");
        let stream = self
            .stream_rx
            .write()
            .await
            .recv()
            .await
            .ok_or(Error::StreamTxClosed)?;
        Ok(stream)
    }

    /// Get the next available stream channel
    /// Returns `None` if the connection is closed
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn server_new_stream_channel(&self) -> Option<MuxStream<Sink>> {
        assert_eq!(self.inner.role, Role::Server);
        self.stream_rx.write().await.recv().await
    }

    /// Get the next available datagram
    /// Returns `None` if the connection is closed
    #[tracing::instrument(skip(self), level = "debug")]
    #[inline]
    pub async fn get_datagram(&self) -> Option<DatagramFrame> {
        self.datagram_rx.write().await.recv().await
    }

    /// Send a datagram
    #[tracing::instrument(skip(self), level = "debug")]
    #[inline]
    pub async fn send_datagram(&self, frame: DatagramFrame) -> Result<(), Error> {
        self.inner.send_message(frame.try_into()?).await?;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>
    Multiplexor<SplitSink<WebSocketStream<S>, Message>>
{
    /// Create a new `WebSocketMultiplexor` from a `WebSocketStream`
    #[must_use]
    pub fn new(
        ws_stream: WebSocketStream<S>,
        role: Role,
        keepalive_interval: Option<std::time::Duration>,
    ) -> Self {
        let (sink, stream) = ws_stream.split();
        Self::new_with_sink_stream(sink, stream, keepalive_interval, role)
    }
}

impl<Sink> Drop for Multiplexor<Sink> {
    fn drop(&mut self) {
        self.inner
            .dropped_ports_tx
            .send((0, 0, false))
            .unwrap_or_else(|_| warn!("Failed to notify task of dropped mux"));
    }
}

/// Randomly generate a new number
pub trait IntKey: Eq + Hash + Copy + SampleUniform + PartialOrd {
    /// The minimum value of the key
    const MIN: Self;
    /// The maximum value of the key
    const MAX: Self;

    /// Generate a new key that is not in the map
    #[inline]
    #[must_use]
    fn next_available_key<V>(map: &HashMap<Self, V>) -> Self {
        let mut i = Self::MIN;

        while map.contains_key(&i) {
            i = rand::thread_rng().gen_range(Self::MIN..Self::MAX);
        }
        i
    }
}

macro_rules! impl_int_key {
    ($($t:ty),*) => {
        $(
            impl IntKey for $t {
                // 0 is for special use
                const MIN : Self = 1;
                const MAX : Self = Self::MAX;
            }
        )*
    };
}

impl_int_key!(u8, u16, u32, u64, u128, usize);
