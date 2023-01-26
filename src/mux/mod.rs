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
use crate::mux::locked_sink::LockedMessageSink;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink as FutureSink, Stream as FutureStream, StreamExt};
use inner::MultiplexorInner;
use rand::distributions::uniform::SampleUniform;
use rand::Rng;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
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
    #[error("invalid message: {0}")]
    InvalidMessage(#[from] frame::Error),
    #[error(transparent)]
    LockedSink(#[from] locked_sink::SinkError),
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

#[derive(Clone, Debug)]
pub struct Multiplexor<Sink, Stream> {
    inner: Arc<MultiplexorInner<Sink, Stream>>,
}

impl<Sink, Stream> Multiplexor<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Sync + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Sync + Unpin + 'static,
{
    /// Create a new `Multiplexor`
    #[tracing::instrument(skip_all, level = "debug")]
    pub fn new_with_sink_stream(
        sink: Sink,
        stream: Stream,
        keepalive_interval: Option<std::time::Duration>,
        role: Role,
    ) -> Self {
        let (datagram_tx, datagram_rx) = tokio::sync::mpsc::channel(config::DATAGRAM_BUFFER_SIZE);
        let (stream_tx, stream_rx) = tokio::sync::mpsc::channel(config::STREAM_BUFFER_SIZE);
        let (dropped_ports_tx, dropped_ports_rx) = tokio::sync::mpsc::unbounded_channel();

        let inner = Arc::new(MultiplexorInner {
            role,
            sink: LockedMessageSink::new(sink),
            stream: RwLock::new(stream),
            keepalive_interval,
            streams: RwLock::new(HashMap::new()),
            datagram_rx: RwLock::new(datagram_rx),
            stream_rx: RwLock::new(stream_rx),
            dropped_ports_tx,
        });

        tokio::spawn(inner.dupe().task(datagram_tx, stream_tx, dropped_ports_rx));
        trace!("Multiplexor task spawned");

        Self { inner }
    }

    /// Request a channel for `host` and `port`
    /// Returns `None` if the connection is closed
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn client_new_stream_channel(
        &self,
        host: Vec<u8>,
        port: u16,
    ) -> Result<MuxStream<Sink, Stream>, Error> {
        assert_eq!(self.inner.role, Role::Client);
        // Allocate a new port
        let sport = u16::next_available_key(&*self.inner.streams.read().await);
        trace!("sport = {sport}");
        let syn_frame = StreamFrame::new_syn(&host, port, sport)?;
        trace!("sending syn");
        self.inner.send_frame(Frame::Stream(syn_frame)).await?;
        trace!("sending stream to user");
        let mut stream_rx = self.inner.stream_rx.write().await;
        let stream = stream_rx.recv().await.ok_or(Error::StreamTxClosed)?;
        Ok(stream)
    }

    /// Get the next available stream channel
    /// Returns `None` if the connection is closed
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn server_new_stream_channel(&self) -> Option<MuxStream<Sink, Stream>> {
        assert_eq!(self.inner.role, Role::Server);
        let mut stream_rx = self.inner.stream_rx.write().await;
        stream_rx.recv().await
    }

    /// Get the next available datagram
    /// Returns `None` if the connection is closed
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn get_datagram(&self) -> Option<DatagramFrame> {
        let mut datagram_rx = self.inner.datagram_rx.write().await;
        datagram_rx.recv().await
    }

    /// Send a datagram
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn send_datagram(&self, frame: DatagramFrame) -> Result<(), Error> {
        self.inner.send_frame(Frame::Datagram(frame)).await?;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>
    Multiplexor<SplitSink<WebSocketStream<S>, Message>, SplitStream<WebSocketStream<S>>>
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

impl<Sink, Stream> Drop for Multiplexor<Sink, Stream> {
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
                const MAX : Self = <$t>::MAX;
            }
        )*
    };
}

impl_int_key!(u8, u16, u32, u64, u128, usize);
