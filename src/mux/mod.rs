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
use bytes::Bytes;
use inner::MultiplexorInner;
use rand::distributions::uniform::SampleUniform;
use rand::Rng;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, RwLock},
};
use tokio_tungstenite::WebSocketStream;
use tracing::{error, trace, warn};

pub use frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
pub use stream::MuxStream;
pub use tungstenite::protocol::Role;

/// Multiplexor error
#[derive(Debug, Error)]
pub enum Error {
    #[error("Requester exited before receiving the stream")]
    SendStreamToClient,
    #[error("Mux is already closed")]
    Closed,

    // These are tungstenite errors separated by their origin
    #[error("Failed to receive message: {0}")]
    Next(tungstenite::Error),
    #[error("Failed to flush messages: {0}")]
    Flush(tungstenite::Error),
    #[error("Failed to send datagram: {0}")]
    SendDatagram(tungstenite::Error),
    #[error("Failed to send stream frame: {0}")]
    SendStreamFrame(tungstenite::Error),
    #[error("Failed to send ping: {0}")]
    SendPing(tungstenite::Error),

    // These are the ones that shouldn't normally happen
    #[error("Datagram target host longer than 255 octets")]
    DatagramHostTooLong(#[from] <Vec<u8> as TryFrom<DatagramFrame>>::Error),
    #[error("Invalid frame: {0}")]
    InvalidFrame(#[from] frame::Error),
    #[error("Received `Text` message")]
    TextMessage,
    #[error("Server received `SynAck` frame")]
    ServerReceivedSynAck,
    #[error("Client received `Syn` frame")]
    ClientReceivedSyn,
}

#[derive(Debug)]
pub struct Multiplexor<S> {
    inner: MultiplexorInner<S>,
    /// Channel of received datagram frames for processing
    datagram_rx: RwLock<mpsc::Receiver<DatagramFrame>>,
    /// Channel of established streams for processing
    stream_rx: RwLock<mpsc::Receiver<MuxStream<S>>>,
}

impl<S> Multiplexor<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Create a new `Multiplexor`
    #[tracing::instrument(skip_all, level = "debug")]
    pub fn new(
        ws: WebSocketStream<S>,
        role: Role,
        keepalive_interval: Option<std::time::Duration>,
    ) -> Self {
        let (datagram_tx, datagram_rx) = tokio::sync::mpsc::channel(config::DATAGRAM_BUFFER_SIZE);
        let (stream_tx, stream_rx) = tokio::sync::mpsc::channel(config::STREAM_BUFFER_SIZE);
        let (dropped_ports_tx, dropped_ports_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ack_tx, ack_rx) = tokio::sync::mpsc::unbounded_channel();

        let inner = MultiplexorInner {
            role,
            ws: locked_sink::LockedWebSocket::new(ws),
            keepalive_interval,
            streams: Arc::new(RwLock::new(HashMap::new())),
            dropped_ports_tx,
            ack_tx,
        };
        tokio::spawn(
            inner
                .dupe()
                .task(datagram_tx, stream_tx, dropped_ports_rx, ack_rx),
        );
        trace!("Multiplexor task spawned");

        Self {
            inner,
            datagram_rx: RwLock::new(datagram_rx),
            stream_rx: RwLock::new(stream_rx),
        }
    }

    /// Request a channel for `host` and `port`
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn client_new_stream_channel(
        &self,
        host: &[u8],
        port: u16,
    ) -> Result<MuxStream<S>, Error> {
        assert_eq!(self.inner.role, Role::Client);
        // Allocate a new port
        let sport = u16::next_available_key(&*self.inner.streams.read().await);
        trace!("sport = {sport}");
        trace!("sending `Syn`");
        self.inner
            .ws
            .send_with(|| StreamFrame::new_syn(host, port, sport, config::RWND).into())
            .await
            .map_err(Error::SendStreamFrame)?;
        self.inner
            .ws
            .flush_ignore_closed()
            .await
            .map_err(Error::Flush)?;
        trace!("sending stream to user");
        let stream = self
            .stream_rx
            .write()
            .await
            .recv()
            .await
            .ok_or(Error::Closed)?;
        Ok(stream)
    }

    /// Get the next available stream channel
    /// Returns `None` if the connection is closed
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn server_new_stream_channel(&self) -> Option<MuxStream<S>> {
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
        let payload: Bytes = Vec::<u8>::try_from(frame)?.into();
        self.inner
            .ws
            .send_with(|| tungstenite::Message::Binary(payload.dupe().into()))
            .await
            .map_err(Error::SendDatagram)?;
        Ok(())
    }
}

impl<S> Drop for Multiplexor<S> {
    fn drop(&mut self) {
        self.inner
            .dropped_ports_tx
            .send((0, 0))
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
        loop {
            let i = rand::thread_rng().gen_range(Self::MIN..Self::MAX);
            if !map.contains_key(&i) {
                break i;
            }
        }
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
