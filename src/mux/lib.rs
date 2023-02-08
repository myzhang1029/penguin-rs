//! Client- and server-side connection multiplexing and processing
//!
//! This is not a general-purpose `WebSocket` multiplexing library.
//! It is tailored to the needs of `penguin`.
//!
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
#![deny(missing_docs, missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]

mod config;
pub mod dupe;
mod frame;
mod inner;
mod locked_sink;
mod stream;
#[cfg(test)]
mod test;

use bytes::Bytes;
use dupe::Dupe;
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
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};
use tracing::{error, trace, warn};

pub use frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
pub use stream::MuxStream;
pub use tokio_tungstenite::tungstenite::protocol::Role;

/// Multiplexor error
#[derive(Debug, Error)]
pub enum Error {
    /// Requester exited before receiving the stream
    /// (i.e. the `Receiver` was dropped before the task could send the stream)
    #[error("Requester exited before receiving the stream")]
    SendStreamToClient,
    /// When
    #[error("Mux is already closed")]
    Closed,

    // These are tungstenite errors separated by their origin
    /// Tungstenite error when polling the next message
    #[error("Failed to receive message: {0}")]
    Next(tokio_tungstenite::tungstenite::Error),
    /// Tungstenite error when flushing messages
    #[error("Failed to flush messages: {0}")]
    Flush(tokio_tungstenite::tungstenite::Error),
    /// Tungstenite error when sending a datagram
    #[error("Failed to send datagram: {0}")]
    SendDatagram(tokio_tungstenite::tungstenite::Error),
    /// Tungstenite error when sending a stream frame
    #[error("Failed to send stream frame: {0}")]
    SendStreamFrame(tokio_tungstenite::tungstenite::Error),
    /// Tungstenite error when sending a ping
    #[error("Failed to send ping: {0}")]
    SendPing(tokio_tungstenite::tungstenite::Error),

    // These are the ones that shouldn't normally happen
    /// Datagram target host longer than 255 octets
    #[error("Datagram target host longer than 255 octets")]
    DatagramHostTooLong(#[from] <Vec<u8> as TryFrom<DatagramFrame>>::Error),
    /// Received an invalid frame
    #[error("Invalid frame: {0}")]
    InvalidFrame(#[from] frame::Error),
    /// The peer sent a `Text` message
    /// "The client and server MUST NOT use other WebSocket data frame types"
    #[error("Received `Text` message")]
    TextMessage,
    /// A `SynAck` frame was received by the server:
    /// "clients MUST NOT send `SynAck` frames"
    #[error("Server received `SynAck` frame")]
    ServerReceivedSynAck,
    /// A `Syn` frame was received by the client
    /// "Servers MUST NOT send `Syn` frames"
    #[error("Client received `Syn` frame")]
    ClientReceivedSyn,
}

/// A variant of `std::result::Result` with `Error` as the error type
pub type Result<T> = std::result::Result<T, Error>;

/// A multiplexor over a `WebSocket` connection
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
        let (datagram_tx, datagram_rx) = mpsc::channel(config::DATAGRAM_BUFFER_SIZE);
        let (stream_tx, stream_rx) = mpsc::channel(config::STREAM_BUFFER_SIZE);
        let (dropped_ports_tx, dropped_ports_rx) = mpsc::unbounded_channel();
        let (ack_tx, ack_rx) = mpsc::unbounded_channel();

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
    pub async fn client_new_stream_channel(&self, host: &[u8], port: u16) -> Result<MuxStream<S>> {
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
            // Happens if the task exits before sending the stream,
            // thus `Closed` is the correct error
            .ok_or(Error::Closed)?;
        Ok(stream)
    }

    /// Get the next available stream channel
    ///
    /// # Errors
    /// Returns `Error::Closed` if the connection is closed
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn server_new_stream_channel(&self) -> Result<MuxStream<S>> {
        assert_eq!(self.inner.role, Role::Server);
        self.stream_rx
            .write()
            .await
            .recv()
            .await
            .ok_or(Error::Closed)
    }

    /// Get the next available datagram
    ///
    /// # Errors
    /// Returns `Error::Closed` if the connection is closed
    #[tracing::instrument(skip(self), level = "debug")]
    #[inline]
    pub async fn get_datagram(&self) -> Result<DatagramFrame> {
        self.datagram_rx
            .write()
            .await
            .recv()
            .await
            .ok_or(Error::Closed)
    }

    /// Send a datagram
    ///
    /// # Errors
    /// - Returns `Error::DatagramHostTooLong` if the destination host is
    /// longer than 255 octets.
    /// - Returns `Error::SendDatagram` if the datagram could not be sent
    /// due to a `tungstenite::Error`.
    #[tracing::instrument(skip(self), level = "debug")]
    #[inline]
    pub async fn send_datagram(&self, frame: DatagramFrame) -> Result<()> {
        let payload: Bytes = Vec::<u8>::try_from(frame)?.into();
        self.inner
            .ws
            .send_with(|| Message::Binary(payload.dupe().into()))
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
