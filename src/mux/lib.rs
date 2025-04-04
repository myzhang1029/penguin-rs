//! Multiplexing streamed data and datagrams over a single WebSocket
//! connection.
//!
//! This is not a general-purpose WebSocket multiplexing library.
//! It is tailored to the needs of `penguin`.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
#![deny(missing_docs, missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]

mod config;
mod dupe;
mod frame;
mod inner;
mod stream;
#[cfg(test)]
mod tests;
pub mod timing;
pub mod ws;

use crate::inner::MultiplexorInner;
use crate::timing::OptionalDuration;
use crate::ws::WebSocketStream;
use rand::distr::uniform::SampleUniform;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::{
    sync::{mpsc, Mutex, RwLock},
    task::JoinSet,
};
use tracing::{error, trace, warn};

pub use crate::dupe::Dupe;
pub use crate::frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
pub use crate::stream::MuxStream;
pub use crate::ws::Role;

/// Multiplexor error
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Requester exited before receiving the stream
    /// (i.e. the `Receiver` was dropped before the task could send the stream).
    #[error("Requester exited before receiving the stream")]
    SendStreamToClient,
    /// The multiplexor is closed.
    #[error("Mux is already closed")]
    Closed,

    /// WebSocket errors
    #[error("WebSocket Error: {0}")]
    WebSocket(#[from] crate::ws::Error),

    // These are the ones that shouldn't normally happen
    /// Datagram target host longer than 255 octets.
    #[error("Datagram target host longer than 255 octets")]
    DatagramHostTooLong(#[from] <Vec<u8> as TryFrom<DatagramFrame>>::Error),
    /// Received an invalid frame.
    #[error("Invalid frame: {0}")]
    InvalidFrame(#[from] frame::Error),
    /// The peer sent a `Text` message.
    /// "The client and server MUST NOT use other WebSocket data frame types"
    #[error("Received `Text` message")]
    TextMessage,
    /// A `SynAck` frame was received by the server.
    /// "clients MUST NOT send `SynAck` frames"
    #[error("Server received `SynAck` frame")]
    ServerReceivedSynAck,
    /// A `Syn` frame was received by the client.
    /// "Servers MUST NOT send `Syn` frames"
    #[error("Client received `Syn` frame")]
    ClientReceivedSyn,
    /// A `Syn` frame carrying a non-zero-port ot aport that is already in use.
    #[error("Invalid `Syn` port: {0}")]
    InvalidSynPort(u16),
    /// A `SynAck` frame that does not match any pending `Syn` request.
    #[error("Bogus `SynAck` frame")]
    BogusSynAck,
}

/// A variant of [`std::result::Result`] with [`enum@Error`] as the error type.
pub type Result<T> = std::result::Result<T, Error>;

/// A multiplexor over a `WebSocket` connection.
#[derive(Debug)]
pub struct Multiplexor {
    inner: MultiplexorInner,
    /// Channel of received datagram frames for processing.
    datagram_rx: Mutex<mpsc::Receiver<DatagramFrame>>,
    /// Channel for a server-side `Multiplexor` to receive newly
    /// established streams.
    server_stream_rx: Mutex<mpsc::Receiver<MuxStream>>,
}

impl Multiplexor {
    /// Create a new `Multiplexor`.
    ///
    /// # Arguments
    ///
    /// * `ws`: The `WebSocket` connection to multiplex over.
    ///
    /// * `role`: The role of this side of the connection.
    ///   (does not have to match the `WebSocket` role)
    ///
    /// * `keepalive_interval`: The interval at which to send `Ping` frames.
    ///
    /// * `task_joinset`: A `JoinSet` to spawn the multiplexor task into so
    ///   that the caller can notice if the task exits. If it is `None`, the
    ///   task will be spawned by `tokio::spawn` and errors will be logged.
    #[tracing::instrument(skip_all, level = "debug")]
    pub fn new<S: WebSocketStream>(
        ws: S,
        role: Role,
        keepalive_interval: OptionalDuration,
        task_joinset: Option<&mut JoinSet<Result<()>>>,
    ) -> Self {
        let (datagram_tx, datagram_rx) = mpsc::channel(config::DATAGRAM_BUFFER_SIZE);
        let (server_stream_tx, server_stream_rx) = mpsc::channel(config::STREAM_BUFFER_SIZE);
        // This one is unbounded because the protocol provides its own flow control for `Psh` frames
        // and other frame types are to be immediately processed without any backpressure,
        // so they are ok to be unbounded channels.
        let (frame_tx, frame_rx) = mpsc::unbounded_channel();
        // This one cannot be bounded because it needs to be used in Drop
        let (dropped_ports_tx, dropped_ports_rx) = mpsc::unbounded_channel();

        let inner = MultiplexorInner {
            role,
            frame_tx,
            keepalive_interval,
            streams: Arc::new(RwLock::new(HashMap::new())),
            dropped_ports_tx,
        };
        let task_future = inner.dupe().task(
            ws,
            datagram_tx,
            server_stream_tx,
            frame_rx,
            dropped_ports_rx,
        );
        if let Some(task_joinset) = task_joinset {
            task_joinset.spawn(task_future);
        } else {
            tokio::spawn(async move {
                if let Err(e) = task_future.await {
                    error!("Multiplexor task exited with error: {}", e);
                }
            });
        }
        trace!("Multiplexor task spawned");

        Self {
            inner,
            datagram_rx: Mutex::new(datagram_rx),
            server_stream_rx: Mutex::new(server_stream_rx),
        }
    }

    /// Request a channel for `host` and `port`.
    ///
    /// # Arguments
    /// * `host`: The host to forward to. While the current implementation
    ///   supports a domain of arbitrary length, Section 3.2.2 of
    ///   [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2)
    ///   specifies that the host component of a URI is limited to 255 octets.
    /// * `port`: The port to forward to.
    ///
    /// # Panics
    /// Panics if the `Multiplexor` is not a client.
    ///
    /// # Cancel safety
    /// This function is not cancel safe. If the task is cancelled while waiting
    /// for the channel to be established, that channel may be established but
    /// inaccessible through normal means. Subsequent calls to this function
    /// will result in a new channel being established.
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn client_new_stream_channel(&self, host: &[u8], port: u16) -> Result<MuxStream> {
        assert_eq!(self.inner.role, Role::Client);
        let (stream_tx, stream_rx) = oneshot::channel();
        let sport = {
            let mut streams = self.inner.streams.write().await;
            // Allocate a new port
            let sport = u16::next_available_key(&*streams);
            trace!("sport = {sport}");
            streams.insert(sport, inner::MuxStreamSlot::Requested(stream_tx));
            sport
        };
        trace!("sending `Syn`");
        self.inner
            .frame_tx
            .send(StreamFrame::new_syn(host, port, sport, config::RWND).into())
            .map_err(|_| Error::Closed)?;
        trace!("sending stream to user");
        let stream = stream_rx
            .await
            // Happens if the task exits before sending the stream,
            // thus `Closed` is the correct error
            .map_err(|_| Error::Closed)?;
        Ok(stream)
    }

    /// Get the next available stream channel.
    ///
    /// # Errors
    /// Returns [`Error::Closed`] if the connection is closed.
    ///
    /// # Panics
    /// Panics if the `Multiplexor` is not a server.
    ///
    /// # Cancel Safety
    /// This function is cancel safe. If the task is cancelled while waiting
    /// for a new connection, it is guaranteed that no connected stream will
    /// be lost.
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn server_new_stream_channel(&self) -> Result<MuxStream> {
        assert_eq!(self.inner.role, Role::Server);
        self.server_stream_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(Error::Closed)
    }

    /// Get the next available datagram.
    ///
    /// # Errors
    /// Returns [`Error::Closed`] if the connection is closed.
    ///
    /// # Cancel Safety
    /// This function is cancel safe. If the task is cancelled while waiting
    /// for a datagram, it is guaranteed that no datagram will be lost.
    #[tracing::instrument(skip(self), level = "debug")]
    #[inline]
    pub async fn get_datagram(&self) -> Result<DatagramFrame> {
        self.datagram_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(Error::Closed)
    }

    /// Send a datagram
    ///
    /// # Errors
    /// * Returns `Error::DatagramHostTooLong` if the destination host is
    /// longer than 255 octets.
    /// * Returns `Error::SendDatagram` if the datagram could not be sent
    /// due to a `crate::ws::Error`.
    ///
    /// # Cancel Safety
    /// This function is cancel safe. If the task is cancelled, it is
    /// guaranteed that the datagram has not been sent.
    #[tracing::instrument(skip(self), level = "debug")]
    #[inline]
    pub async fn send_datagram(&self, frame: DatagramFrame) -> Result<()> {
        self.inner
            .frame_tx
            .send(frame.into())
            .map_err(|_| Error::Closed)?;
        Ok(())
    }
}

impl Drop for Multiplexor {
    fn drop(&mut self) {
        self.inner.dropped_ports_tx.send((0, 0)).ok();
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
            let i = rand::random_range(Self::MIN..Self::MAX);
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
