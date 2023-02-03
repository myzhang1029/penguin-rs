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
use inner::MultiplexorInner;
use rand::distributions::uniform::SampleUniform;
use rand::Rng;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, Ordering};
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
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Tungstenite(#[from] tungstenite::Error),
    #[error("requester exited before receiving the stream")]
    SendStreamToClient,
    #[error("mux is already closed")]
    Closed,

    // These are the ones that shouldn't normally happen
    #[error("datagram host longer than 255 octets")]
    DatagramHostTooLong(#[from] <Vec<u8> as TryFrom<DatagramFrame>>::Error),
    #[error("invalid frame: {0}")]
    InvalidFrame(#[from] frame::Error),
    #[error("received `Text` message")]
    TextMessage,
    #[error("server received `SynAck` frame")]
    ServerReceivedSynAck,
    #[error("client received `Syn` frame")]
    ClientReceivedSyn,
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
            closed: Arc::new(AtomicBool::new(false)),
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
    /// Returns `None` if the connection is closed
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn client_new_stream_channel(
        &self,
        host: Vec<u8>,
        port: u16,
    ) -> Result<MuxStream<S>, Error> {
        assert_eq!(self.inner.role, Role::Client);
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }
        // Allocate a new port
        let sport = u16::next_available_key(&*self.inner.streams.read().await);
        trace!("sport = {sport}");
        trace!("sending `Syn`");
        self.inner
            .ws
            .send_with(|| StreamFrame::new_syn(&host, port, sport, config::RWND).into())
            .await?;
        self.inner.ws.flush_ignore_closed().await?;
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
        let message: tungstenite::Message = frame.try_into()?;
        self.inner.ws.send_with(|| message.clone()).await?;
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
