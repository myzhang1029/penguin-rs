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
use bytes::Bytes;
use frame::FinalizedFrame;
use futures_util::future::poll_fn;
use parking_lot::{Mutex, RwLock};
use rand::distr::uniform::SampleUniform;
use std::collections::HashMap;
use std::hash::Hash;
use std::num::TryFromIntError;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{error, trace, warn};

pub use crate::dupe::Dupe;
pub use crate::frame::{DatagramFrame, Frame, StreamFrame, StreamOpCode};
pub use crate::stream::MuxStream;

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
    /// The peer does not support the requested operation.
    #[error("Peer does not support requested operation")]
    PeerUnsupportedOperation,
    /// This `Multiplexor` is not configured for this operation.
    #[error("Unsupported operation")]
    UnsupportedOperation,

    /// WebSocket errors
    #[error("WebSocket Error: {0}")]
    WebSocket(#[from] Box<crate::ws::Error>),

    // These are the ones that shouldn't normally happen
    /// Datagram target host longer than 255 octets.
    #[error("Datagram target host longer than 255 octets")]
    DatagramHostTooLong(#[from] TryFromIntError),
    /// Received an invalid frame.
    #[error("Invalid frame: {0}")]
    InvalidFrame(#[from] frame::Error),
    /// The peer sent a `Text` message.
    /// "The client and server MUST NOT use other WebSocket data frame types"
    #[error("Received `Text` message")]
    TextMessage,
    /// A `Con` frame carrying a non-zero-dport.
    #[error("Received `Con` frame with non-zero dport ({0})")]
    ConWithDport(u16),
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
    datagram_rx: Mutex<mpsc::Receiver<DatagramFrame<'static>>>,
    /// Channel for a `Multiplexor` to receive newly
    /// established streams after the peer requests one.
    con_recv_stream_rx: Mutex<mpsc::Receiver<MuxStream>>,
    /// Channel for `Bnd` requests.
    bnd_request_rx: Option<Mutex<mpsc::Receiver<(Bytes, u16)>>>,
}

/// Internal type used for spawning the multiplexor task.
struct TaskData {
    datagram_tx: mpsc::Sender<DatagramFrame<'static>>,
    con_recv_stream_tx: mpsc::Sender<MuxStream>,
    tx_frame_rx: mpsc::UnboundedReceiver<FinalizedFrame>,
    dropped_ports_rx: mpsc::UnboundedReceiver<(u16, u16)>,
    bnd_request_tx: Option<mpsc::Sender<(Bytes, u16)>>,
}

impl Multiplexor {
    /// Create a new `Multiplexor`.
    ///
    /// # Arguments
    ///
    /// * `ws`: The `WebSocket` connection to multiplex over.
    ///
    /// * `keepalive_interval`: The interval at which to send `Ping` frames.
    ///
    /// * `task_joinset`: A `JoinSet` to spawn the multiplexor task into so
    ///   that the caller can notice if the task exits. If it is `None`, the
    ///   task will be spawned by `tokio::spawn` and errors will be logged.
    #[tracing::instrument(skip_all, level = "debug")]
    pub fn new<S: WebSocketStream>(
        ws: S,
        keepalive_interval: OptionalDuration,
        accept_bnd: bool,
        task_joinset: Option<&mut JoinSet<Result<()>>>,
    ) -> Self {
        let (mux, taskdata) = Self::new_no_task(keepalive_interval, accept_bnd);
        mux.spawn_task(ws, taskdata, task_joinset);
        mux
    }

    /// Create a new `Multiplexor` without spawning the task.
    #[inline]
    fn new_no_task(keepalive_interval: OptionalDuration, accept_bnd: bool) -> (Self, TaskData) {
        let (datagram_tx, datagram_rx) = mpsc::channel(config::DATAGRAM_BUFFER_SIZE);
        let (con_recv_stream_tx, con_recv_stream_rx) = mpsc::channel(config::STREAM_BUFFER_SIZE);
        // This one is unbounded because the protocol provides its own flow control for `Psh` frames
        // and other frame types are to be immediately processed without any backpressure,
        // so they are ok to be unbounded channels.
        let (tx_frame_tx, tx_frame_rx) = mpsc::unbounded_channel();
        // This one cannot be bounded because it needs to be used in Drop
        let (dropped_ports_tx, dropped_ports_rx) = mpsc::unbounded_channel();

        let (bnd_request_tx, bnd_request_rx) = if accept_bnd {
            let (tx, rx) = mpsc::channel(config::BND_BUFFER_SIZE);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let inner = MultiplexorInner {
            tx_frame_tx,
            keepalive_interval,
            streams: Arc::new(RwLock::new(HashMap::new())),
            dropped_ports_tx,
            default_rwnd_threshold: config::DEFAULT_RWND_THRESHOLD,
        };

        let mux = Self {
            inner,
            datagram_rx: Mutex::new(datagram_rx),
            con_recv_stream_rx: Mutex::new(con_recv_stream_rx),
            bnd_request_rx: bnd_request_rx.map(Mutex::new),
        };
        let taskdata = TaskData {
            datagram_tx,
            con_recv_stream_tx,
            tx_frame_rx,
            dropped_ports_rx,
            bnd_request_tx,
        };
        (mux, taskdata)
    }

    /// Spawn the multiplexor task.
    /// This function and [`new_no_task`] are implementation details and not exposed in the public API.
    #[inline]
    fn spawn_task<S: WebSocketStream>(
        &self,
        ws: S,
        taskdata: TaskData,
        task_joinset: Option<&mut JoinSet<Result<()>>>,
    ) {
        let task_future = self.inner.dupe().task(ws, taskdata);
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
    pub async fn new_stream_channel(&self, host: &[u8], port: u16) -> Result<MuxStream> {
        let (stream_tx, stream_rx) = oneshot::channel();
        let sport = {
            let mut streams = self.inner.streams.write();
            // Allocate a new port
            let sport = u16::next_available_key(&*streams);
            trace!("sport = {sport}");
            streams.insert(sport, inner::MuxStreamSlot::Requested(stream_tx));
            sport
        };
        trace!("sending `Con`");
        self.inner
            .tx_frame_tx
            .send(StreamFrame::new_con(host, port, sport, config::RWND).finalize())
            .map_err(|_| Error::Closed)?;
        trace!("sending stream to user");
        let stream = stream_rx
            .await
            // Happens if the task exits before sending the stream,
            // thus `Closed` is the correct error
            .map_err(|_| Error::Closed)?;
        Ok(stream)
    }

    /// Accept a new stream channel from the remote peer.
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
    pub async fn accept_stream_channel(&self) -> Result<MuxStream> {
        poll_fn(|cx| self.con_recv_stream_rx.lock().poll_recv(cx))
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
    pub async fn get_datagram(&self) -> Result<DatagramFrame<'static>> {
        poll_fn(|cx| self.datagram_rx.lock().poll_recv(cx))
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
    pub async fn send_datagram<'data>(&self, frame: DatagramFrame<'data>) -> Result<()> {
        self.inner
            .tx_frame_tx
            .send(frame.finalize()?)
            .map_err(|_| Error::Closed)?;
        Ok(())
    }

    /// Request a `Bnd` for `host` and `port`.
    ///
    /// # Arguments
    /// * `host`: The local address or host to bind to. Hostname resolution might
    /// not be supported by the remote peer.
    /// * `port`: The local port to bind to.
    ///
    /// # Cancel Safety
    /// TODO
    #[tracing::instrument(skip(self), level = "debug")]
    #[inline]
    pub async fn request_bnd(&self, host: &[u8], port: u16, request_id: u16) -> Result<()> {
        let bnd_frame = StreamFrame::new_bnd(request_id, host, port).finalize();
        self.inner
            .tx_frame_tx
            .send(bnd_frame)
            .map_err(|_| Error::Closed)?;
        // TODO: await response
        Ok(())
    }

    /// Accept a `Bnd` request from the remote peer.
    ///
    /// # Cancel Safety
    /// This function is cancel safe. If the task is cancelled while waiting
    /// for a `Bnd` request, it is guaranteed that no request will be lost.
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn accept_bnd_request(&self) -> Result<(Bytes, u16)> {
        if let Some(rx) = self.bnd_request_rx.as_ref() {
            poll_fn(|cx| rx.lock().poll_recv(cx))
                .await
                .ok_or(Error::Closed)
        } else {
            Err(Error::UnsupportedOperation)
        }
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
