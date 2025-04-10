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
pub mod frame;
mod inner;
mod proto_version;
mod stream;
#[cfg(test)]
mod tests;
pub mod timing;

use crate::frame::{BindPayload, BindType, FinalizedFrame, Frame};
use crate::inner::MultiplexorInner;
use crate::timing::OptionalDuration;
use bytes::Bytes;
use futures_util::future::poll_fn;
use futures_util::{Sink, Stream};
use parking_lot::{Mutex, RwLock};
use rand::distr::uniform::SampleUniform;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::{sync::mpsc, task::JoinSet};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tracing::{error, trace, warn};

pub use crate::dupe::Dupe;
pub use crate::proto_version::{PROTOCOL_VERSION, PROTOCOL_VERSION_NUMBER};
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
    WebSocket(#[from] Box<WsError>),

    // These are the ones that shouldn't normally happen
    /// A `Datagram` frame with a target host longer than 255 octets.
    #[error("Datagram target host longer than 255 octets")]
    DatagramHostTooLong,
    /// Received an invalid frame.
    #[error("Invalid frame: {0}")]
    InvalidFrame(#[from] frame::Error),
    /// The peer sent a `Text` message.
    /// "The client and server MUST NOT use other WebSocket data frame types"
    #[error("Received `Text` message")]
    TextMessage,
    /// A `Acknowledge` frame that does not match any pending [`Connect`](frame::OpCode::Connect) request.
    #[error("Bogus `Acknowledge` frame")]
    ConnAckGone,
}

/// A variant of [`std::result::Result`] with [`enum@Error`] as the error type.
pub type Result<T> = std::result::Result<T, Error>;

/// A multiplexor over a `WebSocket` connection.
#[derive(Debug)]
pub struct Multiplexor {
    inner: MultiplexorInner,
    /// Channel of received datagram frames for processing.
    datagram_rx: Mutex<mpsc::Receiver<Datagram>>,
    /// Channel for a `Multiplexor` to receive newly
    /// established streams after the peer requests one.
    con_recv_stream_rx: Mutex<mpsc::Receiver<MuxStream>>,
    /// Channel for `Bnd` requests.
    bnd_request_rx: Option<Mutex<mpsc::Receiver<BindPayload<'static>>>>,
}

impl Multiplexor {
    /// Create a new `Multiplexor`.
    ///
    /// # Arguments
    ///
    /// * `ws`: The `WebSocket` connection to multiplex over.
    ///
    /// * `keepalive_interval`: The interval at which to send [`Ping`](tokio_tungstenite::tungstenite::protocol::Message::Ping) frames.
    ///
    /// * `task_joinset`: A [`JoinSet`] to spawn the multiplexor task into so
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
        // This one is unbounded because the protocol provides its own flow control for `Push` frames
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
    /// # Cancel safety
    /// This function is not cancel safe. If the task is cancelled while waiting
    /// for the channel to be established, that channel may be established but
    /// inaccessible through normal means. Subsequent calls to this function
    /// will result in a new channel being established.
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn new_stream_channel(&self, host: &[u8], port: u16) -> Result<MuxStream> {
        let (stream_tx, stream_rx) = oneshot::channel();
        let flow_id = {
            let mut streams = self.inner.streams.write();
            // Allocate a new port
            let flow_id = u32::next_available_key(&*streams);
            trace!("flow_id = {flow_id}");
            streams.insert(flow_id, inner::MuxStreamSlot::Requested(stream_tx));
            flow_id
        };
        trace!("sending `Connect`");
        self.inner
            .tx_frame_tx
            .send(Frame::new_connect(host, port, flow_id, config::RWND).finalize())
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
    pub async fn get_datagram(&self) -> Result<Datagram> {
        poll_fn(|cx| self.datagram_rx.lock().poll_recv(cx))
            .await
            .ok_or(Error::Closed)
    }

    /// Send a datagram
    ///
    /// # Errors
    /// * Returns [`Error::DatagramHostTooLong`] if the destination host is
    /// longer than 255 octets.
    /// * Returns [`Error::Closed`] if the Multiplexor is already closed.
    ///
    /// # Cancel Safety
    /// This function is cancel safe. If the task is cancelled, it is
    /// guaranteed that the datagram has not been sent.
    #[tracing::instrument(skip(self), level = "debug")]
    #[inline]
    pub async fn send_datagram(&self, datagram: Datagram) -> Result<()> {
        if datagram.target_host.len() > 255 {
            return Err(Error::DatagramHostTooLong);
        }
        let frame = Frame::new_datagram_owned(
            datagram.flow_id,
            datagram.target_host,
            datagram.target_port,
            datagram.data,
        );
        self.inner
            .tx_frame_tx
            .send(frame.finalize())
            .map_err(|_| Error::Closed)?;
        Ok(())
    }

    /// Request a `Bind` for `host` and `port`.
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
    pub async fn request_bnd(
        &self,
        host: &[u8],
        port: u16,
        request_id: u32,
        bind_type: BindType,
    ) -> Result<()> {
        let bnd_frame = Frame::new_bind(request_id, bind_type, host, port).finalize();
        self.inner
            .tx_frame_tx
            .send(bnd_frame)
            .map_err(|_| Error::Closed)?;
        // TODO: await response
        Ok(())
    }

    /// Accept a `Bind` request from the remote peer.
    ///
    /// # Cancel Safety
    /// This function is cancel safe. If the task is cancelled while waiting
    /// for a `Bind` request, it is guaranteed that no request will be lost.
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn accept_bnd_request(&self) -> Result<BindPayload<'static>> {
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
        self.inner.dropped_ports_tx.send(0).ok();
    }
}

/// Internal type used for spawning the multiplexor task
#[derive(Debug)]
struct TaskData {
    datagram_tx: mpsc::Sender<Datagram>,
    con_recv_stream_tx: mpsc::Sender<MuxStream>,
    tx_frame_rx: mpsc::UnboundedReceiver<FinalizedFrame>,
    dropped_ports_rx: mpsc::UnboundedReceiver<u32>,
    bnd_request_tx: Option<mpsc::Sender<BindPayload<'static>>>,
}

/// Datagram frame data
#[derive(Clone, Debug)]
pub struct Datagram {
    /// Flow ID
    pub flow_id: u32,
    /// Target host
    pub target_host: Bytes,
    /// Target port
    pub target_port: u16,
    /// Data
    pub data: Bytes,
}

/// A generic WebSocket stream
pub trait WebSocketStream:
    Stream<Item = std::result::Result<Message, WsError>>
    + Sink<Message, Error = WsError>
    + Send
    + Unpin
    + 'static
{
}

impl<RW> WebSocketStream for tokio_tungstenite::WebSocketStream<RW> where
    RW: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
{
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
