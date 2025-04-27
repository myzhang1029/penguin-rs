//! Multiplexing streamed data and datagrams over a single WebSocket
//! connection.
//!
//! This is not a general-purpose WebSocket multiplexing library.
//! It is tailored to the needs of `penguin`.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
#![deny(missing_docs, missing_debug_implementations)]

mod config;
mod dupe;
pub mod frame;
mod inner;
mod proto_version;
mod stream;
mod task;
#[cfg(test)]
mod tests;
pub mod timing;

use crate::frame::{BindPayload, BindType, FinalizedFrame, Frame};
use crate::inner::MultiplexorInner;
use crate::task::Task;
use crate::timing::OptionalDuration;
use bytes::Bytes;
use futures_util::{Sink, Stream, future::poll_fn};
use parking_lot::{Mutex, RwLock};
use rand::distr::uniform::SampleUniform;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use task::TaskData;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
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
    /// Peer rejected the flow ID selection.
    #[error("Peer rejected flow ID selection")]
    FlowIdRejected,

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
    /// An internal channel closed
    #[error("Internal channel `{0}` closed")]
    ChannelClosed(&'static str),
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
    bnd_request_rx: Option<Mutex<mpsc::Receiver<BindRequest<'static>>>>,
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
    pub fn new<S: WebSocketStream<WsError>>(
        ws: S,
        keepalive_interval: OptionalDuration,
        accept_bnd: bool,
        task_joinset: Option<&mut JoinSet<Result<()>>>,
    ) -> Self {
        let (mux, taskdata) = Self::new_no_task(keepalive_interval, accept_bnd);
        taskdata.spawn(ws, task_joinset);
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
            flows: Arc::new(RwLock::new(HashMap::new())),
            dropped_ports_tx,
            con_recv_stream_tx,
            default_rwnd_threshold: config::DEFAULT_RWND_THRESHOLD,
        };

        let mux = Self {
            inner: inner.dupe(),
            datagram_rx: Mutex::new(datagram_rx),
            con_recv_stream_rx: Mutex::new(con_recv_stream_rx),
            bnd_request_rx: bnd_request_rx.map(Mutex::new),
        };
        let taskdata = TaskData {
            task: Task {
                inner,
                datagram_tx,
                bnd_request_tx,
                keepalive_interval,
            },
            dropped_ports_rx,
            tx_frame_rx,
        };
        (mux, taskdata)
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
        let mut retries_left = config::MAX_FLOW_ID_RETRIES;
        // Normally this should terminate in one loop
        while retries_left > 0 {
            retries_left -= 1;
            let (stream_tx, stream_rx) = oneshot::channel();
            let flow_id = {
                let mut streams = self.inner.flows.write();
                // Allocate a new port
                let flow_id = u32::next_available_key(&*streams);
                trace!("flow_id = {flow_id:08x}");
                streams.insert(flow_id, inner::FlowSlot::Requested(stream_tx));
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
            if let Some(s) = stream {
                return Ok(s);
            }
            // For testing purposes. Make sure the previous flow ID is gone
            debug_assert!(!self.inner.flows.read().contains_key(&flow_id));
        }
        Err(Error::FlowIdRejected)
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
    /// This function is not cancel safe. If the task is cancelled while waiting
    /// for the peer to reply, the user will not be able to receive whether the
    /// peer accepted the bind request.
    #[tracing::instrument(skip(self), level = "debug")]
    #[inline]
    pub async fn request_bind(&self, host: &[u8], port: u16, bind_type: BindType) -> Result<bool> {
        let (result_tx, result_rx) = oneshot::channel();
        let flow_id = {
            let mut streams = self.inner.flows.write();
            // Allocate a new port
            let flow_id = u32::next_available_key(&*streams);
            trace!("flow_id = {flow_id:08x}");
            streams.insert(flow_id, inner::FlowSlot::BindRequested(result_tx));
            flow_id
        };
        let bnd_frame = Frame::new_bind(flow_id, bind_type, host, port).finalize();
        self.inner
            .tx_frame_tx
            .send(bnd_frame)
            .map_err(|_| Error::Closed)?;
        let result = result_rx.await.map_err(|_| Error::Closed)?;
        Ok(result)
    }

    /// Accept a `Bind` request from the remote peer.
    ///
    /// # Cancel Safety
    /// This function is cancel safe. If the task is cancelled while waiting
    /// for a `Bind` request, it is guaranteed that no request will be lost.
    #[tracing::instrument(skip(self), level = "debug")]
    pub async fn next_bind_request(&self) -> Result<BindRequest<'static>> {
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
        if self.inner.dropped_ports_tx.send(0).is_err() {
            error!("Failed to inform task of dropped multiplexor");
        }
    }
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

/// A `Bind` request that the user can respond to
#[derive(Debug)]
pub struct BindRequest<'data> {
    /// Flow ID
    flow_id: u32,
    /// Bind payload
    payload: BindPayload<'data>,
    /// Place to respond to the bind request
    tx_frame_tx: mpsc::UnboundedSender<FinalizedFrame>,
}

impl BindRequest<'_> {
    /// Get the flow ID of the bind request
    #[inline]
    pub const fn flow_id(&self) -> u32 {
        self.flow_id
    }

    /// Get the bind type of the bind request
    #[inline]
    pub const fn bind_type(&self) -> BindType {
        self.payload.bind_type
    }

    /// Get the host of the bind request
    #[inline]
    pub fn host(&self) -> &[u8] {
        self.payload.target_host.as_ref()
    }

    /// Get the port of the bind request
    #[inline]
    pub const fn port(&self) -> u16 {
        self.payload.target_port
    }

    /// Accept or reject the bind request
    #[tracing::instrument(skip(self), level = "debug")]
    pub fn reply(&self, accepted: bool) -> Result<()> {
        if accepted {
            self.tx_frame_tx
                .send(Frame::new_finish(self.flow_id).finalize())
        } else {
            self.tx_frame_tx
                .send(Frame::new_reset(self.flow_id).finalize())
        }
        .map_err(|_| Error::Closed)
    }
}

impl Drop for BindRequest<'_> {
    /// Dropping a `BindRequest` will reject the request
    fn drop(&mut self) {
        self.reply(false).ok();
    }
}

/// A generic WebSocket stream
pub trait WebSocketStream<E>
where
    Self: Stream<Item = std::result::Result<Message, E>>
        + Sink<Message, Error = E>
        + Send
        + Unpin
        + 'static,
    Box<E>: Into<Error>,
{
}

impl<RW> WebSocketStream<WsError> for tokio_tungstenite::WebSocketStream<RW> where
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
