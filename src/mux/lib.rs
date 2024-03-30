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
pub mod dupe;
mod frame;
mod locked_sink;
mod stream;
mod task;
#[cfg(test)]
mod test;
pub mod ws;

use crate::dupe::Dupe;
use crate::ws::{Message, WebSocketStream};
use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use rand::distributions::uniform::SampleUniform;
use rand::Rng;
use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::MissedTickBehavior;
use tokio::{
    sync::{mpsc, oneshot, RwLock},
    task::JoinSet,
};
use tracing::{debug, error, trace, warn};

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

    // These are WebSocket errors separated by their origin
    /// WebSocket error when polling the next message.
    #[error("Failed to receive message: {0}")]
    Next(crate::ws::Error),
    /// WebSocket error when sending a datagram.
    #[error("Failed to send datagram: {0}")]
    SendDatagram(crate::ws::Error),
    /// WebSocket error when sending a stream frame.
    #[error("Failed to send stream frame: {0}")]
    SendStreamFrame(crate::ws::Error),
    /// WebSocket error when working with [Ping](Message::Ping)/[Pong](Message::Pong) frames.
    #[error("Failed to send ping/pong: {0}")]
    PingPong(crate::ws::Error),

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

#[derive(Debug)]
pub struct MuxStreamData {
    /// Channel for sending data to `MuxStream`'s `AsyncRead`
    sender: mpsc::Sender<Bytes>,
    /// Whether writes should succeed.
    /// There are two cases for `false`:
    /// 1. `Fin` has been sent.
    /// 2. The stream has been removed from `inner.streams`.
    // In general, our `Atomic*` types don't need more than `Relaxed` ordering
    // because we are not protecting memory accesses, but rather counting the
    // frames we have sent and received.
    can_write: Arc<AtomicBool>,
    /// Number of `Psh` frames we are allowed to send before waiting for a `Ack` frame.
    psh_send_remaining: Arc<AtomicU64>,
    /// Waker to wake up the task that sends frames because their `psh_send_remaining`
    /// has increased.
    writer_waker: Arc<AtomicWaker>,
}

#[derive(Debug)]
pub enum MuxStreamSlot {
    /// The stream is requested by the `client`.
    Requested(oneshot::Sender<MuxStream>),
    /// The stream is established.
    Established(MuxStreamData),
}

impl MuxStreamSlot {
    /// Take the sender and set the slot to `Established`.
    /// Returns `None` if the slot is already established.
    pub fn establish(&mut self, data: MuxStreamData) -> Option<oneshot::Sender<MuxStream>> {
        // Make sure it is not replaced in the error case
        if matches!(self, Self::Established(_)) {
            return None;
        }
        let sender = match std::mem::replace(self, Self::Established(data)) {
            Self::Requested(sender) => sender,
            Self::Established(_) => unreachable!(),
        };
        Some(sender)
    }
}

/// A multiplexor over a `WebSocket` connection.
#[derive(Debug)]
pub struct Multiplexor {
    /// The role of this multiplexor
    role: Role,
    /// Open stream channels: our_port -> `MuxStreamData`
    streams: Arc<RwLock<HashMap<u16, MuxStreamSlot>>>,
    /// Channel for notifying the task of a dropped `MuxStream`
    /// (in the form (our_port, their_port)).
    /// Sending (0, _) means that the multiplexor is being dropped and the
    /// task should exit.
    /// The reason we need `their_port` is to ensure the connection is `Rst`ed
    /// if the user did not call `poll_shutdown` on the `MuxStream`.
    dropped_ports_tx: mpsc::UnboundedSender<(u16, u16)>,
    /// Channel for queuing `Ack` frames to be sent
    /// (in the form (our_port, their_port, psh_recvd_since)).
    ack_tx: mpsc::UnboundedSender<(u16, u16, u64)>,
    /// Channel to send stream frames to the task.
    outgoing_frame_tx: mpsc::Sender<StreamFrame>,
    /// Channel of received datagram frames for processing.
    incoming_datagram_rx: RefCell<mpsc::Receiver<DatagramFrame>>,
    /// Channel for a server-side `Multiplexor` to receive newly
    /// established streams.
    server_stream_rx: RefCell<mpsc::Receiver<MuxStream>>,
}

impl Drop for Multiplexor {
    fn drop(&mut self) {
        self.dropped_ports_tx.send((0, 0)).ok();
    }
}

// Impl block for public methods
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
        keepalive_interval: Option<std::time::Duration>,
        task_joinset: Option<&mut JoinSet<Result<()>>>,
    ) -> Self {
        let (incoming_datagram_tx, incoming_datagram_rx) =
            mpsc::channel(config::DATAGRAM_BUFFER_SIZE);
        let (server_stream_tx, server_stream_rx) = mpsc::channel(config::STREAM_BUFFER_SIZE);
        let (dropped_ports_tx, dropped_ports_rx) = mpsc::unbounded_channel();
        let (ack_tx, ack_rx) = mpsc::unbounded_channel();
        // TODO: what should the size be?
        let (outgoing_frame_tx, outgoing_frame_rx) =
            mpsc::channel(config::STREAM_FRAME_BUFFER_SIZE);

        let task_future = Self::task(datagram_tx, server_stream_tx, dropped_ports_rx, ack_rx);
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
            role,
            ws,
            keepalive_interval,
            streams: Arc::new(RwLock::new(HashMap::new())),
            dropped_ports_tx,
            ack_tx,
            stream_frame_tx,
            datagram_rx: RefCell::new(datagram_rx),
            server_stream_rx: RefCell::new(server_stream_rx),
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
        assert_eq!(self.role, Role::Client);
        let (stream_tx, stream_rx) = oneshot::channel();
        let sport = {
            let mut streams = self.streams.write().await;
            // Allocate a new port
            let sport = u16::next_available_key(&*streams);
            trace!("sport = {sport}");
            streams.insert(sport, MuxStreamSlot::Requested(stream_tx));
            sport
        };
        trace!("sending `Syn`");
        self.ws
            .send_with(|| StreamFrame::new_syn(host, port, sport, config::RWND).into())
            .await
            .map_err(Error::SendStreamFrame)?;
        trace!("sending stream to user");
        let stream = stream_rx
            .await
            // Happens if the task exits before sending the stream,
            // thus `Closed` is the correct error
            .map_err(|_| Error::Closed)?;
        Ok(stream)
    }

    /// Get the next available stream channel. Note that only one task should call this
    /// function at a time, since the underlying receiving channel is behind a `RefCell`.
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
        assert_eq!(self.role, Role::Server);
        self.server_stream_rx
            .borrow_mut()
            .recv()
            .await
            .ok_or(Error::Closed)
    }

    /// Get the next available datagram. Note that only one task should call this
    /// function at a time, since the underlying receiving channel is behind a `RefCell`.
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
        self.incoming_datagram_rx
            .borrow_mut()
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
        let payload: Bytes = Vec::<u8>::try_from(frame)?.into();
        // Always flush datagrams immediately
        self.ws
            .send_with(|| Message::Binary(payload.dupe().into()))
            .await
            .map_err(Error::SendDatagram)?;
        Ok(())
    }
}

impl Multiplexor {
    /// Process an incoming message
    /// Returns `Ok(true)` if a `Close` message was received.
    #[tracing::instrument(skip_all, level = "debug")]
    #[inline]
    async fn process_message(
        &self,
        msg: Message,
        datagram_tx: &mpsc::Sender<DatagramFrame>,
        server_stream_tx: &mpsc::Sender<MuxStream>,
    ) -> Result<bool> {
        match msg {
            Message::Binary(data) => {
                let frame = data.try_into()?;
                match frame {
                    Frame::Datagram(datagram_frame) => {
                        trace!("received datagram frame: {:?}", datagram_frame);
                        // Only fails if the receiver is dropped or the queue is full.
                        // The first case means the multiplexor itself is dropped;
                        // In the second case, we just drop the frame to avoid blocking.
                        // It is UDP, after all.
                        if let Err(e) = datagram_tx.try_send(datagram_frame) {
                            match e {
                                TrySendError::Full(_) => {
                                    warn!("dropped datagram frame: {e}");
                                }
                                TrySendError::Closed(_) => {
                                    return Err(Error::Closed);
                                }
                            }
                        }
                    }
                    Frame::Stream(stream_frame) => {
                        trace!("received stream frame: {:?}", stream_frame);
                        self.process_stream_frame(stream_frame, server_stream_tx)
                            .await?;
                    }
                }
                Ok(false)
            }
            Message::Ping(_data) => {
                // `tokio-tungstenite` handles `Ping` messages automatically
                trace!("received ping");
                self.ws
                    .flush_ignore_closed()
                    .await
                    .map_err(Error::PingPong)?;
                Ok(false)
            }
            Message::Pong(_data) => {
                trace!("received pong");
                Ok(false)
            }
            Message::Close(_) => {
                debug!("received close");
                Ok(true)
            }
            Message::Text(text) => {
                debug!("received `Text` message: `{text}'");
                Err(Error::TextMessage)
            }
            Message::Frame(_) => {
                unreachable!("`Frame` message should not be received");
            }
        }
    }

    /// Process a stream frame
    /// Does the following:
    /// - If `flag` is `Syn`,
    ///   - Find an available `dport` and send a `Ack`.
    ///   - Create a new `MuxStream` and send it to the `stream_tx` channel.
    /// - If `flag` is `Ack`,
    ///   - Create a `MuxStream` and send it to the `stream_tx` channel.
    /// - Otherwise, we find the sender with the matching `dport` and
    ///   - Send the data to the sender.
    ///   - If the receiver is closed or the port does not exist, send back a
    ///     `Rst` frame.
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    async fn process_stream_frame(
        &self,
        stream_frame: StreamFrame,
        server_stream_tx: &mpsc::Sender<MuxStream>,
    ) -> Result<()> {
        let StreamFrame {
            dport: our_port,
            sport: their_port,
            flag,
            mut data,
        } = stream_frame;
        let send_rst = || async {
            self.ws
                .send_with(|| StreamFrame::new_rst(our_port, their_port).into())
                .await
                .map_err(Error::SendStreamFrame)
        };
        match flag {
            StreamFlag::Syn => {
                if self.role == Role::Client {
                    return Err(Error::ClientReceivedSyn);
                }
                // Decode Syn handshake
                if data.remaining() < 10 {
                    return Err(frame::Error::FrameTooShort.into());
                }
                let peer_rwnd = data.get_u64();
                let dest_port = data.get_u16();
                let dest_host = data;
                // "we" is `role == Server`
                // "they" is `role == Client`
                self.server_new_stream(
                    our_port,
                    their_port,
                    dest_host,
                    dest_port,
                    peer_rwnd,
                    server_stream_tx,
                )
                .await?;
            }
            StreamFlag::SynAck => {
                if self.role == Role::Server {
                    return Err(Error::ServerReceivedSynAck);
                }
                if data.remaining() < 8 {
                    return Err(frame::Error::FrameTooShort.into());
                }
                // Decode `SynAck` handshake
                let peer_rwnd = data.get_u64();
                // "we" is `role == Client`
                // "they" is `role == Server`
                self.client_new_stream(our_port, their_port, peer_rwnd)
                    .await?;
            }
            StreamFlag::Ack => {
                trace!("received `Ack` for {our_port}");
                if data.remaining() < 8 {
                    return Err(frame::Error::FrameTooShort.into());
                }
                let peer_processed = data.get_u64();
                debug!("peer processed {peer_processed} frames");
                let streams = self.streams.read().await;
                if let Some(MuxStreamSlot::Established(stream_data)) = streams.get(&our_port) {
                    // Atomic ordering: as long as the value is incremented atomically,
                    // whether a writer sees the new value or the old value is not
                    // important. If it sees the old value and decides to return
                    // `Poll::Pending`, it will be woken up by the `Waker` anyway.
                    stream_data
                        .psh_send_remaining
                        .fetch_add(peer_processed, Ordering::Relaxed);
                    stream_data.writer_waker.wake();
                } else {
                    // the port does not exist
                    drop(streams);
                    send_rst().await?;
                }
            }
            StreamFlag::Rst => {
                // `true` because we don't want to reply `Rst` with `Rst`.
                self.close_port(our_port, their_port, true).await;
            }
            StreamFlag::Fin => {
                if let Some(MuxStreamSlot::Established(stream_data)) =
                    self.streams.read().await.get(&our_port)
                {
                    // Make sure the user receives `EOF`.
                    stream_data.sender.send(Bytes::new()).await.ok();
                }
                // And our end can still send
            }
            StreamFlag::Psh => {
                if let Some(MuxStreamSlot::Established(stream_data)) =
                    self.streams.read().await.get(&our_port)
                {
                    if stream_data.sender.send(data).await.is_ok() {
                        // The data is sent successfully
                        return Ok(());
                    }
                    // Else, the corresponding `MuxStream` is dropped
                    // let it fall through to send `Rst`.
                    // The job to remove the port from the map is done by `close_port_task`,
                    // so not being able to send is the same as not finding the port;
                    // just timing is different.
                    trace!("dropped `MuxStream` not yet removed from the map");
                }
                // The port does not exist
                send_rst().await?;
            }
        }
        Ok(())
    }

    /// Create a new `MuxStream`, add it to the map, and send a `SynAck` frame.
    /// If `our_port` is 0, a new port will be allocated.
    #[inline]
    async fn server_new_stream(
        &self,
        our_port: u16,
        their_port: u16,
        dest_host: Bytes,
        dest_port: u16,
        peer_rwnd: u64,
        server_stream_tx: &mpsc::Sender<MuxStream>,
    ) -> Result<()> {
        assert_eq!(self.role, Role::Server);
        // `tx` is our end, `rx` is the user's end
        let (frame_tx, frame_rx) = mpsc::channel(config::STREAM_FRAME_BUFFER_SIZE);
        let can_write = Arc::new(AtomicBool::new(true));
        let psh_send_remaining = Arc::new(AtomicU64::new(peer_rwnd));
        let writer_waker = Arc::new(AtomicWaker::new());
        // Save the TX end of the stream so we can write to it when subsequent frames arrive
        let mut streams = self.streams.write().await;
        let our_port = if our_port == 0 {
            // Allocate a new port
            let result = u16::next_available_key(&streams);
            trace!("port {our_port} allocated");
            result
        } else {
            // Check if the port is available
            if streams.contains_key(&our_port) {
                return Err(Error::InvalidSynPort(our_port));
            }
            our_port
        };
        streams.insert(
            our_port,
            MuxStreamSlot::Established(MuxStreamData {
                sender: frame_tx,
                can_write: can_write.dupe(),
                psh_send_remaining: psh_send_remaining.dupe(),
                writer_waker: writer_waker.dupe(),
            }),
        );
        drop(streams);
        let stream = MuxStream {
            frame_rx,
            our_port,
            their_port,
            dest_host,
            dest_port,
            can_write,
            psh_send_remaining,
            psh_recvd_since: AtomicU64::new(0),
            ack_tx: self.ack_tx.dupe(),
            writer_waker,
            buf: Bytes::new(),
            ws: self.ws.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
        };
        // Send a `SynAck`
        // Make sure `SynAck` is sent before the stream is sent to the user
        // so that the stream is `Established` when the user uses it.
        trace!("sending `SynAck`");
        self.ws
            .send_with(|| StreamFrame::new_synack(our_port, their_port, config::RWND).into())
            .await
            .map_err(Error::SendStreamFrame)?;
        // At the server side, we use `server_stream_tx` to send the new stream to the
        // user.
        trace!("sending stream to user");
        // This goes to the user
        server_stream_tx
            .send(stream)
            .await
            .map_err(|_| Error::SendStreamToClient)?;
        Ok(())
    }

    /// Create a new `MuxStream` and change the state of the port to `Established`.
    #[inline]
    async fn client_new_stream(
        &self,
        our_port: u16,
        their_port: u16,
        peer_rwnd: u64,
    ) -> Result<()> {
        assert_eq!(self.role, Role::Client);
        // `tx` is our end, `rx` is the user's end
        let (frame_tx, frame_rx) = mpsc::channel(config::STREAM_FRAME_BUFFER_SIZE);
        let can_write = Arc::new(AtomicBool::new(true));
        let psh_send_remaining = Arc::new(AtomicU64::new(peer_rwnd));
        let writer_waker = Arc::new(AtomicWaker::new());
        let stream_data = MuxStreamData {
            sender: frame_tx,
            can_write: can_write.dupe(),
            psh_send_remaining: psh_send_remaining.dupe(),
            writer_waker: writer_waker.dupe(),
        };
        let stream = MuxStream {
            frame_rx,
            our_port,
            their_port,
            dest_host: Bytes::new(),
            dest_port: 0,
            can_write,
            psh_send_remaining,
            psh_recvd_since: AtomicU64::new(0),
            ack_tx: self.ack_tx.dupe(),
            writer_waker,
            buf: Bytes::new(),
            ws: self.ws.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
        };
        // Save the TX end of the stream so we can write to it when subsequent frames arrive
        let mut streams = self.streams.write().await;
        assert_ne!(our_port, 0);
        let entry = streams.get_mut(&our_port).ok_or(Error::BogusSynAck)?;
        // Change the state of the port to `Established`
        let Some(sender) = entry.establish(stream_data) else {
            return Err(Error::BogusSynAck);
        };
        drop(streams);
        // Send the stream to the user
        // At the client side, we use the associated oneshot channel to send the new stream
        trace!("sending stream to user");
        sender.send(stream).map_err(|_| Error::SendStreamToClient)?;
        Ok(())
    }

    /// Close a port. That is, send `Rst` if `Fin` is not sent,
    /// and remove it from the map.
    #[tracing::instrument(skip_all, level = "debug")]
    #[inline]
    async fn close_port(&self, our_port: u16, their_port: u16, inhibit_rst: bool) {
        // Free the port for reuse
        if let Some(MuxStreamSlot::Established(stream_data)) =
            self.streams.write().await.remove(&our_port)
        {
            // Make sure the user receives `EOF`.
            stream_data.sender.send(Bytes::new()).await.ok();
            // Atomic ordering:
            // Load part:
            // If the user calls `poll_shutdown`, but we see `true` here,
            // the other end will receive a bogus `Rst` frame, which is fine.
            // Store part:
            // It does not matter whether the user calls `poll_shutdown` or not,
            // the stream is shut down and the final value of `can_write` is `false`.
            let old = stream_data.can_write.swap(false, Ordering::Relaxed);
            if old && !inhibit_rst {
                // If the user did not call `poll_shutdown`, we need to send a `Rst` frame
                self.ws
                    .send_with(|| StreamFrame::new_rst(our_port, their_port).into())
                    .await
                    .ok();
            }
            // If there is a writer waiting for `Ack`, wake it up because it will never receive one.
            // Waking it here and the user should receive a `BrokenPipe` error.
            stream_data.writer_waker.wake();
        }
        debug!("freed connection {our_port} -> {their_port}");
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
