//! Client side of the multiplexor
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::config;
use super::dupe::Dupe;
use super::frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
use super::locked_sink::LockedWebSocket;
use super::stream::MuxStream;
use super::{Error, IntKey, Result, Role};
use crate::ws::{Message, WebSocketStream};
use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::MissedTickBehavior;
use tracing::{debug, trace, warn};

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
pub enum MuxStreamSlot<S> {
    /// The stream is requested by the `client`.
    Requested(oneshot::Sender<MuxStream<S>>),
    /// The stream is established.
    Established(MuxStreamData),
}

impl<S> MuxStreamSlot<S> {
    /// Take the sender and set the slot to `Established`.
    /// Returns `None` if the slot is already established.
    pub fn establish(&mut self, data: MuxStreamData) -> Option<oneshot::Sender<MuxStream<S>>> {
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

/// Multiplexor inner
pub struct MultiplexorInner<S> {
    /// The role of this multiplexor
    pub role: Role,
    /// The underlying `Sink + Stream` of messages.
    pub ws: LockedWebSocket<S>,
    /// Interval between keepalive `Ping`s
    pub keepalive_interval: Option<std::time::Duration>,
    /// Open stream channels: our_port -> `MuxStreamData`
    pub streams: Arc<RwLock<HashMap<u16, MuxStreamSlot<S>>>>,
    /// Channel for notifying the task of a dropped `MuxStream`
    /// (in the form (our_port, their_port)).
    /// Sending (0, _) means that the multiplexor is being dropped and the
    /// task should exit.
    /// The reason we need `their_port` is to ensure the connection is `Rst`ed
    /// if the user did not call `poll_shutdown` on the `MuxStream`.
    pub dropped_ports_tx: mpsc::UnboundedSender<(u16, u16)>,
    /// Channel for queuing `Ack` frames to be sent
    /// (in the form (our_port, their_port, psh_recvd_since)).
    pub ack_tx: mpsc::UnboundedSender<(u16, u16, u64)>,
}

impl<S> std::fmt::Debug for MultiplexorInner<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexorInner")
            .field("role", &self.role)
            .field("keepalive_interval", &self.keepalive_interval)
            .finish_non_exhaustive()
    }
}

impl<S> Dupe for MultiplexorInner<S> {
    #[inline]
    fn dupe(&self) -> Self {
        Self {
            role: self.role,
            ws: self.ws.dupe(),
            keepalive_interval: self.keepalive_interval,
            streams: self.streams.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
            ack_tx: self.ack_tx.dupe(),
        }
    }
}

impl<S: WebSocketStream> MultiplexorInner<S> {
    /// Processing task
    /// Does the following:
    /// - Receives messages from `WebSocket` and processes them
    /// - Sends received datagrams to the `datagram_tx` channel
    /// - Sends received streams to the appropriate handler
    /// - Responds to ping/pong messages
    // It doesn't make sense to return a `Result` here because we can't propagate
    // the error to the user from a spawned task.
    // Instead, the user will notice when `rx` channels return `None`.
    #[tracing::instrument(skip_all, level = "trace")]
    pub async fn task(
        mut self,
        datagram_tx: mpsc::Sender<DatagramFrame>,
        server_stream_tx: mpsc::Sender<MuxStream<S>>,
        dropped_ports_rx: mpsc::UnboundedReceiver<(u16, u16)>,
        ack_rx: mpsc::UnboundedReceiver<(u16, u16, u64)>,
    ) -> Result<()> {
        let result = tokio::try_join!(
            self.keepalive_task(),
            self.process_messages_task(datagram_tx, server_stream_tx),
            self.close_port_task(dropped_ports_rx),
            self.send_ack_task(ack_rx),
        );
        self.shutdown().await;
        result.map(|_| ())
    }

    /// Keepalive subtask
    async fn keepalive_task(&self) -> Result<()> {
        if let Some(keepalive_interval) = self.keepalive_interval {
            let mut interval = tokio::time::interval(keepalive_interval);
            // If we missed a tick, it is probably doing networking, so we don't need to
            // make up for it.
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                trace!("sending ping");
                self.ws
                    .send_with(|| Message::Ping(vec![]))
                    .await
                    .map_err(Error::PingPong)?;
            }
        } else {
            futures_util::future::pending::<()>().await;
            unreachable!("`futures_util::future::pending` never resolves")
        }
    }

    /// Process closed ports subtask
    async fn close_port_task(
        &self,
        mut dropped_ports_rx: mpsc::UnboundedReceiver<(u16, u16)>,
    ) -> Result<()> {
        while let Some((our_port, their_port)) = dropped_ports_rx.recv().await {
            if our_port == 0 {
                debug!("mux dropped");
                break;
            }
            self.close_port(our_port, their_port, false).await;
        }
        // Only happens when the last sender (i.e. `dropped_ports_tx` in `MultiplexorInner`)
        // is dropped or when the mux is dropped.
        Ok(())
    }
    /// Send `Ack` subtask
    async fn send_ack_task(
        &self,
        mut ack_rx: mpsc::UnboundedReceiver<(u16, u16, u64)>,
    ) -> Result<()> {
        while let Some((our_port, their_port, psh_recvd_since)) = ack_rx.recv().await {
            trace!("sending `Ack` for port {}", our_port);
            self.ws
                .send_with(|| StreamFrame::new_ack(our_port, their_port, psh_recvd_since).into())
                .await
                .map_err(Error::SendStreamFrame)?;
        }
        // Only happens when the last sender (i.e. `ack_tx` in `MultiplexorInner`)
        // is dropped.
        Ok(())
    }

    /// Message processing subtask
    async fn process_messages_task(
        &self,
        datagram_tx: mpsc::Sender<DatagramFrame>,
        server_stream_tx: mpsc::Sender<MuxStream<S>>,
    ) -> Result<()> {
        while let Some(msg) = self.ws.next().await {
            let msg = msg.map_err(Error::Next)?;
            trace!("received message length = {}", msg.len());
            // Messages cannot be processed concurrently
            // because doing so will break stream ordering
            if self
                .process_message(msg, &datagram_tx, &server_stream_tx)
                .await?
            {
                // `Close` message was received, so we can exit
                break;
            }
        }
        Ok(())
    }
}

impl<S: WebSocketStream> MultiplexorInner<S> {
    /// Process an incoming message
    /// Returns `Ok(true)` if a `Close` message was received.
    #[tracing::instrument(skip_all, level = "debug")]
    #[inline]
    async fn process_message(
        &self,
        msg: Message,
        datagram_tx: &mpsc::Sender<DatagramFrame>,
        server_stream_tx: &mpsc::Sender<MuxStream<S>>,
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
        server_stream_tx: &mpsc::Sender<MuxStream<S>>,
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
                    return Err(super::frame::Error::FrameTooShort.into());
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
                    return Err(super::frame::Error::FrameTooShort.into());
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
                    return Err(super::frame::Error::FrameTooShort.into());
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
        server_stream_tx: &mpsc::Sender<MuxStream<S>>,
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
    pub async fn close_port(&self, our_port: u16, their_port: u16, inhibit_rst: bool) {
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

    /// Should really only be called when the mux is dropped.
    #[tracing::instrument(skip_all, level = "trace")]
    async fn shutdown(&mut self) {
        debug!("closing all connections");
        for (_, stream_data) in self.streams.write().await.drain() {
            // Make sure `self.streams` is not locked in loop body
            if let MuxStreamSlot::Established(stream_data) = stream_data {
                // Make sure the user receives `EOF`.
                stream_data.sender.send(Bytes::new()).await.ok();
                // Prevent the user from writing
                // Atomic ordering: It does not matter whether the user calls `poll_shutdown` or not,
                // the stream is shut down and the final value of `can_write` is `false`.
                stream_data.can_write.store(false, Ordering::Relaxed);
                // If there is a writer waiting for `Ack`, wake it up because it will never receive one.
                // Waking it here and the user should receive a `BrokenPipe` error.
                stream_data.writer_waker.wake();
            }
            // else: just drop the sender
        }
        // This also effectively `Rst`s all streams on the other side
        self.ws.close().await.ok();
        self.ws.flush_ignore_closed().await.ok();
        // Intentionally flushing twice: this time we should get a `ConnectionClosed` error
        self.ws.flush_ignore_closed().await.ok();
    }
}
