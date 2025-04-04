//! Client side of the multiplexor
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::config;
use super::dupe::Dupe;
use super::frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
use super::stream::MuxStream;
use super::{Error, IntKey, Result, Role};
use crate::timing::{OptionalDuration, OptionalInterval};
use crate::ws::{Message, WebSocketStream};
use bytes::{Buf, Bytes};
use futures_util::{task::AtomicWaker, SinkExt, StreamExt};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, trace, warn};

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

/// Multiplexor inner
pub struct MultiplexorInner {
    /// The role of this multiplexor
    pub role: Role,
    /// Where tasks queue frames to be sent
    pub frame_tx: mpsc::UnboundedSender<Frame>,
    /// Interval between keepalive `Ping`s
    pub keepalive_interval: OptionalDuration,
    /// Open stream channels: our_port -> `MuxStreamData`
    pub streams: Arc<RwLock<HashMap<u16, MuxStreamSlot>>>,
    /// Channel for notifying the task of a dropped `MuxStream`
    /// (in the form (our_port, their_port)).
    /// Sending (0, _) means that the multiplexor is being dropped and the
    /// task should exit.
    /// The reason we need `their_port` is to ensure the connection is `Rst`ed
    /// if the user did not call `poll_shutdown` on the `MuxStream`.
    pub dropped_ports_tx: mpsc::UnboundedSender<(u16, u16)>,
}

impl std::fmt::Debug for MultiplexorInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexorInner")
            .field("role", &self.role)
            .field("keepalive_interval", &self.keepalive_interval)
            .finish_non_exhaustive()
    }
}

impl Dupe for MultiplexorInner {
    #[inline]
    fn dupe(&self) -> Self {
        Self {
            role: self.role,
            frame_tx: self.frame_tx.dupe(),
            keepalive_interval: self.keepalive_interval,
            streams: self.streams.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
        }
    }
}

impl MultiplexorInner {
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
    pub async fn task<S: WebSocketStream>(
        self,
        mut ws: S,
        datagram_tx: mpsc::Sender<DatagramFrame>,
        con_recv_stream_tx: mpsc::Sender<MuxStream>,
        mut frame_rx: mpsc::UnboundedReceiver<Frame>,
        mut dropped_ports_rx: mpsc::UnboundedReceiver<(u16, u16)>,
    ) -> Result<()> {
        let mut interval = OptionalInterval::from(self.keepalive_interval);
        let mut should_drain_frame_rx = false;
        // If we missed a tick, it is probably doing networking, so we don't need to
        // make up for it.
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            trace!("multiplexor task loop");
            tokio::select! {
                // Keepalive task
                _ = interval.tick() => {
                    trace!("sending ping");
                    ws.send(Message::Ping(Bytes::new())).await?;
                }
                maybe_msg = ws.next() => {
                    if self.process_ws_next(
                        maybe_msg,
                        &datagram_tx,
                        &con_recv_stream_tx,
                    ).await? {
                        break;
                    }
                }
                // Process frames from the frame receiver
                maybe_frame = frame_rx.recv() => {
                    // cannot happen because `Self` contains one sender unless
                    // there is a bug in our code or `tokio` itself.
                    let frame = maybe_frame.expect("frame receiver should not be closed (this is a bug)");
                    ws.send(Message::Binary(frame.try_into()?)).await?;
                }
                req = dropped_ports_rx.recv() => {
                    if let Some((our_port, their_port)) = req {
                        if our_port != 0 {
                            self.close_port(our_port, their_port, false).await;
                            continue;
                        }
                        // else: `our_port` is `0`, which means the multiplexor itself is being dropped.
                        debug!("mux dropped");
                    }
                    // else: only happens when the last sender (i.e. `dropped_ports_tx` in `MultiplexorInner`)
                    // is dropped,
                    // which can be combined with the case when the multiplexor itself is being dropped.
                    // These are the only cases we should make some attempt to flush `frame_rx` before exiting.
                    should_drain_frame_rx = true;
                    break;
                }
            }
        }
        self.wind_down(
            should_drain_frame_rx,
            ws,
            datagram_tx,
            con_recv_stream_tx,
            frame_rx,
        )
        .await
    }

    /// Wind down the multiplexor task.
    #[tracing::instrument(skip_all, level = "trace")]
    async fn wind_down<S: WebSocketStream>(
        &self,
        should_drain_frame_rx: bool,
        mut ws: S,
        datagram_tx: mpsc::Sender<DatagramFrame>,
        server_stream_tx: mpsc::Sender<MuxStream>,
        mut frame_rx: mpsc::UnboundedReceiver<Frame>,
    ) -> Result<()> {
        debug!("closing all connections");
        // We first make sure the streams can no longer send
        for (_, stream_data) in self.streams.write().iter() {
            if let MuxStreamSlot::Established(stream_data) = stream_data {
                // Prevent the user from writing
                // Atomic ordering: It does not matter whether the user calls `poll_shutdown` or not,
                // the stream is shut down and the final value of `can_write` is `false`.
                stream_data.can_write.store(false, Ordering::Relaxed);
                // If there is a writer waiting for `Ack`, wake it up because it will never receive one.
                // Waking it here and the user should receive a `BrokenPipe` error.
                stream_data.writer_waker.wake();
            }
        }
        // Now if `should_drain_frame_rx` is `true`, we will process the remaining frames in `frame_rx`.
        // If it is `false`, then we reached here because the peer is now not interested
        // in our connection anymore, and we should just mind our own business and serve the connections
        // on our end.
        // We must use `try_recv` because, again, `Self` contains one sender.
        if should_drain_frame_rx {
            while let Ok(frame) = frame_rx.try_recv() {
                debug!("sending remaining frame after mux drop");
                if let Err(e) = ws.feed(Message::Binary(frame.try_into()?)).await {
                    warn!("Failed to send remaining frame after mux drop: {e}");
                    // Don't keep trying to send frames after an error
                    break;
                }
                // will be flushed in `ws.close()` anyways
                // ws.flush().await.ok();
            }
        }
        // This will flush the remaining frames already queued for sending as well
        ws.close().await.ok();
        // The above line only closes the `Sink``. Before we terminate connections,
        // we dispatch the remaining frames in the `Source` to our streams.
        while let Some(Ok(msg)) = ws.next().await {
            debug!(
                "processing remaining message after closure length = {}",
                msg.len()
            );
            self.process_message(msg, &datagram_tx, &server_stream_tx)
                .await?;
        }
        // Finally, we send EOF to all established streams.
        let senders = self
            .streams
            .write()
            .drain()
            .filter_map(|(_, stream_slot)| {
                if let MuxStreamSlot::Established(stream_data) = stream_slot {
                    Some(stream_data.sender)
                } else {
                    None
                    // else: just drop the sender for `Requested` slots, and the user
                    // will get `Error::Closed` from `client_new_stream_channel`
                }
            })
            .collect::<Vec<_>>();
        for sender in senders {
            sender.send(Bytes::new()).await.ok();
        }
        Ok(())
    }

    /// Process the return value of `ws.next()`
    /// Returns `Ok(true)` if a `Close` message was received or the WebSocket was otherwise closed by the peer.
    #[tracing::instrument(skip_all, level = "trace")]
    pub async fn process_ws_next(
        &self,
        maybe_msg: Option<std::result::Result<Message, crate::ws::Error>>,
        datagram_tx: &mpsc::Sender<DatagramFrame>,
        con_recv_stream_tx: &mpsc::Sender<MuxStream>,
    ) -> Result<bool> {
        match maybe_msg {
            Some(Ok(msg)) => {
                trace!("received message length = {}", msg.len());
                self.process_message(msg, datagram_tx, con_recv_stream_tx)
                    .await
            }
            Some(Err(e)) => {
                error!("Failed to receive message from WebSocket: {e}");
                Err(Error::WebSocket(e))
            }
            None => {
                debug!("WebSocket closed by peer");
                Ok(true)
            }
        }
    }

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
        let send_rst = async {
            self.frame_tx
                .send(StreamFrame::new_rst(our_port, their_port).into())
                .ok()
            // Error only happens if the `frame_tx` channel is closed, at which point
            // we don't care about sending a `Rst` frame anymore
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
                self.client_new_stream(our_port, their_port, peer_rwnd)?;
            }
            StreamFlag::Ack => {
                if data.remaining() < 8 {
                    return Err(super::frame::Error::FrameTooShort.into());
                }
                let peer_processed = data.get_u64();
                debug!("peer processed {peer_processed} frames");
                let port_exists = {
                    let streams = self.streams.read();
                    if let Some(MuxStreamSlot::Established(stream_data)) = streams.get(&our_port) {
                        // Atomic ordering: as long as the value is incremented atomically,
                        // whether a writer sees the new value or the old value is not
                        // important. If it sees the old value and decides to return
                        // `Poll::Pending`, it will be woken up by the `Waker` anyway.
                        stream_data
                            .psh_send_remaining
                            .fetch_add(peer_processed, Ordering::Relaxed);
                        stream_data.writer_waker.wake();
                        true
                    } else {
                        // the port does not exist
                        false
                    }
                };
                // This part is refactored out so that we don't hold the lock across await
                if !port_exists {
                    send_rst.await;
                }
            }
            StreamFlag::Rst => {
                debug!("`Rst` for {our_port}");
                // `true` because we don't want to reply `Rst` with `Rst`.
                self.close_port(our_port, their_port, true).await;
            }
            StreamFlag::Fin => {
                let sender = if let Some(MuxStreamSlot::Established(stream_data)) =
                    self.streams.read().get(&our_port)
                {
                    Some(stream_data.sender.dupe())
                } else {
                    None
                };
                // Make sure the user receives `EOF`.
                // This part is refactored out so that we don't hold the lock across await
                if let Some(sender) = sender {
                    sender.send(Bytes::new()).await.ok();
                } else {
                    warn!("Bogus `Fin` frame {their_port} -> {our_port}");
                }
                // And our end can still send
            }
            StreamFlag::Psh => {
                let sender = if let Some(MuxStreamSlot::Established(stream_data)) =
                    self.streams.read().get(&our_port)
                {
                    Some(stream_data.sender.dupe())
                } else {
                    None
                };
                // This part is refactored out so that we don't hold the lock across await
                if let Some(sender) = sender {
                    if sender.send(data).await.is_ok() {
                        // The data is sent successfully
                        return Ok(());
                    }
                    // Else, the corresponding `MuxStream` is dropped
                    // let it fall through to send `Rst`.
                    // The job to remove the port from the map is done by `close_port_task`,
                    // so not being able to send is the same as not finding the port;
                    // just timing is different.
                    trace!("dropped `MuxStream` not yet removed from the map");
                } else {
                    warn!("Bogus `Psh` frame {their_port} -> {our_port}");
                }
                // The port does not exist
                send_rst.await;
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
        // Scope the following block to reduce locked time
        let our_port = {
            // Save the TX end of the stream so we can write to it when subsequent frames arrive
            let mut streams = self.streams.write();
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
            our_port
        };
        let stream = MuxStream {
            frame_rx,
            our_port,
            their_port,
            dest_host,
            dest_port,
            can_write,
            psh_send_remaining,
            psh_recvd_since: AtomicU64::new(0),
            writer_waker,
            buf: Bytes::new(),
            frame_tx: self.frame_tx.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
        };
        // Send a `SynAck`
        // Make sure `SynAck` is sent before the stream is sent to the user
        // so that the stream is `Established` when the user uses it.
        trace!("sending `SynAck`");
        self.frame_tx
            .send(StreamFrame::new_synack(our_port, their_port, config::RWND).into())
            .map_err(|_| Error::Closed)?;
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
    fn client_new_stream(&self, our_port: u16, their_port: u16, peer_rwnd: u64) -> Result<()> {
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
            writer_waker,
            buf: Bytes::new(),
            frame_tx: self.frame_tx.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
        };
        // Save the TX end of the stream so we can write to it when subsequent frames arrive
        let mut streams = self.streams.write();
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
        let removed = self.streams.write().remove(&our_port);
        if let Some(MuxStreamSlot::Established(stream_data)) = removed {
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
                self.frame_tx
                    .send(StreamFrame::new_rst(our_port, their_port).into())
                    .ok();
            }
            // If there is a writer waiting for `Ack`, wake it up because it will never receive one.
            // Waking it here and the user should receive a `BrokenPipe` error.
            stream_data.writer_waker.wake();
        }
        debug!("freed connection {our_port} -> {their_port}");
    }
}
