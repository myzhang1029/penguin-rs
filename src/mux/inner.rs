//! Client side of the multiplexor
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::config;
use super::dupe::Dupe;
use super::frame::{DatagramFrame, Frame, StreamFrame, StreamOpCode};
use super::stream::MuxStream;
use super::{Error, IntKey, Result};
use crate::frame::{FinalizedFrame, StreamPayload};
use crate::timing::{OptionalDuration, OptionalInterval};
use crate::ws::{Message, WebSocketStream};
use bytes::Bytes;
use futures_util::future::poll_fn;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt, task::AtomicWaker};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::Poll;
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
    psh_send_remaining: Arc<AtomicU32>,
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
    /// Where tasks queue frames to be sent
    pub tx_frame_tx: mpsc::UnboundedSender<FinalizedFrame>,
    /// Interval between keepalive `Ping`s
    pub keepalive_interval: OptionalDuration,
    /// Open stream channels: `our_port` -> `MuxStreamData`
    pub streams: Arc<RwLock<HashMap<u16, MuxStreamSlot>>>,
    /// Channel for notifying the task of a dropped `MuxStream`
    /// (in the form (`our_port`, `their_port`)).
    /// Sending (0, _) means that the multiplexor is being dropped and the
    /// task should exit.
    /// The reason we need `their_port` is to ensure the connection is `Rst`ed
    /// if the user did not call `poll_shutdown` on the `MuxStream`.
    pub dropped_ports_tx: mpsc::UnboundedSender<(u16, u16)>,
    /// Default threshold for `Ack` replies. See [`MuxStream`] for more details.
    pub default_rwnd_threshold: u32,
}

impl std::fmt::Debug for MultiplexorInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexorInner")
            .field("keepalive_interval", &self.keepalive_interval)
            .field("default_rwnd_threshold", &self.default_rwnd_threshold)
            .finish_non_exhaustive()
    }
}

impl Dupe for MultiplexorInner {
    #[inline]
    fn dupe(&self) -> Self {
        Self {
            tx_frame_tx: self.tx_frame_tx.dupe(),
            keepalive_interval: self.keepalive_interval,
            streams: self.streams.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
            default_rwnd_threshold: self.default_rwnd_threshold,
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
    pub async fn task<S: WebSocketStream>(self, ws: S, taskdata: super::TaskData) -> Result<()> {
        let super::TaskData {
            datagram_tx,
            con_recv_stream_tx,
            mut tx_frame_rx,
            bnd_request_tx,
            mut dropped_ports_rx,
        } = taskdata;
        // Split the `WebSocket` stream into a `Sink` and `Stream` so we can process them concurrently
        let (mut ws_sink, mut ws_stream) = ws.split();
        // This is modified from an unrolled version of `tokio::try_join!` with our custom cancellation
        // logic and to make sure that tasks are not cancelled at random points.
        let (e, should_drain_frame_rx) = {
            let mut process_dropped_ports_task_fut =
                pin!(self.process_dropped_ports_task(&mut dropped_ports_rx));
            let mut process_frame_recv_task_fut =
                pin!(self.process_frame_recv_task(&mut tx_frame_rx, &mut ws_sink));
            let mut process_ws_next_fut = pin!(self.process_ws_next(
                &mut ws_stream,
                &datagram_tx,
                &con_recv_stream_tx,
                bnd_request_tx.as_ref()
            ));
            poll_fn(|cx| {
                if let Poll::Ready(r) = process_dropped_ports_task_fut.as_mut().poll(cx) {
                    let should_drain_frame_rx = r.is_ok();
                    return Poll::Ready((r, should_drain_frame_rx));
                }
                if let Poll::Ready(r) = process_ws_next_fut.as_mut().poll(cx) {
                    return Poll::Ready((r, false));
                }
                if let Poll::Ready(r) = process_frame_recv_task_fut.as_mut().poll(cx) {
                    return Poll::Ready((r, false));
                }
                Poll::Pending
            })
            .await
        };
        self.wind_down(
            should_drain_frame_rx,
            ws_sink
                .reunite(ws_stream)
                .expect("Failed to reunite sink and stream (this is a bug)"),
            datagram_tx,
            con_recv_stream_tx,
            tx_frame_rx,
        )
        .await?;
        e
    }

    /// Process dropped ports from the `dropped_ports_rx` channel.
    /// Returns when either [`MultiplexorInner`] or [`Multiplexor`] itself is dropped.
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    pub async fn process_dropped_ports_task(
        &self,
        dropped_ports_rx: &mut mpsc::UnboundedReceiver<(u16, u16)>,
    ) -> Result<()> {
        while let Some((our_port, their_port)) = dropped_ports_rx.recv().await {
            if our_port == 0 {
                // `our_port` is `0`, which means the multiplexor itself is being dropped.
                debug!("mux dropped");
                break;
            }
            self.close_port(our_port, their_port, false).await;
        }
        // None: only happens when the last sender (i.e. `dropped_ports_tx` in `MultiplexorInner`)
        // is dropped,
        // which can be combined with the case when the multiplexor itself is being dropped.
        // If this returns, our end is dropped, but we should still try to flush everything we
        // already have in the `frame_rx` before closing.
        // we should make some attempt to flush `frame_rx` before exiting.
        Ok(())
    }

    /// Poll `frame_rx` and process the frame received and send keepalive pings as needed.
    /// It never returns an `Ok(())`, and propagates errors from the `Sink` processing.
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    async fn process_frame_recv_task<S: WebSocketStream>(
        &self,
        frame_rx: &mut mpsc::UnboundedReceiver<FinalizedFrame>,
        ws_sink: &mut SplitSink<S, Message>,
    ) -> Result<()> {
        let mut interval = OptionalInterval::from(self.keepalive_interval);
        // If we missed a tick, it is probably doing networking, so we don't need to
        // make up for it.
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    trace!("sending keepalive ping");
                    ws_sink.send(Message::Ping(Bytes::new())).await.map_err(Box::new)?;
                }
                Some(frame) = frame_rx.recv() => {
                    // Buffer `Psh` frames, and flush everything else immediately
                    if frame.is_stream_with_opcode(StreamOpCode::Psh) {
                        ws_sink.feed(Message::Binary(frame.into())).await
                    } else if frame.is_empty() {
                        // Flush
                        ws_sink.flush().await
                    } else {
                        ws_sink.send(Message::Binary(frame.into())).await
                    }
                    .map_err(Box::new)?;
                }
                else => {
                    // Only happens when `frame_rx` is closed
                    // cannot happen because `Self` contains one sender unless
                    // there is a bug in our code or `tokio` itself.
                    panic!("frame receiver should not be closed (this is a bug)");
                }
            }
        }
        // This returns if we cannot sink or cannot receive from `frame_rx` anymore,
        // in either case, it does not make sense to check `frame_rx`.
    }

    /// Process the return value of `ws.next()`
    /// Returns `Ok(())` when a `Close` message was received or the WebSocket was otherwise closed by the peer.
    #[tracing::instrument(skip_all, level = "trace")]
    async fn process_ws_next<S: WebSocketStream>(
        &self,
        ws_stream: &mut SplitStream<S>,
        datagram_tx: &mpsc::Sender<DatagramFrame<'static>>,
        con_recv_stream_tx: &mpsc::Sender<MuxStream>,
        bnd_request_tx: Option<&mpsc::Sender<(Bytes, u16)>>,
    ) -> Result<()> {
        loop {
            match ws_stream.next().await {
                Some(Ok(msg)) => {
                    trace!("received message length = {}", msg.len());
                    if self
                        .process_message(msg, datagram_tx, con_recv_stream_tx, bnd_request_tx)
                        .await?
                    {
                        // Received a `Close` message
                        break Ok(());
                    }
                }
                Some(Err(e)) => {
                    error!("Failed to receive message from WebSocket: {e}");
                    break Err(Error::WebSocket(Box::new(e)));
                }
                None => {
                    debug!("WebSocket closed by peer");
                    break Ok(());
                }
            }
        }
        // In this case, peer already requested close, so we should not attempt to send any more frames.
    }

    /// Wind down the multiplexor task.
    #[tracing::instrument(skip_all, level = "trace")]
    async fn wind_down<S: WebSocketStream>(
        &self,
        should_drain_frame_rx: bool,
        mut ws: S,
        datagram_tx: mpsc::Sender<DatagramFrame<'static>>,
        con_recv_stream_tx: mpsc::Sender<MuxStream>,
        mut frame_rx: mpsc::UnboundedReceiver<FinalizedFrame>,
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
                if let Err(e) = ws.feed(Message::Binary(frame.into())).await {
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
        // The above line only closes the `Sink`. Before we terminate connections,
        // we dispatch the remaining frames in the `Source` to our streams.
        while let Some(Ok(msg)) = ws.next().await {
            debug!(
                "processing remaining message after closure length = {}",
                msg.len()
            );
            self.process_message(msg, &datagram_tx, &con_recv_stream_tx, None)
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
}

impl MultiplexorInner {
    /// Process an incoming message
    /// Returns `Ok(true)` if a `Close` message was received.
    #[tracing::instrument(skip_all, level = "debug")]
    #[inline]
    async fn process_message(
        &self,
        msg: Message,
        datagram_tx: &mpsc::Sender<DatagramFrame<'static>>,
        con_recv_stream_tx: &mpsc::Sender<MuxStream>,
        bnd_request_tx: Option<&mpsc::Sender<(Bytes, u16)>>,
    ) -> Result<bool> {
        match msg {
            Message::Binary(data) => {
                let frame = data.try_into()?;
                match frame {
                    Frame::Datagram(datagram_frame) => {
                        trace!("received datagram frame: {datagram_frame:?}");
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
                        trace!("received stream frame: {stream_frame:?}");
                        self.process_stream_frame(stream_frame, con_recv_stream_tx, bnd_request_tx)
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
    /// - If `flag` is `Con`,
    ///   - Find an available `dport` and send a `Ack`.
    ///   - Create a new `MuxStream` and send it to the `stream_tx` channel.
    /// - If `flag` is `Ack`,
    ///   - Existing stream with the matching `dport`: increment the `psh_send_remaining` counter.
    ///   - New stream: create a `MuxStream` and send it to the `stream_tx` channel.
    /// - If `flag` is `Bnd`,
    ///   - Send the request to the user if we are accepting `Bnd` requests and reply `Fin`.
    ///   - Otherwise, send back a `Rst` frame.
    /// - Otherwise, we find the sender with the matching `dport` and
    ///   - Send the data to the sender.
    ///   - If the receiver is closed or the port does not exist, send back a
    ///     `Rst` frame.
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    async fn process_stream_frame(
        &self,
        stream_frame: StreamFrame<'static>,
        con_recv_stream_tx: &mpsc::Sender<MuxStream>,
        bnd_request_tx: Option<&mpsc::Sender<(Bytes, u16)>>,
    ) -> Result<()> {
        let StreamFrame {
            dport: our_port,
            sport: their_port,
            payload,
        } = stream_frame;
        let send_rst = async {
            self.tx_frame_tx
                .send(StreamFrame::new_rst(our_port, their_port).finalize())
                .ok()
            // Error only happens if the `frame_tx` channel is closed, at which point
            // we don't care about sending a `Rst` frame anymore
        };
        match payload {
            StreamPayload::Con {
                rwnd: peer_rwnd,
                target_host,
                target_port,
            } => {
                if our_port != 0 {
                    error!("Received `Con` with non-zero dport {our_port}");
                    // just bail because this is a protocol violation
                    return Err(Error::ConWithDport(our_port));
                }
                // In this case, `target_host` is always owned already
                self.con_recv_new_stream(
                    their_port,
                    Bytes::from(target_host.into_owned()),
                    target_port,
                    peer_rwnd,
                    con_recv_stream_tx,
                )
                .await?;
            }
            StreamPayload::Ack(payload) => {
                trace!("received `Ack` for {our_port}");
                // Two cases:
                // 1. Peer acknowledged `Con`
                // 2. Peer acknowledged some `Psh` frames
                let action = self.streams.read().get(&our_port).map(|slot| {
                    match slot {
                        MuxStreamSlot::Established(stream_data) => {
                            // We have an established stream, so process the `Ack`
                            // Atomic ordering: as long as the value is incremented atomically,
                            // whether a writer sees the new value or the old value is not
                            // important. If it sees the old value and decides to return
                            // `Poll::Pending`, it will be woken up by the `Waker` anyway.
                            stream_data
                                .psh_send_remaining
                                .fetch_add(payload, Ordering::Relaxed);
                            stream_data.writer_waker.wake();
                            true
                        }
                        MuxStreamSlot::Requested(_) => false,
                    }
                });
                match action {
                    Some(true) => debug!("peer processed {payload} frames"),
                    Some(false) => {
                        debug!("new stream {our_port} -> {their_port} with peer rwnd {payload}");
                        self.ack_recv_new_stream(our_port, their_port, payload)?;
                    }
                    None => {
                        trace!("port {our_port} does not exist, sending `Rst`");
                        send_rst.await;
                    }
                }
            }
            StreamPayload::Fin => {
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
            StreamPayload::Rst => {
                debug!("`Rst` for {our_port}");
                // `true` because we don't want to reply `Rst` with `Rst`.
                self.close_port(our_port, their_port, true).await;
            }
            StreamPayload::Psh(data) => {
                let sender = if let Some(MuxStreamSlot::Established(stream_data)) =
                    self.streams.read().get(&our_port)
                {
                    Some(stream_data.sender.dupe())
                } else {
                    None
                };
                // This part is refactored out so that we don't hold the lock across await
                if let Some(sender) = sender {
                    // In this case, `data` is always owned already
                    match sender.try_send(Bytes::from(data.into_owned())) {
                        Err(TrySendError::Full(_)) => {
                            // Peer does not respect the `rwnd` limit, this should not happen in normal circumstances.
                            // let it fall through to send `Rst`.
                            warn!(
                                "Peer does not respect `rwnd` limit, dropping stream {our_port} -> {their_port}"
                            );
                            send_rst.await;
                        }
                        Err(TrySendError::Closed(_)) => {
                            // Else, the corresponding `MuxStream` is dropped
                            // The job to remove the port from the map is done by `close_port_task`,
                            // so not being able to send is the same as not finding the port;
                            // just timing is different.
                            trace!("dropped `MuxStream` not yet removed from the map");
                        }
                        Ok(()) => (),
                    }
                } else {
                    warn!("Bogus `Psh` frame {their_port} -> {our_port}");
                    send_rst.await;
                }
            }
            StreamPayload::Bnd {
                target_host,
                target_port,
            } => {
                if let Some(sender) = bnd_request_tx {
                    let target_host = Bytes::from(target_host.into_owned());
                    debug!("received `Bnd` request: [{target_host:?}]:{target_port}");
                    if let Err(e) = sender.send((target_host, target_port)).await {
                        warn!("Failed to send `Bnd` request: {e}");
                    }
                    self.tx_frame_tx
                        .send(StreamFrame::new_fin(our_port, their_port).finalize())
                        .ok();
                } else {
                    trace!("received `Bnd` request but not accepting, sending `Rst`");
                    self.tx_frame_tx
                        .send(StreamFrame::new_rst(our_port, their_port).finalize())
                        .ok();
                }
            }
        }
        Ok(())
    }

    /// Create a new stream because this end received a `Con` frame.
    /// Create a new `MuxStream`, add it to the map, and send an `Ack` frame.
    /// If `our_port` is 0, a new port will be allocated.
    #[inline]
    async fn con_recv_new_stream(
        &self,
        their_port: u16,
        dest_host: Bytes,
        dest_port: u16,
        peer_rwnd: u32,
        con_recv_stream_tx: &mpsc::Sender<MuxStream>,
    ) -> Result<()> {
        // `tx` is our end, `rx` is the user's end
        let (frame_tx, frame_rx) = mpsc::channel(config::RWND_USIZE);
        let can_write = Arc::new(AtomicBool::new(true));
        let psh_send_remaining = Arc::new(AtomicU32::new(peer_rwnd));
        let writer_waker = Arc::new(AtomicWaker::new());
        // Scope the following block to reduce locked time
        let our_port = {
            // Save the TX end of the stream so we can write to it when subsequent frames arrive
            let mut streams = self.streams.write();
            // Allocate a new port
            let our_port = u16::next_available_key(&streams);
            trace!("port {our_port} allocated");
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
            psh_recvd_since: AtomicU32::new(0),
            writer_waker,
            buf: Bytes::new(),
            frame_tx: self.tx_frame_tx.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
            rwnd_threshold: self.default_rwnd_threshold.min(peer_rwnd),
        };
        // Send a `Ack`
        // Make sure `Ack` is sent before the stream is sent to the user
        // so that the stream is `Established` when the user uses it.
        trace!("sending `Ack`");
        self.tx_frame_tx
            .send(StreamFrame::new_ack(our_port, their_port, config::RWND).finalize())
            .map_err(|_| Error::Closed)?;
        // At the con_recv side, we use `con_recv_stream_tx` to send the new stream to the
        // user.
        trace!("sending stream to user");
        // This goes to the user
        con_recv_stream_tx
            .send(stream)
            .await
            .map_err(|_| Error::SendStreamToClient)?;
        Ok(())
    }

    /// Create a new `MuxStream` by finalizing a Con/Ack handshsake and
    /// change the state of the port to `Established`.
    #[inline]
    fn ack_recv_new_stream(&self, our_port: u16, their_port: u16, peer_rwnd: u32) -> Result<()> {
        // `tx` is our end, `rx` is the user's end
        let (frame_tx, frame_rx) = mpsc::channel(config::RWND_USIZE);
        let can_write = Arc::new(AtomicBool::new(true));
        let psh_send_remaining = Arc::new(AtomicU32::new(peer_rwnd));
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
            psh_recvd_since: AtomicU32::new(0),
            writer_waker,
            buf: Bytes::new(),
            frame_tx: self.tx_frame_tx.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
            rwnd_threshold: self.default_rwnd_threshold.min(peer_rwnd),
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
    async fn close_port(&self, our_port: u16, their_port: u16, inhibit_rst: bool) {
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
                self.tx_frame_tx
                    .send(StreamFrame::new_rst(our_port, their_port).finalize())
                    .ok();
            }
            // If there is a writer waiting for `Ack`, wake it up because it will never receive one.
            // Waking it here and the user should receive a `BrokenPipe` error.
            stream_data.writer_waker.wake();
        }
        debug!("freed connection {our_port} -> {their_port}");
    }
}
