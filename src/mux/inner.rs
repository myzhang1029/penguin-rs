//! Client side of the multiplexor
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::dupe::Dupe;
use crate::frame::{ConnectPayload, FinalizedFrame, Frame, Payload};
use crate::stream::MuxStream;
use crate::{BindRequest, Datagram, Message, config};
use crate::{Error, Result};
use bytes::Bytes;
use futures_util::task::AtomicWaker;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct EstablishedStreamData {
    /// Channel for sending data to `MuxStream`'s `AsyncRead`
    /// If `None`, we have received `Finish` from the peer but we can possibly still send data.
    sender: Option<mpsc::Sender<Bytes>>,
    /// Whether writes should succeed.
    /// There are two cases for `true`:
    /// 1. `Finish` has been sent.
    /// 2. The stream has been removed from `inner.streams`.
    // In general, our `Atomic*` types don't need more than `Relaxed` ordering
    // because we are not protecting memory accesses, but rather counting the
    // frames we have sent and received.
    pub finish_sent: Arc<AtomicBool>,
    /// Number of `Push` frames we are allowed to send before waiting for a `Acknowledge` frame.
    psh_send_remaining: Arc<AtomicU32>,
    /// Waker to wake up the task that sends frames because their `psh_send_remaining`
    /// has increased.
    pub writer_waker: Arc<AtomicWaker>,
}

#[derive(Debug)]
pub enum FlowSlot {
    /// A `Connect` frame was sent and waiting for the peer to `Acknowledge`.
    Requested(oneshot::Sender<Option<MuxStream>>),
    /// The stream is established.
    Established(EstablishedStreamData),
    /// A `Bind` request was sent and waiting for the peer to `Acknowledge` or `Reset`.
    BindRequested(oneshot::Sender<bool>),
}

impl FlowSlot {
    /// Take the sender and set the slot to `Established`.
    /// Returns `None` if the slot is already established.
    #[inline]
    pub fn establish(
        &mut self,
        data: EstablishedStreamData,
    ) -> Option<oneshot::Sender<Option<MuxStream>>> {
        // Make sure it is not replaced in the error case
        if matches!(self, Self::Established(_) | Self::BindRequested(_)) {
            error!("establishing an established or invalid slot");
            return None;
        }
        let sender = match std::mem::replace(self, Self::Established(data)) {
            Self::Requested(sender) => sender,
            Self::Established(_) | Self::BindRequested(_) => unreachable!(),
        };
        Some(sender)
    }
    /// If the slot is established, send data. Otherwise, return `None`.
    #[inline]
    pub fn dispatch(&self, data: Bytes) -> Option<std::result::Result<(), TrySendError<()>>> {
        if let Self::Established(stream_data) = self {
            let r = stream_data
                .sender
                .as_ref()
                .map(|sender| sender.try_send(data))?
                .map_err(|e| match e {
                    TrySendError::Full(_) => TrySendError::Full(()),
                    TrySendError::Closed(_) => TrySendError::Closed(()),
                });
            Some(r)
        } else {
            None
        }
    }
}

/// Multiplexor inner
#[derive(Clone)]
pub struct MultiplexorInner {
    /// Where tasks queue frames to be sent
    pub tx_frame_tx: mpsc::UnboundedSender<FinalizedFrame>,
    /// Open stream channels: `flow_id` -> `FlowSlot`
    pub flows: Arc<RwLock<HashMap<u32, FlowSlot>>>,
    /// Channel for notifying the task of a dropped `MuxStream` (to send the flow ID)
    /// Sending 0 means that the multiplexor is being dropped and the
    /// task should exit.
    /// The reason we need `their_port` is to ensure the connection is `Reset`ted
    /// if the user did not call `poll_shutdown` on the `MuxStream`.
    pub dropped_ports_tx: mpsc::UnboundedSender<u32>,
    /// Default threshold for `Acknowledge` replies. See [`MuxStream`] for more details.
    pub default_rwnd_threshold: u32,
}

impl std::fmt::Debug for MultiplexorInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexorInner")
            .field("default_rwnd_threshold", &self.default_rwnd_threshold)
            .finish_non_exhaustive()
    }
}

impl Dupe for MultiplexorInner {
    #[inline]
    fn dupe(&self) -> Self {
        Self {
            tx_frame_tx: self.tx_frame_tx.dupe(),
            flows: self.flows.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
            default_rwnd_threshold: self.default_rwnd_threshold,
        }
    }
}

impl MultiplexorInner {
    /// Process an incoming message
    /// Returns `Ok(true)` if a `Close` message was received.
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    pub async fn process_message(
        &self,
        msg: Message,
        datagram_tx: &mpsc::Sender<Datagram>,
        con_recv_stream_tx: &mpsc::Sender<MuxStream>,
        bnd_request_tx: Option<&mpsc::Sender<BindRequest<'static>>>,
    ) -> Result<bool> {
        match msg {
            Message::Binary(data) => {
                let frame = data.try_into()?;
                trace!("received stream frame: {frame:?}");
                self.process_frame(frame, datagram_tx, con_recv_stream_tx, bnd_request_tx)
                    .await?;
                Ok(false)
            }
            Message::Ping(_) | Message::Pong(_) => {
                // `tokio-tungstenite` handles `Ping` messages automatically
                trace!("received ping/pong");
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
    /// - If `flag` is [`Connect`](crate::frame::OpCode::Connect),
    ///   - Find an available `dport` and send a `Acknowledge`.
    ///   - Create a new `MuxStream` and send it to the `stream_tx` channel.
    /// - If `flag` is `Acknowledge`,
    ///   - Existing stream with the matching `dport`: increment the `psh_send_remaining` counter.
    ///   - New stream: create a `MuxStream` and send it to the `stream_tx` channel.
    /// - If `flag` is `Bind`,
    ///   - Send the request to the user if we are accepting `Bind` requests and reply `Finish`.
    ///   - Otherwise, send back a `Reset` frame.
    /// - Otherwise, we find the sender with the matching `dport` and
    ///   - Send the data to the sender.
    ///   - If the receiver is closed or the port does not exist, send back a
    ///     `Reset` frame.
    #[tracing::instrument(skip_all, fields(flow_id), level = "debug")]
    #[inline]
    async fn process_frame(
        &self,
        frame: Frame<'static>,
        datagram_tx: &mpsc::Sender<Datagram>,
        con_recv_stream_tx: &mpsc::Sender<MuxStream>,
        bnd_request_tx: Option<&mpsc::Sender<BindRequest<'static>>>,
    ) -> Result<()> {
        let Frame {
            id: flow_id,
            payload,
        } = frame;
        tracing::Span::current().record("flow_id", format_args!("{flow_id:08x}"));
        let send_rst = || {
            self.tx_frame_tx
                .send(Frame::new_reset(flow_id).finalize())
                .ok()
            // Error only happens if the `frame_tx` channel is closed, at which point
            // we don't care about sending a `Reset` frame anymore
        };
        match payload {
            Payload::Connect(ConnectPayload {
                rwnd: peer_rwnd,
                target_host,
                target_port,
            }) => {
                // In this case, `target_host` is always owned already
                self.con_recv_new_stream(
                    flow_id,
                    target_host.into_owned(),
                    target_port,
                    peer_rwnd,
                    con_recv_stream_tx,
                )
                .await?;
            }
            Payload::Acknowledge(payload) => {
                trace!("received `Acknowledge`");
                // Three cases:
                // 1. Peer acknowledged `Connect`
                // 2. Peer acknowledged some `Push` frames
                // 3. Something unexpected
                let (should_new_stream, should_send_rst) = match self.flows.read().get(&flow_id) {
                    Some(FlowSlot::Established(stream_data)) => {
                        debug!("peer processed {payload} frames");
                        // We have an established stream, so process the `Acknowledge`
                        // Atomic ordering: as long as the value is incremented atomically,
                        // whether a writer sees the new value or the old value is not
                        // important. If it sees the old value and decides to return
                        // `Poll::Pending`, it will be woken up by the `Waker` anyway.
                        stream_data
                            .psh_send_remaining
                            .fetch_add(payload, Ordering::Relaxed);
                        stream_data.writer_waker.wake();
                        (false, false)
                    }
                    Some(FlowSlot::Requested(_)) => {
                        debug!("new stream with peer rwnd {payload}");
                        (true, false)
                    }
                    Some(FlowSlot::BindRequested(_)) => {
                        warn!("Peer replied `Acknowledge` to a `Bind` request");
                        (false, true)
                    }
                    None => {
                        debug!("stream does not exist, sending `Reset`");
                        (false, true)
                    }
                };
                if should_new_stream {
                    self.ack_recv_new_stream(flow_id, payload)?;
                } else if should_send_rst {
                    send_rst();
                }
            }
            Payload::Finish => {
                let mut flows = self.flows.write();
                let was_bind = match flows.get_mut(&flow_id) {
                    Some(FlowSlot::Established(stream_data)) => {
                        let sender = stream_data.sender.take();
                        if sender.is_none() {
                            warn!("Duplicate `Finish` frame");
                        }
                        // And our end can still send
                        false
                    }
                    Some(FlowSlot::Requested(_)) => {
                        // This is an invalid reply to a `Connect` frame
                        warn!("Peer replied `Finish` to a `Connect` request");
                        flows.remove(&flow_id);
                        send_rst();
                        false
                    }
                    Some(FlowSlot::BindRequested(_)) => true,
                    None => {
                        warn!("Bogus `Finish` frame");
                        false
                    }
                };
                if was_bind {
                    // Peer successfully bound the port
                    let Some(FlowSlot::BindRequested(sender)) = flows.remove(&flow_id) else {
                        unreachable!();
                    };
                    drop(flows);
                    sender.send(true).ok();
                    // If the send above fails, the receiver is dropped,
                    // so we can just ignore it.
                }
            }
            Payload::Reset => {
                debug!("received `Reset`");
                // `true` because we don't want to reply `Reset` with `Reset`.
                self.close_port(flow_id, true);
            }
            Payload::Push(data) => {
                // In this case, `data` is always owned already
                let result = self
                    .flows
                    .read()
                    .get(&flow_id)
                    .and_then(|slot| slot.dispatch(data.into_owned()));
                // This part is refactored out so that we don't have a deadlock
                match result {
                    Some(Ok(())) => (),
                    Some(Err(TrySendError::Full(()))) => {
                        // Peer does not respect the `rwnd` limit, this should not happen in normal circumstances.
                        // let's send `Reset`.
                        warn!("Peer does not respect `rwnd` limit, dropping stream");
                        self.close_port(flow_id, false);
                    }
                    Some(Err(TrySendError::Closed(()))) => {
                        // Else, the corresponding `MuxStream` is dropped
                        // The job to remove the port from the map is done by `close_port_task`,
                        // so not being able to send is the same as not finding the port;
                        // just timing is different.
                        trace!("dropped `MuxStream` not yet removed from the map");
                    }
                    None => {
                        warn!("Bogus `Push` frame");
                        send_rst();
                    }
                }
            }
            Payload::Bind(payload) => {
                if let Some(sender) = bnd_request_tx {
                    debug!(
                        "received `Bind` request: [{:?}]:{}",
                        payload.target_host, payload.target_port
                    );
                    let request = BindRequest {
                        flow_id,
                        payload,
                        tx_frame_tx: self.tx_frame_tx.dupe(),
                    };
                    if let Err(e) = sender.send(request).await {
                        warn!("Failed to send `Bind` request: {e}");
                    }
                    // Let the user decide what to reply using `BindRequest::reply`
                } else {
                    info!("Received `Bind` request but configured to not accept such requests");
                    self.tx_frame_tx
                        .send(Frame::new_reset(flow_id).finalize())
                        .ok();
                }
            }
            Payload::Datagram(payload) => {
                trace!("received datagram frame: {payload:?}");
                // Only fails if the receiver is dropped or the queue is full.
                // The first case means the multiplexor itself is dropped;
                // In the second case, we just drop the frame to avoid blocking.
                // It is UDP, after all.
                let datagram = Datagram {
                    flow_id,
                    target_host: payload.target_host.into_owned(),
                    target_port: payload.target_port,
                    data: payload.data.into_owned(),
                };
                if let Err(e) = datagram_tx.try_send(datagram) {
                    match e {
                        TrySendError::Full(_) => {
                            warn!("Dropped datagram: {e}");
                        }
                        TrySendError::Closed(_) => {
                            return Err(Error::Closed);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Shared code for new stream stuff
    #[inline]
    fn new_stream_shared(
        &self,
        flow_id: u32,
        peer_rwnd: u32,
        dest_host: Bytes,
        dest_port: u16,
    ) -> (MuxStream, EstablishedStreamData) {
        // `tx` is our end, `rx` is the user's end
        let (frame_tx, frame_rx) = mpsc::channel(config::RWND_USIZE);
        let finish_sent = Arc::new(AtomicBool::new(false));
        let psh_send_remaining = Arc::new(AtomicU32::new(peer_rwnd));
        let writer_waker = Arc::new(AtomicWaker::new());
        let stream_data = EstablishedStreamData {
            sender: Some(frame_tx),
            finish_sent: finish_sent.dupe(),
            psh_send_remaining: psh_send_remaining.dupe(),
            writer_waker: writer_waker.dupe(),
        };
        // Save the TX end of the stream so we can write to it when subsequent frames arrive
        let stream = MuxStream {
            frame_rx,
            flow_id,
            dest_host,
            dest_port,
            finish_sent,
            psh_send_remaining,
            psh_recvd_since: 0,
            writer_waker,
            buf: Bytes::new(),
            frame_tx: self.tx_frame_tx.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
            rwnd_threshold: self.default_rwnd_threshold.min(peer_rwnd),
        };
        (stream, stream_data)
    }

    /// Create a new stream because this end received a [`Connect`](crate::frame::OpCode::Connect) frame.
    /// Create a new `MuxStream`, add it to the map, and send an `Acknowledge` frame.
    /// If `our_port` is 0, a new port will be allocated.
    #[tracing::instrument(skip_all, level = "debug")]
    #[inline]
    async fn con_recv_new_stream(
        &self,
        flow_id: u32,
        dest_host: Bytes,
        dest_port: u16,
        peer_rwnd: u32,
        con_recv_stream_tx: &mpsc::Sender<MuxStream>,
    ) -> Result<()> {
        // Scope the following block to reduce locked time
        let stream = {
            // Save the TX end of the stream so we can write to it when subsequent frames arrive
            let mut streams = self.flows.write();
            if streams.contains_key(&flow_id) {
                debug!("resetting `Connect` with in-use flow_id");
                self.tx_frame_tx
                    .send(Frame::new_reset(flow_id).finalize())
                    .ok();
                // On the other side, `process_frame` will pass the `Reset` frame to
                // `close_port`, which takes the port out of the map and inform `Multiplexor::new_stream_channel`
                // to retry.
                // The existing connection at the same `flow_id` is not affected. For conforminh implementations,
                // This only happens when both ends are trying to establish a new connection at the same time
                // and also happen to have chosen the same `flow_id`.
                // In this case, the peer would also receive our `Connect` frame and, depending on the timing,
                // `Reset` us too or `Acknowledge` us.
                return Ok(());
            }
            let (stream, stream_data) =
                self.new_stream_shared(flow_id, peer_rwnd, dest_host, dest_port);
            // No write should occur between our check and insert
            streams.insert(flow_id, FlowSlot::Established(stream_data));
            stream
        };
        // Send a `Acknowledge`
        // Make sure `Acknowledge` is sent before the stream is sent to the user
        // so that the stream is `Established` when the user uses it.
        trace!("sending `Acknowledge`");
        self.tx_frame_tx
            .send(Frame::new_acknowledge(flow_id, config::RWND).finalize())
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
    #[tracing::instrument(skip_all, level = "debug")]
    #[inline]
    fn ack_recv_new_stream(&self, flow_id: u32, peer_rwnd: u32) -> Result<()> {
        // Change the state of the port to `Established` and send the stream to the user
        // At the client side, we use the associated oneshot channel to send the new stream
        trace!("sending stream to user");
        let (stream, stream_data) = self.new_stream_shared(flow_id, peer_rwnd, Bytes::new(), 0);
        self.flows
            .write()
            .get_mut(&flow_id)
            .ok_or(Error::ConnAckGone)?
            .establish(stream_data)
            .ok_or(Error::ConnAckGone)?
            .send(Some(stream))
            .map_err(|_| Error::SendStreamToClient)?;
        Ok(())
    }

    /// Close a port. That is, remove it from the map and call `close_port_local`.
    pub fn close_port(&self, flow_id: u32, inhibit_rst: bool) {
        // Free the port for reuse
        let value = self.flows.write().remove(&flow_id);
        if let Some(removed) = value {
            self.close_port_local(removed, flow_id, inhibit_rst);
        } else {
            debug!("connection not found, nothing to close");
        }
    }

    /// EOF the local end, and wake up the writer.
    #[tracing::instrument(skip_all)]
    #[inline]
    pub fn close_port_local(&self, removed: FlowSlot, flow_id: u32, inhibit_rst: bool) {
        match removed {
            FlowSlot::Established(mut stream_data) => {
                // Atomic ordering:
                // Load part:
                // If the user calls `poll_shutdown`, but we see `true` here,
                // the other end will receive a bogus `Reset` frame, which is fine.
                // Store part:
                // It does not matter whether the user calls `poll_shutdown` or not,
                // the stream is shut down and the final value of `finish_sent` is `true`.
                let finish_sent = stream_data.finish_sent.swap(true, Ordering::Relaxed);
                if !finish_sent && !inhibit_rst {
                    // If the user did not call `poll_shutdown`, we send a `Reset` frame
                    self.tx_frame_tx
                        .send(Frame::new_reset(flow_id).finalize())
                        .ok();
                    // Ignore the error because the other end will EOF everything anyway
                }
                // If there is a writer waiting for `Acknowledge`, wake it up because it will never receive one.
                // Waking it here and the user should receive a `BrokenPipe` error.
                stream_data.writer_waker.wake();
                // No need to send an empty `Bytes`. Dropping `sender`
                // already makes sure the user receives `EOF`.
                if let Some(sender) = stream_data.sender.take() {
                    debug_assert!(sender.strong_count() == 1);
                }
                // Ignore the error if the user already dropped the stream
                debug!("freed connection");
            }
            FlowSlot::Requested(sender) => {
                sender.send(None).ok();
                // Ignore the error if the user already cancelled the requesting future
                debug!("peer cancelled `Connect`");
            }
            FlowSlot::BindRequested(sender) => {
                sender.send(false).ok();
                // Ignore the error if the user already cancelled the requesting future
                debug!("peer rejected `Bind`");
            }
        }
    }
}
