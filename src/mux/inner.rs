//! Client side of the multiplexor
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::config;
use crate::dupe::Dupe;
use crate::frame::{FinalizedFrame, Frame};
use crate::stream::MuxStream;
use crate::{Error, Result};
use bytes::Bytes;
use futures_util::task::AtomicWaker;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, trace, warn};

/// Multiplexor inner
#[derive(Clone)]
pub struct MultiplexorInner {
    /// Open stream channels: `flow_id` -> `FlowSlot`
    pub flows: Arc<RwLock<HashMap<u32, FlowSlot>>>,
    /// Where tasks queue frames to be sent
    pub tx_frame_tx: mpsc::UnboundedSender<FinalizedFrame>,
    /// Channel for notifying the task of a dropped `MuxStream` (to send the flow ID)
    /// Sending 0 means that the multiplexor is being dropped and the
    /// task should exit.
    /// The reason we need `their_port` is to ensure the connection is `Reset`ted
    /// if the user did not call `poll_shutdown` on the `MuxStream`.
    pub dropped_ports_tx: mpsc::UnboundedSender<u32>,
    pub con_recv_stream_tx: mpsc::Sender<MuxStream>,
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
            flows: self.flows.dupe(),
            tx_frame_tx: self.tx_frame_tx.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
            con_recv_stream_tx: self.con_recv_stream_tx.dupe(),
            default_rwnd_threshold: self.default_rwnd_threshold,
        }
    }
}

impl MultiplexorInner {
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
    pub async fn con_recv_new_stream(
        &self,
        flow_id: u32,
        dest_host: Bytes,
        dest_port: u16,
        peer_rwnd: u32,
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
        self.con_recv_stream_tx
            .send(stream)
            .await
            .map_err(|_| Error::SendStreamToClient)?;
        Ok(())
    }

    /// Create a new `MuxStream` by finalizing a Con/Ack handshsake and
    /// change the state of the port to `Established`.
    #[tracing::instrument(skip_all, level = "debug")]
    #[inline]
    pub fn ack_recv_new_stream(&self, flow_id: u32, peer_rwnd: u32) -> Result<()> {
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
                let finish_sent = stream_data.disallow_write();
                if !finish_sent && !inhibit_rst {
                    // If the user did not call `poll_shutdown`, we send a `Reset` frame
                    self.tx_frame_tx
                        .send(Frame::new_reset(flow_id).finalize())
                        .ok();
                    // Ignore the error because the other end will EOF everything anyway
                }
                // No need to send an empty `Bytes`. Dropping `sender`
                // already makes sure the user receives `EOF`.
                if let Some(sender) = stream_data.disallow_read() {
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
    finish_sent: Arc<AtomicBool>,
    /// Number of `Push` frames we are allowed to send before waiting for a `Acknowledge` frame.
    psh_send_remaining: Arc<AtomicU32>,
    /// Waker to wake up the task that sends frames because their `psh_send_remaining`
    /// has increased.
    writer_waker: Arc<AtomicWaker>,
}

impl EstablishedStreamData {
    /// Process a `Finish` frame from the peer and thus disallowing further `AsyncRead` operations
    /// Returns the sender if it was not already taken.
    #[inline]
    pub const fn disallow_read(&mut self) -> Option<mpsc::Sender<Bytes>> {
        self.sender.take()
    }

    /// Process a `Acknowledge` frame from the peer
    #[inline]
    pub fn acknowledge(&self, acknowledged: u32) {
        // Atomic ordering: as long as the value is incremented atomically,
        // whether a writer sees the new value or the old value is not
        // important. If it sees the old value and decides to return
        // `Poll::Pending`, it will be woken up by the `Waker` anyway.
        self.psh_send_remaining
            .fetch_add(acknowledged, Ordering::Relaxed);
        // Wake up the writer if it is waiting for `Acknowledge`
        self.writer_waker.wake();
    }

    /// Disallow any `AsyncWrite` operations.
    /// Note that this should not be used from inside the `MuxStream` itself
    #[inline]
    pub fn disallow_write(&self) -> bool {
        // Atomic ordering:
        // Load part:
        // If the user calls `poll_shutdown`, but we see `true` here,
        // the other end will receive a bogus `Reset` frame, which is fine.
        // Store part:
        // We need to make sure the writer can see the new value
        // before we call `wake()`.
        let old = self.finish_sent.swap(true, Ordering::AcqRel);
        // If there is a writer waiting for `Acknowledge`, wake it up because it will never receive one.
        // Waking it here and the user should receive a `BrokenPipe` error.
        self.writer_waker.wake();
        old
    }
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
