//! Multiplexor task
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::frame::{ConnectPayload, FinalizedFrame, Frame, OpCode, Payload};
use crate::inner::{FlowSlot, MultiplexorInner};
use crate::timing::{OptionalDuration, OptionalInterval};
use crate::{BindRequest, Datagram, Dupe, Error, Message, Result, WebSocketStream, WsError};
use bytes::Bytes;
use futures_util::future::poll_fn;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::task::{Context, Poll, ready};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, trace, warn};

/// Internal type used for spawning the multiplexor task
#[derive(Debug)]
pub struct TaskData {
    pub task: Task,
    // To be taken out when the task is spawned
    pub tx_frame_rx: mpsc::UnboundedReceiver<FinalizedFrame>,
    // To be taken out when the task is spawned
    pub dropped_ports_rx: mpsc::UnboundedReceiver<u32>,
}

impl TaskData {
    /// Spawn the multiplexor task.
    /// This function and [`new_no_task`] are implementation details and not exposed in the public API.
    #[inline]
    pub fn spawn<S: WebSocketStream<WsError>>(
        self,
        ws: S,
        task_joinset: Option<&mut JoinSet<Result<()>>>,
    ) {
        let Self {
            task,
            tx_frame_rx,
            dropped_ports_rx,
        } = self;
        if let Some(task_joinset) = task_joinset {
            task_joinset.spawn(task.start(ws, dropped_ports_rx, tx_frame_rx));
        } else {
            let parent_task = tokio::task::try_id();
            tokio::spawn(async move {
                debug!(
                    "spawning mux task {} from {}",
                    tokio::task::id(),
                    parent_task.map_or_else(|| "0".to_string(), |id| format!("{id}"))
                );
                if let Err(e) = task.start(ws, dropped_ports_rx, tx_frame_rx).await {
                    error!("Multiplexor task exited with error: {e}");
                }
            });
        }
        trace!("Multiplexor task spawned");
    }
}

/// Data owned by the multiplexor task.
// Not `Clone` because cloning it makes no sense.
#[derive(Debug)]
pub struct Task {
    pub inner: MultiplexorInner,
    pub datagram_tx: mpsc::Sender<Datagram>,
    pub bnd_request_tx: Option<mpsc::Sender<BindRequest<'static>>>,
    /// Interval between keepalive `Ping`s,
    pub keepalive_interval: OptionalDuration,
}

impl Task {
    /// Processing task
    /// Does the following:
    /// - Receives messages from `WebSocket` and processes them
    /// - Sends received datagrams to the `datagram_tx` channel
    /// - Sends received streams to the appropriate handler
    /// - Responds to ping/pong messages
    // It doesn't make sense to return a `Result` here because we can't propagate
    // the error to the user from a spawned task.
    // Instead, the user will notice when `rx` channels return `None`.
    #[tracing::instrument(skip_all, level = "debug", fields(task_id = %tokio::task::id()))]
    #[inline]
    async fn start<S: WebSocketStream<WsError>>(
        mut self,
        ws: S,
        mut dropped_ports_rx: mpsc::UnboundedReceiver<u32>,
        mut tx_frame_rx: mpsc::UnboundedReceiver<FinalizedFrame>,
    ) -> Result<()> {
        // Split the `WebSocket` stream into a `Sink` and `Stream` so we can process them concurrently
        let (mut ws_sink, mut ws_stream) = ws.split();
        let mut should_drain_frame_rx = false;
        let res = tokio::select! {
                r = self.process_dropped_ports_task(&mut dropped_ports_rx) => {
                    debug!("mux dropped ports task finished: {r:?}");
                    should_drain_frame_rx = true;
                    r
                }
                r = self.process_frame_recv_task(&mut ws_sink, &mut tx_frame_rx) => {
                    debug!("mux frame recv task finished: {r:?}");
                    // should_drain_frame_rx = false;
                    r
                }
                r = self.process_ws_next(
                    &mut ws_stream,
                ) => {
                    debug!("mux ws next task finished: {r:?}");
                    // should_drain_frame_rx = false;
                    r

            }
        };
        self.wind_down(
            should_drain_frame_rx,
            ws_sink
                .reunite(ws_stream)
                .expect("Failed to reunite sink and stream (this is a bug)"),
            &mut tx_frame_rx,
        )
        .await?;
        res
    }

    /// Process dropped ports from the `dropped_ports_rx` channel.
    /// Returns when [`Multiplexor`] itself is dropped.
    ///
    /// # Cancel Safety
    /// This function is cancel safe. If it is cancelled, some items
    /// may be left on `dropped_ports_rx` but no item will be lost.
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    async fn process_dropped_ports_task(
        &self,
        dropped_ports_rx: &mut mpsc::UnboundedReceiver<u32>,
    ) -> Result<()> {
        while let Some(flow_id) = dropped_ports_rx.recv().await {
            if flow_id == 0 {
                // `our_port` is `0`, which means the multiplexor itself is being dropped.
                debug!("mux dropped");
                // If this returns, our end is dropped, but we should still try to flush everything we
                // already have in the `frame_rx` before closing.
                return Ok(());
            }
            self.inner.close_port(flow_id, false);
        }
        // None: only happens when the last sender (i.e. `dropped_ports_tx` in `MultiplexorInner`)
        // is dropped, which should not happen in normal circumstances because `MultiplexorInner::drop`
        // is called before its fields are dropped.
        // However, this is not a fatal inconsistency, so we `debug_assert!` it to avoid
        // panicking in production.
        debug_assert!(
            false,
            "dropped ports receiver should not be closed (this is a bug)"
        );
        Err(Error::ChannelClosed("dropped_ports_rx"))
    }

    /// Poll `frame_rx` and process the frame received and send keepalive pings as needed.
    /// It propagates errors from the `Sink` processing.
    ///
    /// # Cancel Safety
    /// This function is mostly cancel safe. If it is cancelled, no data will be lost,
    /// but there might be unflushed frames on `ws_sink` or lost `Message::Ping` messages.
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    async fn process_frame_recv_task<S: WebSocketStream<WsError>>(
        &self,
        ws_sink: &mut SplitSink<S, Message>,
        tx_frame_rx: &mut mpsc::UnboundedReceiver<FinalizedFrame>,
    ) -> Result<()> {
        let mut interval = OptionalInterval::from(self.keepalive_interval);
        // If we missed a tick, it is probably doing networking, so we don't need to
        // make up for it.
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                r = poll_fn(|cx| Self::poll_reserve_space_recv_frame(cx, ws_sink, tx_frame_rx)) => {
                    let should_flush = r?;
                    if should_flush {
                        ws_sink.flush().await.map_err(Box::new)?;
                    }
                }
                _ = interval.tick() => {
                    trace!("sending keepalive ping");
                    ws_sink.send(Message::Ping(Bytes::new())).await.map_err(Box::new)?;
                }
            }
        }
        // This returns if we cannot sink or cannot receive from `frame_rx` anymore,
        // in either case, it does not make sense to check `frame_rx`.
    }

    /// Poll `frame_rx` and process the frame received in a way that is cancel safe.
    /// Returns `true` if the user should follow the call with a `Sink::flush`.
    fn poll_reserve_space_recv_frame<S: WebSocketStream<WsError>>(
        cx: &mut Context<'_>,
        ws_sink: &mut SplitSink<S, Message>,
        tx_frame_rx: &mut mpsc::UnboundedReceiver<FinalizedFrame>,
    ) -> Poll<Result<bool>> {
        ready!(ws_sink.poll_ready_unpin(cx)).map_err(Box::new)?;
        // `ready!`: if we cancel here, the reserved space is not used, but no other side effect
        let Some(frame) = ready!(tx_frame_rx.poll_recv(cx)) else {
            // Only happens when `frame_rx` is closed
            // cannot happen because `Self` contains one sender unless
            // there is a bug in our code or `tokio` itself. Not a critical error,
            // using `debug_assert!` to avoid panicking in production.
            debug_assert!(false, "frame receiver should not be closed (this is a bug)");
            return Poll::Ready(Err(Error::ChannelClosed("frame_rx")));
        };
        // After this point, we may not return `Poll::Pending` because we (might) hold data
        let should_flush = match frame.opcode() {
            Err(_) => {
                // Not a critical error, treating as flush
                debug_assert!(
                    frame.is_empty(),
                    "nonempty frame with invalid opcode (this is a bug)"
                );
                true
            }
            Ok(OpCode::Push) => {
                ws_sink
                    .start_send_unpin(Message::Binary(frame.into()))
                    .map_err(Box::new)?;
                // Buffer `Push` frames until the user calls `poll_flush`
                false
            }
            Ok(_) => {
                ws_sink
                    .start_send_unpin(Message::Binary(frame.into()))
                    .map_err(Box::new)?;
                // Flush everything else immediately
                true
            }
        };
        Poll::Ready(Ok(should_flush))
    }

    /// Process the return value of `ws.next()`
    /// Returns `Ok(())` when a `Close` message was received or the WebSocket was otherwise closed by the peer.
    #[tracing::instrument(skip_all, level = "trace")]
    async fn process_ws_next<S: WebSocketStream<WsError>>(
        &self,
        ws_stream: &mut SplitStream<S>,
    ) -> Result<()> {
        while let Some(m) = ws_stream.next().await {
            let msg = m.map_err(Box::new)?;
            trace!("received message length = {}", msg.len());
            if self.process_message(msg, false).await? {
                // Received a `Close` message
                debug!("WebSocket gracefully closed by peer");
                return Ok(());
            }
        }
        debug!("WebSocket closed by peer");
        return Ok(());
        // In this case, peer already requested close, so we should not attempt to send any more frames.
    }

    /// Wind down the multiplexor task.
    #[tracing::instrument(skip_all, level = "trace")]
    async fn wind_down<S: WebSocketStream<WsError>>(
        &mut self,
        should_drain_frame_rx: bool,
        mut ws: S,
        tx_frame_rx: &mut mpsc::UnboundedReceiver<FinalizedFrame>,
    ) -> Result<()> {
        debug!("closing all connections");
        // We first make sure the streams can no longer send
        for (_, stream_data) in self.inner.flows.write().iter() {
            if let FlowSlot::Established(stream_data) = stream_data {
                stream_data.disallow_write();
            }
        }
        // Let the tasks do some work now
        tokio::task::yield_now().await;
        // Further ensure no more frames can be sent. This should cause all `AsyncWrite::poll_write`
        // to return `BrokenPipe`.
        // See `tokio::sync::mpsc`#clean-shutdown
        tx_frame_rx.close();
        // Now if `should_drain_frame_rx` is `true`, we will process the remaining frames in `frame_rx`.
        // If it is `false`, then we reached here because the peer is now not interested
        // in our connection anymore, and we should just mind our own business and serve the connections
        // on our end.
        if should_drain_frame_rx {
            // Since we've called `close` on `tx_frame_rx`, this loop will
            // terminate once existing frames are processed.
            while let Some(frame) = tx_frame_rx.recv().await {
                if frame.is_empty() {
                    continue;
                }
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
            self.process_message(msg, true).await?;
        }
        // Finally, we send EOF to all established streams.
        self.inner
            .flows
            .write()
            .drain()
            .for_each(|(flow_id, slot)| {
                self.inner.close_port_local(slot, flow_id, true);
            });
        Ok(())
    }

    /// Process an incoming message
    /// Returns `Ok(true)` if a `Close` message was received.
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    async fn process_message(&self, msg: Message, ignore_bind: bool) -> Result<bool> {
        match msg {
            Message::Binary(data) => {
                let frame = data.try_into()?;
                trace!("received stream frame: {frame:?}");
                self.process_frame(frame, ignore_bind).await?;
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
    async fn process_frame(&self, frame: Frame<'static>, ignore_bind: bool) -> Result<()> {
        let Frame {
            id: flow_id,
            payload,
        } = frame;
        tracing::Span::current().record("flow_id", format_args!("{flow_id:08x}"));
        let send_rst = || {
            self.inner
                .tx_frame_tx
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
                self.inner
                    .con_recv_new_stream(flow_id, target_host.into_owned(), target_port, peer_rwnd)
                    .await?;
            }
            Payload::Acknowledge(payload) => {
                trace!("received `Acknowledge`");
                // Three cases:
                // 1. Peer acknowledged `Connect`
                // 2. Peer acknowledged some `Push` frames
                // 3. Something unexpected
                let (should_new_stream, should_send_rst) =
                    match self.inner.flows.read().get(&flow_id) {
                        Some(FlowSlot::Established(stream_data)) => {
                            debug!("peer processed {payload} frames");
                            // We have an established stream, so process the `Acknowledge`
                            stream_data.acknowledge(payload);
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
                    self.inner.ack_recv_new_stream(flow_id, payload)?;
                } else if should_send_rst {
                    send_rst();
                }
            }
            Payload::Finish => {
                let mut flows = self.inner.flows.write();
                let Some(flow) = flows.get_mut(&flow_id) else {
                    warn!("Bogus `Finish` frame");
                    send_rst();
                    return Ok(());
                };
                match flow {
                    FlowSlot::BindRequested(_) => {
                        // Peer successfully bound the port
                        let Some(FlowSlot::BindRequested(sender)) = flows.remove(&flow_id) else {
                            unreachable!();
                        };
                        drop(flows);
                        sender.send(true).ok();
                        // If the send above fails, the receiver is dropped,
                        // so we can just ignore it.
                    }
                    FlowSlot::Requested(_) => {
                        // `Finish` is an invalid response to `Connect`
                        warn!("Peer replied `Finish` to a `Connect` request");
                        flows.remove(&flow_id);
                        drop(flows);
                        send_rst();
                    }
                    FlowSlot::Established(stream_data) => {
                        if stream_data.disallow_read().is_none() {
                            warn!("Duplicate `Finish` frame");
                        }
                    }
                }
            }
            Payload::Reset => {
                debug!("received `Reset`");
                // `true` because we don't want to reply `Reset` with `Reset`.
                self.inner.close_port(flow_id, true);
            }
            Payload::Push(data) => {
                // In this case, `data` is always owned already
                let result = self
                    .inner
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
                        self.inner.close_port(flow_id, false);
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
                if let Some(sender) = &self.bnd_request_tx {
                    debug!(
                        "received `Bind` request: [{:?}]:{}",
                        payload.target_host, payload.target_port
                    );
                    if ignore_bind {
                        // Used for shutting down
                        return Ok(());
                    }
                    let request = BindRequest {
                        flow_id,
                        payload,
                        tx_frame_tx: self.inner.tx_frame_tx.dupe(),
                    };
                    if let Err(e) = sender.send(request).await {
                        warn!("Failed to send `Bind` request: {e}");
                    }
                    // Let the user decide what to reply using `BindRequest::reply`
                } else {
                    info!("Received `Bind` request but configured to not accept such requests");
                    self.inner
                        .tx_frame_tx
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
                if let Err(e) = self.datagram_tx.try_send(datagram) {
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
}
