//! Multiplexor task
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::frame::{FinalizedFrame, OpCode};
use crate::inner::{FlowSlot, MultiplexorInner};
use crate::stream::MuxStream;
use crate::timing::{OptionalDuration, OptionalInterval};
use crate::{BindRequest, Datagram, Message, WebSocketStream};
use crate::{Error, Result, WsError};
use bytes::Bytes;
use futures_util::future::poll_fn;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::Ordering;
use std::task::{Context, Poll, ready};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, trace, warn};

/// Internal type used for spawning the multiplexor task
#[derive(Debug)]
pub struct Task {
    pub inner: MultiplexorInner,
    pub datagram_tx: mpsc::Sender<Datagram>,
    pub con_recv_stream_tx: mpsc::Sender<MuxStream>,
    // To be taken out when the task is spawned
    pub tx_frame_rx: Option<mpsc::UnboundedReceiver<FinalizedFrame>>,
    // To be taken out when the task is spawned
    pub dropped_ports_rx: Option<mpsc::UnboundedReceiver<u32>>,
    pub bnd_request_tx: Option<mpsc::Sender<BindRequest<'static>>>,
    /// Interval between keepalive `Ping`s,
    pub keepalive_interval: OptionalDuration,
}

impl Task {
    /// Spawn the multiplexor task.
    /// This function and [`new_no_task`] are implementation details and not exposed in the public API.
    #[inline]
    pub fn spawn<S: WebSocketStream<WsError>>(
        self,
        ws: S,
        task_joinset: Option<&mut JoinSet<Result<()>>>,
    ) {
        if let Some(task_joinset) = task_joinset {
            task_joinset.spawn(self.task(ws));
        } else {
            tokio::spawn(async move {
                if let Err(e) = self.task(ws).await {
                    error!("Multiplexor task exited with error: {e}");
                }
            });
        }
        trace!("Multiplexor task spawned");
    }

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
    #[inline]
    async fn task<S: WebSocketStream<WsError>>(mut self, ws: S) -> Result<()> {
        // Split the `WebSocket` stream into a `Sink` and `Stream` so we can process them concurrently
        let (mut ws_sink, mut ws_stream) = ws.split();
        let mut should_drain_frame_rx = false;
        let mut tx_frame_rx = self
            .tx_frame_rx
            .take()
            .expect("`tx_frame_rx` should not be `None` before spawning the task (this is a bug)");
        let mut dropped_ports_rx = self.dropped_ports_rx.take().expect(
            "`dropped_ports_rx` should not be `None` before spawning the task (this is a bug)",
        );
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
            if self
                .inner
                .process_message(
                    msg,
                    &self.datagram_tx,
                    &self.con_recv_stream_tx,
                    self.bnd_request_tx.as_ref(),
                )
                .await?
            {
                // Received a `Close` message
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
                // Prevent the user from writing
                // Atomic ordering: It does not matter whether the user calls `poll_shutdown` or not,
                // the stream is shut down and the final value of `finish_sent` is `true`.
                stream_data.finish_sent.store(true, Ordering::Relaxed);
                // If there is a writer waiting for `Acknowledge`, wake it up because it will never receive one.
                // Waking it here and the user should receive a `BrokenPipe` error.
                stream_data.writer_waker.wake();
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
        // We cannot loop await `recv` because, again, `inner` contains one last sender,
        // so `recv` will never return `None`. We already closed `frame_rx` above, so looping over
        // `try_recv` should give us all the remaining frames.
        if should_drain_frame_rx {
            while let Ok(frame) = tx_frame_rx.try_recv() {
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
            self.inner
                .process_message(msg, &self.datagram_tx, &self.con_recv_stream_tx, None)
                .await?;
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
}
