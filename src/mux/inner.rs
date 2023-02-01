//! Client side of the multiplexor
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
use super::locked_sink::LockedSink;
use super::stream::MuxStream;
use super::{Error, IntKey, Role};
use crate::config;
use crate::dupe::Dupe;
use bytes::{Buf, Bytes};
use futures_util::{Sink as FutureSink, Stream as FutureStream};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, trace};
use tungstenite::Message;

/// (writer, can_write)
type MuxStreamSenderData = (mpsc::Sender<Bytes>, Arc<AtomicBool>);

/// Multiplexor inner
pub(super) struct MultiplexorInner<SinkStream> {
    /// The role of this multiplexor
    pub(super) role: Role,
    /// The underlying `Sink + Stream` of messages.
    pub(super) sink_stream: LockedSink<SinkStream>,
    /// Interval between keepalive `Ping`s
    pub(super) keepalive_interval: Option<std::time::Duration>,
    /// Open stream channels: our_port -> `MuxStreamSenderData`
    pub(super) streams: Arc<RwLock<HashMap<u16, MuxStreamSenderData>>>,
    /// Channel for notifying the task of a dropped `MuxStream`
    /// (in the form (our_port, their_port)).
    /// Sending (0, _) means that the multiplexor is being dropped and the
    /// task should exit.
    /// The reason we need `their_port` is to ensure the connection is `Rst`ed
    /// if the user did not call `poll_shutdown` on the `MuxStream`.
    pub(super) dropped_ports_tx: mpsc::UnboundedSender<(u16, u16)>,
}

impl<SinkStream> std::fmt::Debug for MultiplexorInner<SinkStream> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexorInner")
            .field("role", &self.role)
            .field("keepalive_interval", &self.keepalive_interval)
            .finish()
    }
}

impl<SinkStream> Clone for MultiplexorInner<SinkStream> {
    // `Clone` is manually implemented because we don't need `SinkStream: Clone`.
    #[inline]
    fn clone(&self) -> Self {
        Self {
            role: self.role,
            sink_stream: self.sink_stream.clone(),
            keepalive_interval: self.keepalive_interval,
            streams: self.streams.clone(),
            dropped_ports_tx: self.dropped_ports_tx.clone(),
        }
    }
}

impl<SinkStream> Dupe for MultiplexorInner<SinkStream> {
    // Explicitly providing a `dupe` implementation to prove that everything
    // can be cheaply cloned.
    #[inline]
    fn dupe(&self) -> Self {
        Self {
            role: self.role,
            sink_stream: self.sink_stream.dupe(),
            keepalive_interval: self.keepalive_interval,
            streams: self.streams.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
        }
    }
}

impl<SinkStream> MultiplexorInner<SinkStream>
where
    SinkStream: FutureSink<Message, Error = tungstenite::Error>
        + FutureStream<Item = tungstenite::Result<Message>>
        + Send
        + Unpin
        + 'static,
{
    /// Processing task
    /// Does the following:
    /// - Receives messages from `WebSocket` and processes them
    /// - Sends received datagrams to the `datagram_tx` channel
    /// - Sends received streams to the appropriate handler
    /// - Responds to ping/pong messages
    #[tracing::instrument(skip(datagram_tx, stream_tx, dropped_ports_rx), level = "trace")]
    pub async fn task(
        self,
        mut datagram_tx: mpsc::Sender<DatagramFrame>,
        mut stream_tx: mpsc::Sender<MuxStream<SinkStream>>,
        mut dropped_ports_rx: mpsc::UnboundedReceiver<(u16, u16)>,
    ) -> Result<(), Error> {
        let mut keepalive_interval = MaybeInterval::new(self.keepalive_interval);
        // If we missed a tick, it is probably doing networking, so we don't need to
        // send a ping
        keepalive_interval.maybe_set_missed_tick_behavior(MissedTickBehavior::Skip);
        let result = loop {
            trace!("task loop");
            tokio::select! {
                Some((our_port, their_port)) = dropped_ports_rx.recv() => {
                    if our_port == 0 {
                        debug!("mux dropped");
                        break Ok(());
                    }
                    self.close_port(our_port, their_port, false).await;
                }
                Some(msg) = self.sink_stream.next() => {
                    let msg = match msg {
                        Ok(msg) => msg,
                        Err(e) => {
                            error!("Failed to receive message: {}", e);
                            break Err(e.into());
                        }
                    };
                    trace!("received message length = {}", msg.len());
                    // Messages cannot be processed concurrently
                    // because doing so will break stream ordering
                    if let Err(e) = self.process_message(msg, &mut datagram_tx, &mut stream_tx).await {
                        error!("Failed to process message: {}", e);
                        break Err(e);
                    }
                }
                _ = keepalive_interval.tick() => {
                    trace!("sending ping");
                    // Tungstenite should deliver `Ping` immediately
                    if let Err(e) = self.sink_stream.send_with(|| Message::Ping(vec![])).await {
                        error!("Failed to send ping: {}", e);
                        break Err(e.into());
                    }
                }
                else => {
                    // Everything is closed, we are probably done
                    break Ok(());
                }
            }
        };
        match &result {
            Ok(()) => debug!("Multiplexor task exited"),
            Err(e) => error!("Multiplexor task failed: {e}"),
        }
        self.shutdown().await;
        result
    }
}

impl<SinkStream> MultiplexorInner<SinkStream>
where
    SinkStream: FutureSink<Message, Error = tungstenite::Error> + Send + Unpin + 'static,
{
    /// Process an incoming message
    /// Returns `Ok(true)` if a `Close` message was received.
    #[tracing::instrument(skip(msg, datagram_tx, stream_tx), level = "trace")]
    #[inline]
    async fn process_message(
        &self,
        msg: Message,
        datagram_tx: &mut mpsc::Sender<DatagramFrame>,
        stream_tx: &mut mpsc::Sender<MuxStream<SinkStream>>,
    ) -> Result<bool, Error> {
        match msg {
            Message::Binary(data) => {
                let frame = data.try_into()?;
                match frame {
                    Frame::Datagram(datagram_frame) => {
                        trace!("received datagram frame: {:?}", datagram_frame);
                        datagram_tx.send(datagram_frame).await?;
                    }
                    Frame::Stream(stream_frame) => {
                        trace!("received stream frame: {:?}", stream_frame);
                        self.process_stream_frame(stream_frame, stream_tx).await?;
                    }
                }
                Ok(false)
            }
            Message::Ping(data) => {
                trace!("received ping: {:?}", data);
                self.sink_stream.send_message(&Message::Pong(data)).await?;
                self.sink_stream.flush_ignore_closed().await?;
                Ok(false)
            }
            Message::Pong(data) => {
                trace!("received pong: {:?}", data);
                Ok(false)
            }
            Message::Close(_) => {
                debug!("received close");
                Ok(true)
            }
            Message::Text(text) => {
                error!("Received `Text` message: `{text}'");
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
    #[tracing::instrument(skip(stream_frame, stream_tx), level = "trace")]
    #[inline]
    async fn process_stream_frame(
        &self,
        stream_frame: StreamFrame,
        stream_tx: &mut mpsc::Sender<MuxStream<SinkStream>>,
    ) -> Result<(), Error> {
        let StreamFrame {
            dport: our_port,
            sport: their_port,
            flag,
            data,
        } = stream_frame;
        let send_rst = || async {
            self.sink_stream
                .send_with(|| StreamFrame::new_rst(our_port, their_port).into())
                .await?;
            self.sink_stream.flush_ignore_closed().await
        };
        match flag {
            StreamFlag::Syn => {
                if self.role == Role::Client {
                    return Err(Error::ClientReceivedSyn);
                }
                // Decode Syn handshake
                let mut syn_data = data;
                let host_len = syn_data.get_u8();
                let dest_host = syn_data.split_to(host_len as usize);
                let dest_port = syn_data.get_u16();
                let our_port = u16::next_available_key(&*self.streams.read().await);
                trace!("port: {}", our_port);
                // "we" is `role == Server`
                // "they" is `role == Client`
                self.new_stream(our_port, their_port, dest_host, dest_port, stream_tx)
                    .await?;
                // Send a `Ack`
                trace!("sending `Ack`");
                self.sink_stream
                    .send_with(|| StreamFrame::new_ack(our_port, their_port).into())
                    .await?;
                self.sink_stream.flush_ignore_closed().await?;
            }
            StreamFlag::Ack => {
                if self.role == Role::Server {
                    return Err(Error::ServerReceivedAck);
                }
                // "we" is `role == Client`
                // "they" is `role == Server`
                self.new_stream(our_port, their_port, Bytes::new(), 0, stream_tx)
                    .await?;
            }
            StreamFlag::Rst => {
                // `true` because we don't want to reply `Rst` with `Rst`.
                self.close_port(our_port, their_port, true).await;
            }
            StreamFlag::Fin => {
                let sender = self.streams.write().await;
                if let Some((sender, _)) = sender.get(&our_port) {
                    // Make sure the user receives `EOF`.
                    sender.send(Bytes::new()).await.ok();
                }
                // And our end can still send
            }
            StreamFlag::Psh => {
                let mut streams = self.streams.write().await;
                if let Some((sender, _)) = streams.get_mut(&our_port) {
                    if sender.send(data).await.is_ok() {
                        return Ok(());
                    }
                } else {
                    // The port does not exist
                    drop(streams);
                    send_rst().await?;
                    return Ok(());
                };
            }
        }
        Ok(())
    }

    /// Create a new `MuxStream` and add it into the map
    async fn new_stream(
        &self,
        our_port: u16,
        their_port: u16,
        dest_host: Bytes,
        dest_port: u16,
        stream_tx: &mut mpsc::Sender<MuxStream<SinkStream>>,
    ) -> Result<(), Error> {
        // `tx` is our end, `rx` is the user's end
        let (frame_tx, frame_rx) = mpsc::channel(config::STREAM_FRAME_BUFFER_SIZE);
        let can_write = Arc::new(AtomicBool::new(true));
        // Save the TX end of the stream so we can write to it when subsequent frames arrive
        let mut streams = self.streams.write().await;
        streams.insert(our_port, (frame_tx, can_write.dupe()));
        drop(streams);
        let stream = MuxStream {
            frame_rx,
            our_port,
            their_port,
            dest_host,
            dest_port,
            can_write,
            buf: Bytes::new(),
            sink: self.sink_stream.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
        };
        trace!("sending stream to user");
        // This goes to the user
        stream_tx
            .send(stream)
            .await
            .map_err(|e| Error::SendStreamToClient(e.to_string()))
    }

    /// Close a port. That is, send `Rst` if `Fin` is not sent,
    /// and remove it from the map.
    #[tracing::instrument(level = "trace")]
    #[inline]
    pub async fn close_port(&self, our_port: u16, their_port: u16, inhibit_rst: bool) {
        // Free the port for reuse
        if let Some((sender, can_write)) = self.streams.write().await.remove(&our_port) {
            // Make sure the user receives `EOF`.
            sender.send(Bytes::new()).await.ok();
            let old = can_write.swap(false, Ordering::Relaxed);
            if old && !inhibit_rst {
                // If the user did not call `poll_shutdown`, we need to send a `Rst` frame
                self.sink_stream
                    .send_with(|| StreamFrame::new_rst(our_port, their_port).into())
                    .await
                    .ok();
                self.sink_stream.flush_ignore_closed().await.ok();
            }
        }
        debug!("freed port {}", our_port);
    }

    /// Should really only be called when the mux is dropped
    #[tracing::instrument(level = "trace")]
    async fn shutdown(&self) {
        debug!("closing all connections");
        let mut streams = self.streams.write().await;
        for (_, (sender, closed)) in streams.drain() {
            // Make sure the user receives `EOF`.
            sender.send(Bytes::new()).await.ok();
            // Stop all streams from sending stuff
            closed.store(true, Ordering::Relaxed);
        }
        drop(streams);
        // This also effectively `Rst`s all streams
        self.sink_stream.close().await.ok();
    }
}

/// An interval or a never-resolving future
#[derive(Debug)]
struct MaybeInterval {
    interval: Option<tokio::time::Interval>,
}

impl MaybeInterval {
    fn new(interval: Option<tokio::time::Duration>) -> Self {
        Self {
            interval: interval.map(tokio::time::interval),
        }
    }

    fn maybe_set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior) {
        if let Some(interval) = &mut self.interval {
            interval.set_missed_tick_behavior(behavior);
        }
    }

    async fn tick(&mut self) {
        if let Some(interval) = &mut self.interval {
            interval.tick().await;
        } else {
            let never = futures_util::future::pending::<()>();
            never.await;
        }
    }
}
