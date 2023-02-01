//! Client side of the multiplexor
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
use super::locked_sink::LockedWebSocket;
use super::stream::MuxStream;
use super::{Error, IntKey, Role};
use crate::config;
use crate::dupe::Dupe;
use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, RwLock};
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, trace};
use tungstenite::Message;

/// (
///     writer,
///     can_write,
///     number of `Psh` frames received after the last `Ack` frame,
///     number of `Psh` frames we are allowed to send before waiting for a `Ack` frame,
///     waker to wake writers awaiting `Ack` frames,
/// )
type MuxStreamData = (
    mpsc::Sender<Bytes>,
    Arc<AtomicBool>,
    AtomicU64,
    Arc<AtomicU64>,
    Arc<AtomicWaker>,
);

/// Multiplexor inner
pub(super) struct MultiplexorInner<S> {
    /// The role of this multiplexor
    pub(super) role: Role,
    /// The underlying `Sink + Stream` of messages.
    pub(super) ws: LockedWebSocket<S>,
    /// Interval between keepalive `Ping`s
    pub(super) keepalive_interval: Option<std::time::Duration>,
    /// Open stream channels: our_port -> `MuxStreamData`
    pub(super) streams: Arc<RwLock<HashMap<u16, MuxStreamData>>>,
    /// Channel for notifying the task of a dropped `MuxStream`
    /// (in the form (our_port, their_port)).
    /// Sending (0, _) means that the multiplexor is being dropped and the
    /// task should exit.
    /// The reason we need `their_port` is to ensure the connection is `Rst`ed
    /// if the user did not call `poll_shutdown` on the `MuxStream`.
    pub(super) dropped_ports_tx: mpsc::UnboundedSender<(u16, u16)>,
}

impl<S> std::fmt::Debug for MultiplexorInner<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexorInner")
            .field("role", &self.role)
            .field("keepalive_interval", &self.keepalive_interval)
            .finish()
    }
}

impl<S> Clone for MultiplexorInner<S> {
    // `Clone` is manually implemented because we don't need `S: Clone`.
    #[inline]
    fn clone(&self) -> Self {
        Self {
            role: self.role,
            ws: self.ws.clone(),
            keepalive_interval: self.keepalive_interval,
            streams: self.streams.clone(),
            dropped_ports_tx: self.dropped_ports_tx.clone(),
        }
    }
}

impl<S> Dupe for MultiplexorInner<S> {
    // Explicitly providing a `dupe` implementation to prove that everything
    // can be cheaply cloned.
    #[inline]
    fn dupe(&self) -> Self {
        Self {
            role: self.role,
            ws: self.ws.dupe(),
            keepalive_interval: self.keepalive_interval,
            streams: self.streams.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
        }
    }
}

impl<S> MultiplexorInner<S>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
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
        mut stream_tx: mpsc::Sender<MuxStream<S>>,
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
                Some(msg) = self.ws.next() => {
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
                    if let Err(e) = self.ws.send_with(|| Message::Ping(vec![])).await {
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

impl<S> MultiplexorInner<S>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    /// Process an incoming message
    /// Returns `Ok(true)` if a `Close` message was received.
    #[tracing::instrument(skip(msg, datagram_tx, stream_tx), level = "trace")]
    #[inline]
    async fn process_message(
        &self,
        msg: Message,
        datagram_tx: &mut mpsc::Sender<DatagramFrame>,
        stream_tx: &mut mpsc::Sender<MuxStream<S>>,
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
            Message::Ping(_data) => {
                // `tokio-tungstenite` handles `Ping` messages automatically
                trace!("received ping");
                self.ws.flush_ignore_closed().await?;
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
        stream_tx: &mut mpsc::Sender<MuxStream<S>>,
    ) -> Result<(), Error> {
        let StreamFrame {
            dport: our_port,
            sport: their_port,
            flag,
            mut data,
        } = stream_frame;
        let send_rst = || async {
            self.ws
                .send_with(|| StreamFrame::new_rst(our_port, their_port).into())
                .await?;
            self.ws.flush_ignore_closed().await
        };
        match flag {
            StreamFlag::Syn => {
                if self.role == Role::Client {
                    return Err(Error::ClientReceivedSyn);
                }
                // Decode Syn handshake
                let peer_rwnd = data.get_u64();
                let dest_port = data.get_u16();
                let dest_host = data;
                let our_port = u16::next_available_key(&*self.streams.read().await);
                trace!("port: {}", our_port);
                // "we" is `role == Server`
                // "they" is `role == Client`
                self.new_stream(
                    our_port, their_port, dest_host, dest_port, peer_rwnd, stream_tx,
                )
                .await?;
                // Send a `SynAck`
                trace!("sending `SynAck`");
                self.ws
                    .send_with(|| {
                        StreamFrame::new_synack(our_port, their_port, config::RWND).into()
                    })
                    .await?;
                self.ws.flush_ignore_closed().await?;
            }
            StreamFlag::SynAck => {
                if self.role == Role::Server {
                    return Err(Error::ServerReceivedSynAck);
                }
                // Decode `SynAck` handshake
                let peer_rwnd = data.get_u64();
                // "we" is `role == Client`
                // "they" is `role == Server`
                self.new_stream(our_port, their_port, Bytes::new(), 0, peer_rwnd, stream_tx)
                    .await?;
            }
            StreamFlag::Ack => {
                debug!("received `Ack` for {our_port}");
                let new_rwnd = data.get_u64();
                let mut streams = self.streams.write().await;
                if let Some((_, _, _, cwnd, waker)) = streams.get_mut(&our_port) {
                    cwnd.store(new_rwnd, Ordering::SeqCst);
                    waker.wake();
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
                let sender = self.streams.write().await;
                if let Some((sender, _, _, _, _)) = sender.get(&our_port) {
                    // Make sure the user receives `EOF`.
                    sender.send(Bytes::new()).await.ok();
                }
                // And our end can still send
            }
            StreamFlag::Psh => {
                let mut streams = self.streams.write().await;
                if let Some((sender, _, psh_count, _, _)) = streams.get_mut(&our_port) {
                    if sender.send(data).await.is_ok() {
                        let remaining: u64 = sender
                            .capacity()
                            .try_into()
                            .expect("Capacity should fit into u64 (this is a bug)");
                        let new = psh_count.fetch_add(1, Ordering::SeqCst) + 1;
                        if new >= config::RWND - 1 {
                            psh_count.store(0, Ordering::SeqCst);
                            drop(streams);
                            debug!("sending `Ack` from {our_port} at {remaining}");
                            self.ws
                                .send_with(|| {
                                    StreamFrame::new_ack(our_port, their_port, remaining).into()
                                })
                                .await?;
                            self.ws.flush_ignore_closed().await?;
                        }
                    } else {
                        // The receiver is closed
                        drop(streams);
                        send_rst().await?;
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
        peer_rwnd: u64,
        stream_tx: &mut mpsc::Sender<MuxStream<S>>,
    ) -> Result<(), Error> {
        // `tx` is our end, `rx` is the user's end
        let (frame_tx, frame_rx) = mpsc::channel(config::STREAM_FRAME_BUFFER_SIZE);
        let can_write = Arc::new(AtomicBool::new(true));
        let cwnd = Arc::new(AtomicU64::new(peer_rwnd));
        let writer_waker = Arc::new(AtomicWaker::new());
        // Save the TX end of the stream so we can write to it when subsequent frames arrive
        let mut streams = self.streams.write().await;
        streams.insert(
            our_port,
            (
                frame_tx,
                can_write.dupe(),
                AtomicU64::new(0),
                cwnd.dupe(),
                writer_waker.dupe(),
            ),
        );
        drop(streams);
        let stream = MuxStream {
            frame_rx,
            our_port,
            their_port,
            dest_host,
            dest_port,
            can_write,
            cwnd,
            writer_waker,
            buf: Bytes::new(),
            ws: self.ws.dupe(),
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
        if let Some((sender, can_write, _, _, _)) = self.streams.write().await.remove(&our_port) {
            // Make sure the user receives `EOF`.
            sender.send(Bytes::new()).await.ok();
            let old = can_write.swap(false, Ordering::Relaxed);
            if old && !inhibit_rst {
                // If the user did not call `poll_shutdown`, we need to send a `Rst` frame
                self.ws
                    .send_with(|| StreamFrame::new_rst(our_port, their_port).into())
                    .await
                    .ok();
                self.ws.flush_ignore_closed().await.ok();
            }
        }
        debug!("freed port {}", our_port);
    }

    /// Should really only be called when the mux is dropped
    #[tracing::instrument(level = "trace")]
    async fn shutdown(&self) {
        debug!("closing all connections");
        let mut streams = self.streams.write().await;
        for (_, (sender, closed, _, _, _)) in streams.drain() {
            // Make sure the user receives `EOF`.
            sender.send(Bytes::new()).await.ok();
            // Stop all streams from sending stuff
            closed.store(true, Ordering::Relaxed);
        }
        drop(streams);
        // This also effectively `Rst`s all streams
        self.ws.close().await.ok();
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
