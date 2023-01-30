//! Client side of the multiplexor
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
use super::locked_sink::LockedMessageSink;
use super::stream::MuxStream;
use super::{Error, IntKey, Role};
use crate::config;
use crate::dupe::Dupe;
use bytes::{Buf, Bytes};
use futures_util::{Sink as FutureSink, Stream as FutureStream, StreamExt};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::PollSemaphore;
use tracing::{debug, error, trace};
use tungstenite::Message;

/// (
///     writer,
///     notifier when `close_port` is called,
///     number of remaining packets we can send before having to wait for `Dack`.
/// )
type MuxStreamSenderData = (
    mpsc::Sender<Bytes>,
    Arc<AtomicBool>,
    Arc<Mutex<Vec<OwnedSemaphorePermit>>>,
);

/// Multiplexor inner
pub(super) struct MultiplexorInner<Sink> {
    /// The role of this multiplexor
    pub(super) role: Role,
    /// The underlying `Sink` of messages. `Stream` is localized to `self.task_inner`.
    pub(super) sink: LockedMessageSink<Sink>,
    /// Interval between keepalive `Ping`s
    pub(super) keepalive_interval: Option<std::time::Duration>,
    /// Open stream channels: our_port -> `MuxStreamSenderData`
    pub(super) streams: Arc<RwLock<HashMap<u16, MuxStreamSenderData>>>,
    /// Channel for notifying the task of a dropped `MuxStream`
    /// (in the form (our_port, their_port, fin_sent)).
    /// Sending (0, _, _) means that the multiplexor is being dropped and the
    /// task should exit.
    /// The reason we need `their_port` is to ensure the connection is `Rst`ed
    /// if the user did not call `poll_shutdown` on the `MuxStream`.
    pub(super) dropped_ports_tx: mpsc::UnboundedSender<(u16, u16, bool)>,
}

impl<Sink> std::fmt::Debug for MultiplexorInner<Sink> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexorInner")
            .field("role", &self.role)
            .field("keepalive_interval", &self.keepalive_interval)
            .finish()
    }
}

impl<Sink> Clone for MultiplexorInner<Sink> {
    // `Clone` is manually implemented because we don't need `Sink: Clone`.
    #[inline]
    fn clone(&self) -> Self {
        Self {
            role: self.role,
            sink: self.sink.clone(),
            keepalive_interval: self.keepalive_interval,
            streams: self.streams.clone(),
            dropped_ports_tx: self.dropped_ports_tx.clone(),
        }
    }
}

impl<Sink> Dupe for MultiplexorInner<Sink> {
    // Explicitly providing a `dupe` implementation to prove that everything
    // can be cheaply cloned.
    #[inline]
    fn dupe(&self) -> Self {
        Self {
            role: self.role,
            sink: self.sink.dupe(),
            keepalive_interval: self.keepalive_interval,
            streams: self.streams.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
        }
    }
}

impl<Sink> MultiplexorInner<Sink>
where
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Sync + Unpin + 'static,
{
    /// Wrapper for `task_inner` that makes sure `self.shutdown` is called
    #[tracing::instrument(
        skip(datagram_tx, stream_tx, dropped_ports_rx, message_stream),
        level = "trace"
    )]
    pub(super) async fn task_wrapper<Stream>(
        self,
        datagram_tx: mpsc::Sender<DatagramFrame>,
        stream_tx: mpsc::Sender<MuxStream<Sink>>,
        dropped_ports_rx: mpsc::UnboundedReceiver<(u16, u16, bool)>,
        message_stream: Stream,
    ) -> Result<(), Error>
    where
        Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Sync + Unpin + 'static,
    {
        let res = self
            .task_inner(datagram_tx, stream_tx, dropped_ports_rx, message_stream)
            .await;
        match &res {
            Ok(()) => debug!("Multiplexor task exited"),
            Err(e) => error!("Multiplexor task failed: {e}"),
        }
        self.shutdown().await;
        res
    }
    /// Processing task
    /// Does the following:
    /// - Receives messages from `WebSocket` and processes them
    /// - Sends received datagrams to the `datagram_tx` channel
    /// - Sends received streams to the appropriate handler
    /// - Responds to ping/pong messages
    async fn task_inner<Stream>(
        &self,
        mut datagram_tx: mpsc::Sender<DatagramFrame>,
        mut stream_tx: mpsc::Sender<MuxStream<Sink>>,
        mut dropped_ports_rx: mpsc::UnboundedReceiver<(u16, u16, bool)>,
        mut message_stream: Stream,
    ) -> Result<(), Error>
    where
        Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Sync + Unpin + 'static,
    {
        let mut keepalive_interval = MaybeInterval::new(self.keepalive_interval);
        // If we missed a tick, it is probably doing networking, so we don't need to
        // send a ping
        keepalive_interval.maybe_set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Number of `Psh` frames received after the previous `Dack`
        let recv_counter = AtomicUsize::new(0);
        loop {
            trace!("task loop");
            tokio::select! {
                Some((our_port, their_port, fin_sent)) = dropped_ports_rx.recv() => {
                    if our_port == 0 {
                        debug!("mux dropped");
                        return Ok(());
                    }
                    self.close_port(our_port, their_port, fin_sent).await;
                }
                Some(msg) = message_stream.next() => {
                    let msg = msg?;
                    trace!("received message length = {}", msg.len());
                    if self.process_message(msg, &mut datagram_tx, &mut stream_tx, &recv_counter).await? {
                        // If the message was a `Close` frame, we are done
                        return Ok(());
                    }
                }
                _ = keepalive_interval.tick() => {
                    trace!("sending ping");
                    self.sink.send_message(Message::Ping(vec![])).await?;
                }
                else => {
                    // Everything is closed, we are probably done
                    return Ok(());
                }
            }
        }
    }

    /// Process an incoming message
    /// Returns `Ok(true)` if a `Close` message was received.
    #[tracing::instrument(skip(msg, datagram_tx, stream_tx), level = "trace")]
    #[inline]
    async fn process_message(
        &self,
        msg: Message,
        datagram_tx: &mut mpsc::Sender<DatagramFrame>,
        stream_tx: &mut mpsc::Sender<MuxStream<Sink>>,
        recv_counter: &AtomicUsize,
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
                        self.process_stream_frame(stream_frame, stream_tx, recv_counter)
                            .await?;
                    }
                }
                Ok(false)
            }
            Message::Ping(data) => {
                trace!("received ping: {:?}", data);
                self.sink.send_message(Message::Pong(data)).await?;
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
        stream_tx: &mut mpsc::Sender<MuxStream<Sink>>,
        recv_counter: &AtomicUsize,
    ) -> Result<(), Error> {
        let StreamFrame {
            dport: our_port,
            sport: their_port,
            flag,
            data,
        } = stream_frame;
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
                let ack_frame = Frame::Stream(StreamFrame::new_ack(our_port, their_port));
                trace!("sending `Ack`");
                self.send_frame(ack_frame).await?;
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
                if let Some(sender) = sender.get(&our_port) {
                    // Make sure the user receives `EOF`.
                    sender.0.send(Bytes::new()).await.ok();
                }
                // And our end can still send
            }
            StreamFlag::Psh => {
                let mut streams = self.streams.write().await;
                if let Some(frame_sender) = streams.get_mut(&our_port) {
                    if frame_sender.0.send(data).await.is_ok() {
                        let new = recv_counter.fetch_add(1, Ordering::AcqRel);
                        if new >= config::STREAM_FRAME_BUFFER_SIZE / 2 {
                            // Let's acknowledge them
                            let dack_frame =
                                Frame::Stream(StreamFrame::new_dack(our_port, their_port));
                            debug!("sending `Dack` for {their_port} at count={new}");
                            self.send_frame(dack_frame).await?;
                            recv_counter.store(0, Ordering::Relaxed);
                        }
                        return Ok(());
                    }
                }
                drop(streams);
                // else, the receiver is closed or the port does not exist
                let rst_frame = Frame::Stream(StreamFrame::new_rst(our_port, their_port));
                self.send_frame(rst_frame).await?;
            }
            StreamFlag::Dack => {
                debug!("received `Dack` for {our_port}");
                let mut streams = self.streams.write().await;
                if let Some((_, _, write_permits)) = streams.get_mut(&our_port) {
                    // Relinquish all permits
                    write_permits.lock().clear();
                } else {
                    // the receiver is closed or the port does not exist
                    drop(streams);
                    let rst_frame = Frame::Stream(StreamFrame::new_rst(our_port, their_port));
                    self.send_frame(rst_frame).await?;
                }
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
        stream_tx: &mut mpsc::Sender<MuxStream<Sink>>,
    ) -> Result<(), Error> {
        // `tx` is our end, `rx` is the user's end
        let (frame_tx, frame_rx) = mpsc::channel(config::STREAM_FRAME_BUFFER_SIZE);
        let stream_removed = Arc::new(AtomicBool::new(false));
        let window_remaining =
            PollSemaphore::new(Arc::new(Semaphore::new(config::STREAM_FRAME_BUFFER_SIZE)));
        let write_permits = Arc::new(Mutex::new(Vec::new()));
        // Save the TX end of the stream so we can write to it when subsequent frames arrive
        let mut streams = self.streams.write().await;
        streams.insert(
            our_port,
            (frame_tx, stream_removed.dupe(), write_permits.dupe()),
        );
        drop(streams);
        let stream = MuxStream {
            frame_rx,
            our_port,
            their_port,
            dest_host,
            dest_port,
            fin_sent: AtomicBool::new(false),
            window_remaining,
            write_permits,
            stream_removed,
            buf: Bytes::new(),
            sink: self.sink.dupe(),
            dropped_ports_tx: self.dropped_ports_tx.dupe(),
        };
        trace!("sending stream to user");
        // This goes to the user
        stream_tx
            .send(stream)
            .await
            .map_err(|e| Error::SendStreamToClient(e.to_string()))
    }

    /// Send a frame.
    ///
    /// This method flushes the sink immediately after sending the frame,
    /// so it is designed to be used for control frames or frames that
    /// require immediate delivery.
    #[tracing::instrument(level = "trace")]
    pub(super) async fn send_frame(&self, frame: Frame) -> Result<(), Error> {
        self.sink.send_message(frame.try_into()?).await?;
        match self.sink.flush().await {
            Ok(()) => Ok(()),
            Err(tungstenite::Error::Io(ioerror)) => {
                if ioerror.kind() == std::io::ErrorKind::BrokenPipe {
                    // The other side closed the connection, which is acceptable
                    // here. The user should only discover this when they try to
                    // work with the stream for the next time.
                    Ok(())
                } else {
                    Err(ioerror.into())
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Close a port. That is, send `Rst` if `Fin` is not sent,
    /// and remove it from the map.
    #[tracing::instrument(level = "trace")]
    #[inline]
    pub async fn close_port(&self, our_port: u16, their_port: u16, fin_sent: bool) {
        // If the user did not call `poll_shutdown`, we need to send a `Rst` frame
        if !fin_sent {
            self.sink
                .send_message(
                    Frame::Stream(StreamFrame::new_rst(our_port, their_port))
                        .try_into()
                        .expect("Frame should be representable as a message (this is a bug)"),
                )
                .await
                .ok();
            self.sink.flush().await.ok();
        }
        // Free the port for reuse
        if let Some((sender, closed, _)) = self.streams.write().await.remove(&our_port) {
            // Make sure the user receives `EOF`.
            sender.send(Bytes::new()).await.ok();
            closed.store(true, Ordering::Relaxed);
        }
        debug!("freed port {}", our_port);
    }

    /// Should really only be called when the mux is dropped
    #[tracing::instrument(level = "trace")]
    async fn shutdown(&self) {
        debug!("closing all connections");
        let mut streams = self.streams.write().await;
        for (_, (sender, closed, _)) in streams.drain() {
            // Make sure the user receives `EOF`.
            sender.send(Bytes::new()).await.ok();
            // Stop all streams form sending stuff
            closed.store(true, Ordering::Relaxed);
        }
        drop(streams);
        // This also effectively `Rst`s all streams
        self.sink.close().await.ok();
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
