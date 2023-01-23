//! Client side of the multiplexor
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
use super::locked_sink::LockedMessageSink;
use super::stream::MuxStream;
use super::{Error, IntKey, Role};
use crate::config;
use bytes::Buf;
use futures_util::{Sink as FutureSink, Stream as FutureStream, StreamExt};
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, trace};
use tungstenite::Message;

/// Multiplexor inner
pub(super) struct MultiplexorInner<Sink, Stream> {
    /// The role of this multiplexor
    pub(super) role: Role,
    /// The underlying `Sink` of messages
    pub(super) sink: LockedMessageSink<Sink>,
    /// The underlying `Stream` of messages
    pub(super) stream: RwLock<Stream>,
    /// Interval between keepalive `Ping`s
    pub(super) keepalive_interval: Option<std::time::Duration>,
    /// Open stream channels: our_port -> writer
    pub(super) streams: RwLock<HashMap<u16, mpsc::Sender<Vec<u8>>>>,
    /// Channel of received datagram frames for processing
    pub(super) datagram_rx: RwLock<mpsc::Receiver<DatagramFrame>>,
    /// Channel of established streams for processing
    pub(super) stream_rx: RwLock<mpsc::Receiver<MuxStream<Sink, Stream>>>,
    /// Channel for notifying the task of a dropped `MuxStream`.
    /// Sending 0 means that the multiplexor is being dropped and the
    /// task should exit.
    pub(super) dropped_ports_tx: mpsc::UnboundedSender<u16>,
}

impl<Sink, Stream> std::fmt::Debug for MultiplexorInner<Sink, Stream> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexorInner")
            .field("role", &self.role)
            .field("keepalive_interval", &self.keepalive_interval)
            .finish()
    }
}

impl<Sink, Stream> MultiplexorInner<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Sync + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Sync + Unpin + 'static,
{
    /// Processing task
    /// Does the following:
    /// - Receives messages from `WebSocket` and processes them
    /// - Sends received datagrams to the `datagram_tx` channel
    /// - Sends received streams to the appropriate handler
    /// - Responds to ping/pong messages
    #[tracing::instrument(skip(datagram_tx, stream_tx, dropped_ports_rx), level = "trace")]
    pub(super) async fn task(
        self: Arc<Self>,
        mut datagram_tx: mpsc::Sender<DatagramFrame>,
        mut stream_tx: mpsc::Sender<MuxStream<Sink, Stream>>,
        mut dropped_ports_rx: mpsc::UnboundedReceiver<u16>,
    ) -> Result<(), Error> {
        let mut keepalive_interval = MaybeInterval::new(self.keepalive_interval);
        loop {
            trace!("task loop");
            tokio::select! {
                Some(port) = dropped_ports_rx.recv() => {
                    if port == 0 {
                        debug!("mux dropped");
                        break;
                    }
                    debug!("freeing port {}", port);
                    self.streams.write().await.remove(&port);
                }
                Some(msg) = self.next_message() => {
                    let msg = msg?;
                    trace!("received message length = {}", msg.len());
                    if self.clone().process_message(msg, &mut datagram_tx, &mut stream_tx).await? {
                        break;
                    }
                }
                _ = keepalive_interval.tick() => {
                    trace!("sending ping");
                    self.sink.send_message(Message::Ping(vec![])).await?;
                }
                else => {
                    break;
                }
            }
        }
        self.shutdown().await;
        Ok(())
    }

    /// Get the next message
    #[tracing::instrument(level = "trace")]
    #[inline]
    async fn next_message(&self) -> Option<tungstenite::Result<Message>> {
        let mut stream = self.stream.write().await;
        stream.next().await
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
    async fn process_stream_frame(
        self: Arc<Self>,
        stream_frame: StreamFrame,
        stream_tx: &mut mpsc::Sender<MuxStream<Sink, Stream>>,
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
                let mut syn_data = bytes::Bytes::from(data);
                let host_len = syn_data.get_u8();
                let dest_host = syn_data.split_to(host_len as usize).to_vec();
                let dest_port = syn_data.get_u16();
                let our_port = u16::next_available_key(&*self.streams.read().await);
                trace!("port: {}", our_port);
                // `tx` is our end, `rx` is the user's end
                let (tx, rx) = mpsc::channel(config::STREAM_FRAME_BUFFER_SIZE);
                // Save the TX end of the stream so we can write to it when subsequent frames arrive
                let mut streams = self.streams.write().await;
                streams.insert(our_port, tx);
                drop(streams);
                let stream = MuxStream {
                    stream_rx: rx,
                    // "we" is `role == Server`
                    our_port,
                    // "they" is `role == Client`
                    their_port,
                    dest_host,
                    dest_port,
                    fin_sent: AtomicBool::new(false),
                    buf: None,
                    inner: self.clone(),
                };
                trace!("sending stream to user");
                // This goes to the user
                stream_tx
                    .send(stream)
                    .await
                    .map_err(|e| Error::SendStreamToClient(e.to_string()))?;
                // Send a `Ack`
                let ack_frame = Frame::Stream(StreamFrame::new_ack(our_port, their_port));
                trace!("sending ack");
                self.send_frame(ack_frame).await?;
            }
            StreamFlag::Ack => {
                if self.role == Role::Server {
                    return Err(Error::ServerReceivedAck);
                }
                // `tx` is our end, `rx` is the user's end
                let (tx, rx) = mpsc::channel(config::STREAM_FRAME_BUFFER_SIZE);
                // Save the TX end of the stream so we can write to it when subsequent frames arrive
                let mut streams = self.streams.write().await;
                streams.insert(our_port, tx);
                drop(streams);
                let stream = MuxStream {
                    stream_rx: rx,
                    // "we" is `role == Client`
                    our_port,
                    // "they" is `role == Server`
                    their_port,
                    dest_host: vec![],
                    dest_port: 0,
                    fin_sent: AtomicBool::new(false),
                    buf: None,
                    inner: self.clone(),
                };
                // This goes to the user
                stream_tx
                    .send(stream)
                    .await
                    .map_err(|e| Error::SendStreamToClient(e.to_string()))?;
            }
            StreamFlag::Rst | StreamFlag::Fin => {
                // So subsequent reads will return EOF
                self.streams.write().await.remove(&our_port);
            }
            StreamFlag::Psh => {
                let mut streams = self.streams.write().await;
                if let Some(frame_sender) = streams.get_mut(&our_port) {
                    if frame_sender.send(data).await.is_ok() {
                        return Ok(());
                    }
                }
                // else, the receiver is closed or the port does not exist
                let rst_frame = Frame::Stream(StreamFrame::new_rst(our_port, their_port));
                self.send_frame(rst_frame).await?;
            }
        }
        Ok(())
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

    /// Process an incoming message
    /// Returns `Ok(true)` if we should close
    #[tracing::instrument(skip(msg, datagram_tx, stream_tx), level = "trace")]
    async fn process_message(
        self: Arc<Self>,
        msg: Message,
        datagram_tx: &mut mpsc::Sender<DatagramFrame>,
        stream_tx: &mut mpsc::Sender<MuxStream<Sink, Stream>>,
    ) -> Result<bool, Error> {
        match msg {
            Message::Binary(data) => {
                let frame = data.try_into()?;
                match frame {
                    Frame::Datagram(datagram_frame) => {
                        trace!("Received datagram frame: {:?}", datagram_frame);
                        datagram_tx.send(datagram_frame).await?;
                    }
                    Frame::Stream(stream_frame) => {
                        trace!("Received stream frame: {:?}", stream_frame);
                        self.process_stream_frame(stream_frame, stream_tx).await?;
                    }
                }
                Ok(false)
            }
            Message::Ping(data) => {
                trace!("Received ping: {:?}", data);
                self.sink.send_message(Message::Pong(data)).await?;
                Ok(false)
            }
            Message::Pong(data) => {
                trace!("Received pong: {:?}", data);
                Ok(false)
            }
            Message::Close(_) => {
                debug!("Received close");
                Ok(true)
            }
            Message::Text(_) => {
                error!("Received `Text` message: {:?}", msg);
                Err(Error::TextMessage)
            }
            Message::Frame(_) => {
                unreachable!("`Frame` message should not be received");
            }
        }
    }

    /// Should really only be called when the muxer is dropped
    #[tracing::instrument(level = "trace")]
    async fn shutdown(&self) {
        debug!("closing all connections");
        let mut streams = self.streams.write().await;
        streams.clear();
        drop(streams);
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

    async fn tick(&mut self) {
        if let Some(interval) = &mut self.interval {
            interval.tick().await;
        } else {
            let never = futures_util::future::pending::<()>();
            never.await;
        }
    }
}
