//! Client side of the multiplexor
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
use super::{Error, IntKey, Role};
use crate::config;
use bytes::Buf;
use futures_util::{Sink as FutureSink, SinkExt, Stream as FutureStream, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
pub use tokio::io::DuplexStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::sync::RwLock;
use tracing::{debug, error, trace, warn};
use tungstenite::Message;

/// All parameters of a stream channel
#[derive(Debug)]
pub struct MuxStream<Sink, Stream> {
    /// Communication happens here
    stream: DuplexStream,
    /// Our port
    pub our_port: u16,
    /// Port of the other end
    pub their_port: u16,
    /// Forwarding destination. Only used on `Role::Server`
    pub dest_host: Vec<u8>,
    /// Forwarding destination port. Only used on `Role::Server`
    pub dest_port: u16,
    inner: Arc<MultiplexorInner<Sink, Stream>>,
}

impl<Sink, Stream> Drop for MuxStream<Sink, Stream> {
    fn drop(&mut self) {
        // Notify the task that this port is no longer in use
        self.inner
            .dropped_ports_tx
            .send(self.our_port)
            // Maybe the task has already exited, who knows
            .unwrap_or_else(|_| warn!("Failed to notify task of dropped port"));
    }
}

// Proxy the AsyncRead trait to the underlying stream so that users don't access `stream`
impl<Sink, Stream> AsyncRead for MuxStream<Sink, Stream> {
    #[inline]
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<Sink, Stream> AsyncWrite for MuxStream<Sink, Stream> {
    #[inline]
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Multiplexor inner
#[derive(Debug)]
pub(super) struct MultiplexorInner<Sink, Stream> {
    /// The role of this multiplexor
    pub(super) role: Role,
    /// The underlying `Sink` of messages
    pub(super) sink: RwLock<Sink>,
    /// The underlying `Stream` of messages
    pub(super) stream: RwLock<Stream>,
    /// Interval between keepalive `Ping`s
    pub(super) keepalive_interval: Option<std::time::Duration>,
    /// Open stream channels
    pub(super) streams: RwLock<HashMap<u16, WriteHalf<DuplexStream>>>,
    /// Channel of received datagram frames for processing
    pub(super) datagram_rx: RwLock<tokio::sync::mpsc::Receiver<DatagramFrame>>,
    /// Channel of established streams for processing
    pub(super) stream_rx: RwLock<tokio::sync::mpsc::Receiver<MuxStream<Sink, Stream>>>,
    /// Channel for notifying the task of a dropped port. Sending 0 means that the
    /// multiplexor is being dropped and the task should exit.
    pub(super) dropped_ports_tx: tokio::sync::mpsc::UnboundedSender<u16>,
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
    #[tracing::instrument(skip_all, level = "trace")]
    pub(super) async fn task(
        self: Arc<Self>,
        mut datagram_tx: tokio::sync::mpsc::Sender<DatagramFrame>,
        mut stream_tx: tokio::sync::mpsc::Sender<MuxStream<Sink, Stream>>,
        mut dropped_ports_rx: tokio::sync::mpsc::UnboundedReceiver<u16>,
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
                    debug!("freeing port: {}", port);
                    self.streams.write().await.remove(&port);
                }
                Some(msg) = self.next_message() => {
                    let msg = msg?;
                    trace!("received message: {}", msg.len());
                    if self.clone().process_message(msg, &mut datagram_tx, &mut stream_tx).await? {
                        break;
                    }
                }
                _ = keepalive_interval.tick() => {
                    let mut sink = self.sink.write().await;
                    trace!("sending ping");
                    sink.send(Message::Ping(vec![])).await?;
                }
                else => {
                    break;
                }
            }
        }
        self.close_all_write().await;
        Ok(())
    }

    /// Get the next message
    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    async fn next_message(&self) -> Option<tungstenite::Result<Message>> {
        let mut stream = self.stream.write().await;
        stream.next().await
    }

    /// Process a stream frame
    /// Does the following:
    /// - If `flag` is `Syn`,
    ///   - Find an available `dport` and send a `Ack`.
    ///   - Create a new `DuplexStream` and send it to the `stream_tx` channel.
    /// - If `flag` is `Ack`,
    ///   - Create a `DuplexStream` and send it to the `stream_tx` channel.
    /// - Otherwise, we find the `DuplexStream` with the matching `dport` and
    ///   - Send the data to the `DuplexStream`.
    ///   - If the `DuplexStream` is closed, send a `Fin` frame.
    #[tracing::instrument(skip_all, level = "trace")]
    async fn process_stream_frame(
        self: Arc<Self>,
        stream_frame: StreamFrame,
        stream_tx: &mut tokio::sync::mpsc::Sender<MuxStream<Sink, Stream>>,
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
                // `our` is our end, `their` is the user's end
                let (our, their) = tokio::io::duplex(config::DUPLEX_SIZE);
                let (our_rx, our_tx) = tokio::io::split(our);
                // Save the TX end of the stream so we can write to it when subsequent frames arrive
                let mut streams = self.streams.write().await;
                streams.insert(our_port, our_tx);
                drop(streams);
                let stream = MuxStream {
                    stream: their,
                    // "we" is `role == Server`
                    our_port,
                    // "they" is `role == Client`
                    their_port,
                    dest_host,
                    dest_port,
                    inner: self.clone(),
                };
                trace!("sending stream to user");
                // This goes to the user
                stream_tx
                    .send(stream)
                    .await
                    .map_err(|e| Error::SendStreamToClient(e.to_string()))?;
                // Send a Ack
                let ack_frame = Frame::Stream(StreamFrame::new_ack(our_port, their_port));
                trace!("sending ack");
                self.send_frame(ack_frame).await?;
                // Read from the stream and pack frames
                tokio::spawn(self.stream_task(our_port, their_port, our_rx));
            }
            StreamFlag::Ack => {
                if self.role == Role::Server {
                    return Err(Error::ServerReceivedAck);
                }
                // See `server.rs`
                let (our, their) = tokio::io::duplex(config::DUPLEX_SIZE);
                let (our_rx, our_tx) = tokio::io::split(our);
                // Save the TX end of the stream so we can write to it when subsequent frames arrive
                let mut streams = self.streams.write().await;
                streams.insert(our_port, our_tx);
                drop(streams);
                let stream = MuxStream {
                    stream: their,
                    // "we" is `role == Client`
                    our_port,
                    // "they" is `role == Server`
                    their_port,
                    dest_host: vec![],
                    dest_port: 0,
                    inner: self.clone(),
                };
                // This goes to the user
                stream_tx
                    .send(stream)
                    .await
                    .map_err(|e| Error::SendStreamToClient(e.to_string()))?;
                // Read from the stream and pack frames
                tokio::spawn(self.stream_task(our_port, their_port, our_rx));
            }
            StreamFlag::Rst | StreamFlag::Fin => {
                self.close_write(our_port).await;
            }
            StreamFlag::Psh => {
                let mut streams = self.streams.write().await;
                if let Some(stream) = streams.get_mut(&our_port) {
                    stream.write_all(&data).await?;
                } else {
                    let rst_frame = Frame::Stream(StreamFrame::new_rst(our_port, their_port));
                    warn!("Port {our_port} not found, sending RST");
                    self.send_frame(rst_frame).await?;
                }
            }
        }
        Ok(())
    }

    /// Send a frame
    #[tracing::instrument(skip_all, level = "trace")]
    pub(super) async fn send_frame(&self, frame: Frame) -> Result<(), Error> {
        let mut sink = self.sink.write().await;
        sink.send(frame.try_into()?).await?;
        Ok(())
    }

    /// Process an incoming message
    /// Returns `Ok(true)` if we should close
    #[tracing::instrument(skip_all, level = "trace")]
    async fn process_message(
        self: Arc<Self>,
        msg: Message,
        datagram_tx: &mut tokio::sync::mpsc::Sender<DatagramFrame>,
        stream_tx: &mut tokio::sync::mpsc::Sender<MuxStream<Sink, Stream>>,
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
                let mut sink = self.sink.write().await;
                sink.send(Message::Pong(data)).await?;
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

    /// Spawn a reader task on a stream
    #[tracing::instrument(skip(self, stream), level = "trace")]
    async fn stream_task(
        self: Arc<Self>,
        sport: u16,
        dport: u16,
        mut stream: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    ) -> Result<(), Error> {
        loop {
            let mut buf = vec![0; config::READ_BUF_SIZE];
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                // Send a Fin
                self.send_frame(Frame::Stream(StreamFrame {
                    sport,
                    dport,
                    data: vec![],
                    flag: StreamFlag::Fin,
                }))
                .await?;
                return Ok(());
            }
            self.send_frame(Frame::Stream(StreamFrame {
                sport,
                dport,
                data: buf[..n].to_vec(),
                flag: StreamFlag::Psh,
            }))
            .await?;
        }
    }

    /// Close a port's write end.
    #[tracing::instrument(skip(self), level = "trace")]
    async fn close_write(&self, port: u16) {
        let mut streams = self.streams.write().await;
        if let Some(stream) = streams.get_mut(&port) {
            stream.shutdown().await.unwrap_or_else(|e| {
                warn!("Failed to shutdown stream: {:?}", e);
            });
            // Which should still allow `ReadHalf` to read the remaining data
            // Wait until it is `Drop`ped before removing the port from the map,
            // which is done in `task`
        }
    }

    /// Close all write ends of the streams
    #[tracing::instrument(skip_all, level = "trace")]
    async fn close_all_write(&self) {
        debug!("closing all connections");
        let streams = self.streams.read().await;
        let ports: Vec<_> = streams.keys().copied().collect();
        drop(streams);
        for port in ports {
            self.close_write(port).await;
        }
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
