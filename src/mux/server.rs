//! Server side of the multiplexor
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
use bytes::Buf;
use futures_util::{Sink as FutureSink, SinkExt, Stream as FutureStream, StreamExt};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
pub use tokio::io::DuplexStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::sync::RwLock;
use tracing::{debug, error, trace};
use tungstenite::Message;

/// All parameters of a stream channel
#[derive(Debug)]
pub struct MuxStream<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Unpin + 'static,
{
    /// Communication happens here
    pub stream: DuplexStream,
    /// Our port
    pub port: u16,
    /// Port of the other end
    pub client_port: u16,
    /// Forwarding destination
    pub host: Vec<u8>,
    /// Forwarding destination port
    pub dest_port: u16,
    inner: Arc<MultiplexorInner<Sink, Stream>>,
}

impl<Sink, Stream> Drop for MuxStream<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Unpin + 'static,
{
    fn drop(&mut self) {
        // Notify the task that this port is no longer in use
        self.inner
            .may_close_ports_tx
            .send(self.port)
            .expect("Failed to notify task of dropped port");
    }
}

/// Multiplexor inner
#[derive(Debug)]
pub struct MultiplexorInner<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Unpin + 'static,
{
    /// The underlying `Sink` of messages
    sink: RwLock<Sink>,
    /// The underlying `Stream` of messages
    stream: RwLock<Stream>,
    /// Maximum size of a frame
    max_frame_size: usize,
    /// Open stream channels
    streams: RwLock<HashMap<u16, WriteHalf<DuplexStream>>>,
    /// Channel of received datagram frames for processing
    datagram_rx: RwLock<tokio::sync::mpsc::Receiver<DatagramFrame>>,
    /// Channel of established streams for processing
    stream_rx: RwLock<tokio::sync::mpsc::Receiver<MuxStream<Sink, Stream>>>,
    /// Channel for the task to receive frames to send
    frame_tx: tokio::sync::mpsc::Sender<Frame>,
    /// Channel for notifying the task of a dropped port
    may_close_ports_tx: tokio::sync::mpsc::UnboundedSender<u16>,
}

#[derive(Clone, Debug)]
pub struct Multiplexor<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Unpin + 'static,
{
    inner: Arc<MultiplexorInner<Sink, Stream>>,
}

impl<Sink, Stream> Multiplexor<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Sync + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Sync + Unpin + 'static,
{
    /// Create a new `Multiplexor`
    pub fn new(sink: Sink, stream: Stream, max_frame_size: usize) -> Self {
        let (datagram_tx, datagram_rx) = tokio::sync::mpsc::channel(super::DATAGRAM_BUFFER_SIZE);
        let (stream_tx, stream_rx) = tokio::sync::mpsc::channel(super::STREAM_BUFFER_SIZE);
        let (frame_tx, frame_rx) = tokio::sync::mpsc::channel(super::FRAME_BUFFER_SIZE);
        let (may_close_ports_tx, may_close_ports_rx) = tokio::sync::mpsc::unbounded_channel();
        let inner = Arc::new(MultiplexorInner {
            sink: RwLock::new(sink),
            stream: RwLock::new(stream),
            max_frame_size,
            streams: RwLock::new(HashMap::new()),
            datagram_rx: RwLock::new(datagram_rx),
            stream_rx: RwLock::new(stream_rx),
            frame_tx,
            may_close_ports_tx,
        });
        tokio::spawn(
            inner
                .clone()
                .task(datagram_tx, stream_tx, frame_rx, may_close_ports_rx),
        );
        Self { inner }
    }

    /// Get the next available stream channel
    /// Returns `None` if the connection is closed
    pub async fn new_stream_channel(&self) -> Option<MuxStream<Sink, Stream>> {
        let mut stream_rx = self.inner.stream_rx.write().await;
        stream_rx.recv().await
    }

    /// Get the next available datagram
    /// Returns `None` if the connection is closed
    pub async fn get_datagram(&self) -> Option<DatagramFrame> {
        let mut datagram_rx = self.inner.datagram_rx.write().await;
        datagram_rx.recv().await
    }

    /// Send a datagram
    pub async fn send_datagram(&self, frame: DatagramFrame) -> Result<(), super::Error> {
        self.inner.frame_tx.send(Frame::Datagram(frame)).await?;
        Ok(())
    }
}

impl<Sink, Stream> MultiplexorInner<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Sync + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Sync + Unpin + 'static,
{
    /// Server-side processing task
    /// Does the following:
    /// - Receives frames from the `frame_rx` channel and sends them to WebSocket
    /// - Receives messages from WebSocket and processes them
    /// - Sends received datagrams to the `datagram_tx` channel
    /// - Sends received streams to the appropriate handler
    /// - Responds to ping/pong messages
    async fn task(
        self: Arc<Self>,
        mut datagram_tx: tokio::sync::mpsc::Sender<DatagramFrame>,
        mut stream_tx: tokio::sync::mpsc::Sender<MuxStream<Sink, Stream>>,
        mut frame_rx: tokio::sync::mpsc::Receiver<Frame>,
        mut may_close_ports_rx: tokio::sync::mpsc::UnboundedReceiver<u16>,
    ) -> Result<(), super::Error> {
        loop {
            tokio::select! {
                Some(frame) = frame_rx.recv() => {
                    trace!("sending frame: {:?}", frame);
                    let mut sink = self.sink.write().await;
                    sink.send(frame.try_into()?).await?;
                }
                mut stream = self.stream.write() => {
                    let msg = stream.next().await;
                    if let Some(msg) = msg {
                        let msg = msg?;
                        trace!("received message: {:?}", msg);
                        if self.clone().process_message(msg, &mut datagram_tx, &mut stream_tx).await? {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                Some(port) = may_close_ports_rx.recv() => {
                    debug!("freeing port: {}", port);
                    let mut streams = self.streams.write().await;
                    streams.remove(&port);
                }
                else => {
                    break;
                }
            }
        }
        self.close_all_write().await;
        Ok(())
    }

    crate::make_process_message! {}

    /// Process a stream frame
    /// Does the following:
    /// - If `dport` is `0`, we are creating a new stream.
    ///   - Find an available `dport` and send a `SynAck`.
    ///   - Create a new `DuplexStream` and send it to the `stream_tx` channel.
    /// - If `dport` is not `0`, we are sending data on an existing stream.
    ///   - Find the `DuplexStream` with the matching `dport`.
    ///   - Send the data to the `DuplexStream`.
    ///   - If the `DuplexStream` is closed, send a `Fin` frame.
    async fn process_stream_frame(
        self: Arc<Self>,
        stream_frame: StreamFrame,
        stream_tx: &mut tokio::sync::mpsc::Sender<MuxStream<Sink, Stream>>,
    ) -> Result<(), super::Error> {
        let server_port = stream_frame.dport;
        if server_port == 0 {
            assert!(stream_frame.flag == StreamFlag::Syn);
            let mut server_port = 0;
            // Decode Syn handshake
            let mut syn_data = bytes::Bytes::from(stream_frame.data);
            let host_len = syn_data.get_u8();
            let host = syn_data.split_to(host_len as usize).to_vec();
            let dest_port = syn_data.get_u16();

            // Allocate a new port
            while self.streams.read().await.contains_key(&server_port) {
                server_port = rand::thread_rng().gen_range(1..u16::MAX);
            }
            trace!("port: {}", server_port);

            // So we expose an `AsyncRead` and `AsyncWrite` interface to the user
            // `our` is our end, `their` is the user's end
            let (our, their) = tokio::io::duplex(super::DUPLEX_SIZE);
            let (our_rx, our_tx) = tokio::io::split(our);
            // Save the TX end of the stream so we can write to it when subsequent frames arrive
            let mut streams = self.streams.write().await;
            streams.insert(server_port, our_tx);
            drop(streams);
            let stream = MuxStream {
                stream: their,
                port: server_port,
                client_port: stream_frame.sport,
                host,
                dest_port,
                inner: self.clone(),
            };
            // This goes to the user
            stream_tx.send(stream).await;
            // Read from the stream and pack frames
            tokio::spawn(self.stream_task(server_port, stream_frame.sport, our_rx));
            // Send a Ack
            let ack_frame = Frame::Stream(StreamFrame {
                sport: server_port,
                dport: stream_frame.sport,
                data: vec![],
                flag: StreamFlag::Ack,
            });
        } else {
            let mut streams = self.streams.write().await;
            let stream = streams
                .get_mut(&server_port)
                .ok_or_else(|| super::Error::InvalidMessage("No stream with specified dport"))?;
            if stream_frame.flag == StreamFlag::Fin {
                self.close_write(server_port).await;
            }
            stream.write_all(&stream_frame.data).await?;
        }
        Ok(())
    }

    crate::make_close_all_write! {}

    crate::make_close_write! {}

    crate::make_stream_task! {}
}
