//! Client side of the multiplexor
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::frame::{DatagramFrame, Frame, StreamFlag, StreamFrame};
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
    pub server_port: u16,
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
    /// Interval between keepalive `Ping`s
    keepalive_interval: Option<std::time::Duration>,
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
    pub fn new(
        sink: Sink,
        stream: Stream,
        max_frame_size: usize,
        keepalive_interval: Option<std::time::Duration>,
    ) -> Self {
        let (datagram_tx, datagram_rx) = tokio::sync::mpsc::channel(super::DATAGRAM_BUFFER_SIZE);
        let (stream_tx, stream_rx) = tokio::sync::mpsc::channel(super::STREAM_BUFFER_SIZE);
        let (frame_tx, frame_rx) = tokio::sync::mpsc::channel(super::FRAME_BUFFER_SIZE);
        let (may_close_ports_tx, may_close_ports_rx) = tokio::sync::mpsc::unbounded_channel();

        let inner = Arc::new(MultiplexorInner {
            sink: RwLock::new(sink),
            stream: RwLock::new(stream),
            max_frame_size,
            keepalive_interval,
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

    /// Request a channel for `host` and `port`
    /// Returns `None` if the connection is closed
    pub async fn new_stream_channel(
        &self,
        host: Vec<u8>,
        port: u16,
    ) -> Result<MuxStream<Sink, Stream>, super::Error> {
        let host_len = host.len();
        let mut syn_payload =
            Vec::with_capacity(std::mem::size_of::<u8>() + std::mem::size_of::<u16>() + host_len);
        syn_payload[0] = u8::try_from(host_len)?;
        syn_payload[1..=host_len].copy_from_slice(&host);
        syn_payload[host_len + 1..].copy_from_slice(&port.to_be_bytes());
        // Allocate a new port
        let mut sport = 0;
        while self.inner.streams.read().await.contains_key(&sport) {
            sport = rand::thread_rng().gen_range(1..u16::MAX);
        }
        let syn_frame = StreamFrame {
            sport,
            dport: 0,
            flag: StreamFlag::Syn,
            data: syn_payload,
        };
        self.inner.frame_tx.send(Frame::Stream(syn_frame)).await?;
        let mut stream_rx = self.inner.stream_rx.write().await;
        // `unwrap`. Panic implies my logic is wrong
        let stream = stream_rx.recv().await.unwrap();
        Ok(stream)
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
    /// Client-side processing task
    pub async fn task(
        self: Arc<Self>,
        mut datagram_tx: tokio::sync::mpsc::Sender<DatagramFrame>,
        mut stream_tx: tokio::sync::mpsc::Sender<MuxStream<Sink, Stream>>,
        mut frame_rx: tokio::sync::mpsc::Receiver<Frame>,
        mut may_close_ports_rx: tokio::sync::mpsc::UnboundedReceiver<u16>,
    ) -> Result<(), super::Error> {
        let mut keepalive_interval = if let Some(interval) = self.keepalive_interval {
            Some(tokio::time::interval(interval))
        } else {
            None
        };
        loop {
            tokio::select! {
                Some(frame) = frame_rx.recv() => {
                    trace!("sending frame: {:?}", frame);
                    let mut sink = self.sink.write().await;
                    sink.send(frame.try_into()?).await?;
                }
                Some(port) = may_close_ports_rx.recv() => {
                    debug!("freeing port: {}", port);
                    self.streams.write().await.remove(&port);
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
                _ =  keepalive_interval.as_mut().unwrap().tick(), if keepalive_interval.is_some() => {
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

    /// Process a stream frame
    /// Does the following:
    /// - If `flag` is `Ack`, we create a `DuplexStream` and send it to the
    ///  `stream_tx` channel.
    /// - Otherwise, we find the `DuplexStream` with the matching `dport` and
    ///   - Send the data to the `DuplexStream`.
    ///   - If the `DuplexStream` is closed, send a `Fin` frame.
    async fn process_stream_frame(
        self: Arc<Self>,
        stream_frame: StreamFrame,
        stream_tx: &mut tokio::sync::mpsc::Sender<MuxStream<Sink, Stream>>,
    ) -> Result<(), super::Error> {
        let port = stream_frame.dport;
        match stream_frame.flag {
            StreamFlag::Syn => {
                panic!("`Syn` flag should not be received by client");
            }
            StreamFlag::Ack => {
                // See `server.rs`
                let (our, their) = tokio::io::duplex(super::DUPLEX_SIZE);
                let (our_rx, our_tx) = tokio::io::split(our);
                // Save the TX end of the stream so we can write to it when subsequent frames arrive
                let mut streams = self.streams.write().await;
                streams.insert(port, our_tx);
                drop(streams);
                let stream = MuxStream {
                    stream: their,
                    port,
                    server_port: stream_frame.sport,
                    inner: self.clone(),
                };
                // This goes to the user
                stream_tx.send(stream).await;
                // Read from the stream and pack frames
                tokio::spawn(self.stream_task(port, stream_frame.sport, our_rx));
            }
            StreamFlag::Fin => {
                self.close_write(port).await;
            }
            StreamFlag::Psh => {
                let mut streams = self.streams.write().await;
                if let Some(stream) = streams.get_mut(&port) {
                    stream.write_all(&stream_frame.data).await?;
                }
            }
        }
        Ok(())
    }

    super::common_methods::make_process_message! {}

    super::common_methods::make_close_all_write! {}

    super::common_methods::make_close_write! {}

    super::common_methods::make_stream_task! {}
}
