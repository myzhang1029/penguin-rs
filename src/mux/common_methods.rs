//! Macros to create common codes for client and server
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

macro_rules! make_stream_task {
    () => {
        /// Spawn a reader task on a stream
        async fn stream_task(
            self: Arc<Self>,
            sport: u16,
            dport: u16,
            mut stream: tokio::io::ReadHalf<tokio::io::DuplexStream>,
        ) -> Result<(), super::Error> {
            loop {
                let mut buf = vec![0; super::READ_BUF_SIZE];
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    // Send a Fin
                    self.frame_tx
                        .send(Frame::Stream(StreamFrame {
                            sport,
                            dport,
                            data: vec![],
                            flag: StreamFlag::Fin,
                        }))
                        .await?;
                    return Ok(());
                }
                self.frame_tx
                    .send(Frame::Stream(StreamFrame {
                        sport,
                        dport,
                        data: buf[..n].to_vec(),
                        flag: StreamFlag::Psh,
                    }))
                    .await?;
            }
        }
    };
}

macro_rules! make_process_message {
    () => {
        /// Process an incoming message
        /// Returns `Ok(true)` if we should close
        async fn process_message(
            self: Arc<Self>,
            msg: Message,
            datagram_tx: &mut tokio::sync::mpsc::Sender<DatagramFrame>,
            stream_tx: &mut tokio::sync::mpsc::Sender<MuxStream<Sink, Stream>>,
        ) -> Result<bool, super::Error> {
            match msg {
                Message::Binary(data) => {
                    let frame = data.try_into().map_err(super::Error::InvalidMessage)?;
                    match frame {
                        Frame::Datagram(datagram_frame) => {
                            trace!("Received datagram frame: {:?}", datagram_frame);
                            datagram_tx.send(datagram_frame).await.unwrap();
                        }
                        Frame::Stream(stream_frame) => {
                            trace!("Received stream frame: {:?}", stream_frame);
                            self.process_stream_frame(stream_frame, stream_tx);
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
                    Err(super::Error::InvalidMessage("`Text` message received"))
                }
                Message::Frame(_) => {
                    unreachable!("`Frame` message should not be received");
                }
            }
        }
    };
}

macro_rules! make_close_write {
    () => {
        /// Close a port's write end.
        async fn close_write(&self, port: u16) {
            let mut streams = self.streams.write().await;
            if let Some(stream) = streams.get_mut(&port) {
                stream.shutdown().await;
                // Which should still allow `ReadHalf` to read the remaining data
                // Wait until it is `Drop`ped before removing the port from the map,
                // which is done in `task`
            }
        }
    };
}

macro_rules! make_close_all_write {
    () => {
        /// Close all write ends of the streams
        async fn close_all_write(&self) {
            debug!("closing all connections");
            let streams = self.streams.read().await;
            let ports = streams.keys();
            for port in ports {
                self.close_write(*port).await;
            }
        }
    };
}

macro_rules! make_asyncrw_proxy {
    () => {
        // Proxy the AsyncRead trait to the underlying stream so that users don't access `stream`
        impl<Sink, Stream> AsyncRead for MuxStream<Sink, Stream>
        where
            Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Unpin + 'static,
            Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Unpin + 'static,
        {
            #[inline]
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<Result<(), std::io::Error>> {
                std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
            }
        }

        impl<Sink, Stream> AsyncWrite for MuxStream<Sink, Stream>
        where
            Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Unpin + 'static,
            Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Unpin + 'static,
        {
            #[inline]
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<Result<usize, std::io::Error>> {
                std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
            }

            #[inline]
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), std::io::Error>> {
                std::pin::Pin::new(&mut self.stream).poll_flush(cx)
            }

            #[inline]
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), std::io::Error>> {
                std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
            }
        }
    };
}

pub(super) use make_asyncrw_proxy;
pub(super) use make_close_all_write;
pub(super) use make_close_write;
pub(super) use make_process_message;
pub(super) use make_stream_task;
