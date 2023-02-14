//! Abstraction over Tungstenite's WebSocket implementation.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use futures_util::{Sink, Stream};
pub use tokio_tungstenite::tungstenite::{protocol::Role, Error, Message, Result};

/// A generic WebSocket stream
pub trait WebSocketStream:
    Stream<Item = std::result::Result<Message, Error>>
    + Sink<Message, Error = Error>
    + Send
    + Unpin
    + 'static
{
    /// Whether the implementation sends `Pong` automatically.
    fn ping_auto_pong(&self) -> bool;
}

impl<RW> WebSocketStream for tokio_tungstenite::WebSocketStream<RW>
where
    RW: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    fn ping_auto_pong(&self) -> bool {
        true
    }
}

/// Utilities for working with WebSocket errors.
pub trait WebSocketError {
    /// Whether the error is caused by the connection being closed.
    fn because_closed(&self) -> bool;
    /// Convert the error into a `std::io::Error`.
    fn into_io_error(self) -> std::io::Error;
}

impl WebSocketError for Error {
    fn because_closed(&self) -> bool {
        match self {
            Self::ConnectionClosed | Self::AlreadyClosed => true,

            Self::Io(ioerror) if ioerror.kind() == std::io::ErrorKind::BrokenPipe => true,
            _ => false,
        }
    }

    fn into_io_error(self) -> std::io::Error {
        match self {
            Self::Io(e) => e,
            Self::AlreadyClosed | Self::ConnectionClosed => std::io::ErrorKind::BrokenPipe.into(),
            e => std::io::Error::new(std::io::ErrorKind::Other, e),
        }
    }
}

#[cfg(test)]
pub(crate) mod mock {
    #![allow(unused_imports)]
    #![allow(dead_code)]
    use super::*;
    use parking_lot::Mutex;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::DuplexStream;

    /// A mock WebSocket stream.
    #[derive(Debug)]
    pub(crate) struct MockWebSocket {
        /// Messages to send.
        pub other_end_recv_queue: Arc<Mutex<VecDeque<Message>>>,
        /// Messages received.
        pub recv_queue: Arc<Mutex<VecDeque<Message>>>,
        /// Role.
        pub role: Role,
    }

    impl Stream for MockWebSocket {
        type Item = std::result::Result<Message, Error>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut recv_queue = self.recv_queue.lock();
            if let Some(msg) = recv_queue.pop_front() {
                Poll::Ready(Some(Ok(msg)))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    impl Sink<Message> for MockWebSocket {
        type Error = Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, msg: Message) -> Result<(), Self::Error> {
            let mut other_end_recv_queue = self.other_end_recv_queue.lock();
            other_end_recv_queue.push_back(msg);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl WebSocketStream for MockWebSocket {
        fn ping_auto_pong(&self) -> bool {
            false
        }
    }
    // If we are not using `loom`, we create a pair of mock WebSocket streams
    // from a `tokio` `DuplexStream`.
    pub(crate) async fn get_pair() -> (
        tokio_tungstenite::WebSocketStream<DuplexStream>,
        tokio_tungstenite::WebSocketStream<DuplexStream>,
    ) {
        let (client, server) = tokio::io::duplex(10);
        let client =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let server =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        (client, server)
    }
}
