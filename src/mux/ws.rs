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
            e => std::io::Error::other(e),
        }
    }
}

#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use tokio::io::DuplexStream;

    pub async fn get_pair(
        link_mss: Option<usize>,
    ) -> (
        tokio_tungstenite::WebSocketStream<DuplexStream>,
        tokio_tungstenite::WebSocketStream<DuplexStream>,
    ) {
        let (client, server) = tokio::io::duplex(link_mss.unwrap_or(2048));
        let client =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let server =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        (client, server)
    }
}
