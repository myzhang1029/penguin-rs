//! Common remote helpers.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::client::{MuxStream, StreamCommand};
use bytes::Bytes;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tracing::info;

/// A Listener that can accept connections asynchronously.
pub trait AsyncAcceptable {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn accept(&self) -> impl Future<Output = io::Result<(Self::Stream, SocketAddr)>>;
}

impl AsyncAcceptable for TcpListener {
    type Stream = TcpStream;

    fn accept(&self) -> impl Future<Output = io::Result<(Self::Stream, SocketAddr)>> {
        self.accept()
    }
}

#[cfg(unix)]
impl AsyncAcceptable for tokio::net::UnixListener {
    type Stream = tokio::net::UnixStream;

    fn accept(&self) -> impl Future<Output = io::Result<(Self::Stream, SocketAddr)>> {
        async {
            self.accept()
                .await
                .map(|(stream, _)| (stream, SocketAddr::from(([0, 0, 0, 0], 0))))
        }
    }
}

/// Request a channel from the mux
/// Returns an error if the main loop timed out waiting for a response.
#[tracing::instrument(skip(stream_command_tx_permit), level = "debug")]
pub async fn request_tcp_channel(
    stream_command_tx_permit: mpsc::Permit<'_, StreamCommand>,
    dest_host: Bytes,
    dest_port: u16,
) -> Result<MuxStream, oneshot::error::RecvError> {
    let (tx, rx) = oneshot::channel();
    let stream_request = StreamCommand {
        tx,
        host: dest_host,
        port: dest_port,
    };
    stream_command_tx_permit.send(stream_request);
    rx.await
}

/// Open a TCP listener.
#[tracing::instrument(level = "trace")]
pub async fn open_tcp_listener(lhost: &str, lport: u16) -> io::Result<TcpListener> {
    let listener = TcpListener::bind((lhost, lport)).await?;
    // `expect`: at this point `listener` should be bound. Otherwise, it's a bug.
    let local_addr = listener
        .local_addr()
        .expect("Failed to get local address of TCP listener (this is a bug)");
    info!("Listening on {local_addr}");
    Ok(listener)
}
