//! Common remote helpers
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::client::handle_remote::FatalError;
use crate::client::{MuxStream, StreamCommand};
use bytes::Bytes;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tracing::info;

/// A Listener that can accept connections asynchronously
pub trait AsyncAcceptable {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    async fn accept(&self) -> io::Result<(Self::Stream, SocketAddr)>;
}

impl AsyncAcceptable for TcpListener {
    type Stream = TcpStream;
    async fn accept(&self) -> io::Result<(Self::Stream, SocketAddr)> {
        self.accept().await
    }
}

#[cfg(unix)]
impl AsyncAcceptable for UnixListener {
    type Stream = tokio::net::UnixStream;
    async fn accept(&self) -> io::Result<(Self::Stream, SocketAddr)> {
        self.accept()
            .await
            .map(|(stream, _)| (stream, SocketAddr::from(([0, 0, 0, 0], 0))))
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

/// Open a TCP listener
#[tracing::instrument(level = "trace")]
pub async fn bind_tcp(lhost: &str, lport: u16) -> Result<TcpListener, FatalError> {
    let listener = TcpListener::bind((lhost, lport))
        .await
        .map_err(FatalError::ClientIo)?;
    // `expect`: at this point `listener` should be bound. Otherwise, it's a bug.
    let local_addr = listener
        .local_addr()
        .expect("Failed to get local address of TCP listener (this is a bug)");
    info!("Listening on {local_addr}");
    Ok(listener)
}

/// Open a STREAM type unix domain socket listener
#[tracing::instrument(level = "trace")]
#[cfg(unix)]
#[inline]
pub async fn bind_uds(path: &std::path::Path) -> Result<UnixListener, FatalError> {
    if path.exists() {
        tokio::fs::remove_file(path)
            .await
            .map_err(FatalError::ClientIo)?;
    }
    let listener = UnixListener::bind(path).map_err(FatalError::ClientIo)?;
    let local_addr = listener
        .local_addr()
        .expect("Failed to get local address of TCP listener (this is a bug)");
    info!("Listening on {local_addr:?}");
    Ok(listener)
}
#[tracing::instrument(level = "trace")]
#[cfg(not(unix))]
#[inline]
pub async fn bind_uds(_path: &std::path::Path) -> Result<TcpListener, FatalError> {
    Err(FatalError::NotAvailable("unix domain sockets"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_bind_tcp() {
        crate::tests::setup_logging();
        let listener = bind_tcp("127.0.0.1", 0).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        assert_eq!(local_addr.ip(), std::net::Ipv4Addr::LOCALHOST);
        let accept_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut stream = tokio::net::TcpStream::connect(local_addr).await.unwrap();
        stream.shutdown().await.unwrap();
        accept_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_bind_uds() {
        crate::tests::setup_logging();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sock");
        #[cfg(unix)]
        {
            let listener = bind_uds(&path).await.unwrap();
            let accept_task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
            stream.shutdown().await.unwrap();
            accept_task.await.unwrap();
        }
        #[cfg(not(unix))]
        {
            let result = bind_uds(&path).await;
            assert!(result.is_err());
        }
    }
}
