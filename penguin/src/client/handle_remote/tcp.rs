//! Run a remote TCP connection.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::FatalError;
use super::common::{AsyncAcceptable, request_tcp_channel};
use crate::client::HandlerResources;
use crate::client::MaybeRetryableError;
use bytes::Bytes;
use tokio::io as tio;
use tracing::{error, info, warn};

/// Handle a TCP Inet->Inet remote.
#[tracing::instrument(skip(listener, handler_resources), level = "debug")]
pub(super) async fn handle_tcp<L: AsyncAcceptable>(
    listener: L,
    rhost: &'static str,
    rport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), FatalError> {
    let rhost = rhost.as_bytes();
    loop {
        // This fails only if main has exited, which is a fatal error.
        let stream_command_tx_permit = handler_resources
            .stream_command_tx
            .reserve()
            .await
            .or(Err(FatalError::RequestStream))?;
        // Only `accept` when we have a permit to send a request.
        // This way, the backpressure is propagated to the TCP listener.
        // Not being able to accept a TCP connection is a fatal error.
        let (mut tcp_stream, _) = listener.accept().await.map_err(FatalError::ClientIo)?;
        // A new channel is created for each incoming TCP connection.
        // It's already TCP, anyways.
        let channel =
            request_tcp_channel(stream_command_tx_permit, Bytes::from_static(rhost), rport)
                .await
                .or(Err(FatalError::MainLoopExitWithoutSendingStream))?;
        // Transient errors in the forwarder don't matter.
        tokio::spawn(async move {
            if let Err(error) = channel.into_copy_bidirectional(&mut tcp_stream).await {
                warn!("TCP forwarder failed: {error}");
            }
        });
    }
}

/// Handle a TCP Stdio->Inet remote.
#[tracing::instrument(skip(handler_resources))]
pub(super) async fn handle_tcp_stdio(
    rhost: &'static str,
    rport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), FatalError> {
    let mut stdio = tio::join(tio::stdin(), tio::stdout());
    let rhost = rhost.as_bytes();
    // We want `loop` to be able to continue after a connection failure
    loop {
        // This fails only if main has exited, which is a fatal error.
        let stream_command_tx_permit = handler_resources
            .stream_command_tx
            .reserve()
            .await
            .or(Err(FatalError::RequestStream))?;
        let channel =
            request_tcp_channel(stream_command_tx_permit, Bytes::from_static(rhost), rport)
                .await
                .or(Err(FatalError::MainLoopExitWithoutSendingStream))?;
        match channel.into_copy_bidirectional(&mut stdio).await {
            Ok(_) => {
                info!("TCP stdio connection closed");
                break Ok(());
            }
            Err(error) if error.retryable() => {
                warn!("TCP stdio connection failed: {error}");
            }
            Err(error) => {
                error!("TCP stdio connection failed: {error}");
                break Err(FatalError::ClientIo(error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::open_tcp_listener;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_open_tcp_listener() {
        crate::tests::setup_logging();
        let listener = open_tcp_listener("127.0.0.1", 0).await.unwrap();
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
}
