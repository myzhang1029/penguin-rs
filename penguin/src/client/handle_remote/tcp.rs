//! Run a remote TCP connection.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::FatalError;
use super::common::{AsyncAcceptable, request_tcp_channel};
use crate::client::HandlerResources;
use bytes::Bytes;
use tracing::warn;

/// Handle a TCP Inet remote
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
