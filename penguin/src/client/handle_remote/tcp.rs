//! Run a remote TCP connection.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::FatalError;
use super::common::{request_tcp_channel, wait_break_or_spawn};
use crate::client::HandlerResources;
use async_acceptor::{AsyncAcceptable, AsyncAcceptableExt};
use bytes::Bytes;
use futures_util::TryFutureExt;
use tracing::warn;

/// Handle a TCP Inet remote
#[tracing::instrument(skip(listener, hr), level = "debug")]
pub(super) async fn handle_tcp<L: AsyncAcceptable + Send + Sync>(
    listener: L,
    rhost: &'static str,
    rport: u16,
    accept_multiple: bool,
    hr: &HandlerResources,
) -> Result<(), FatalError> {
    let rhost = rhost.as_bytes();
    loop {
        // This fails only if main has exited, which is a fatal error.
        let stream_command_tx_permit = hr
            .stream_command_tx
            .reserve()
            .await
            .or(Err(FatalError::RequestStream))?;
        // Only `accept` when we have a permit to send a request.
        // This way, the backpressure is propagated to the TCP listener.
        // Not being able to accept a TCP connection is a fatal error.
        let tcp_stream = listener.accept().await.map_err(FatalError::ClientIo)?;
        // A new channel is created for each incoming TCP connection.
        // It's already TCP, anyways.
        let channel =
            request_tcp_channel(stream_command_tx_permit, Bytes::from_static(rhost), rport)
                .await
                .or(Err(FatalError::MainLoopExitWithoutSendingStream))?;
        wait_break_or_spawn! {
            channel
                .into_copy_bidirectional(tcp_stream)
                .map_ok_or_else(
                    // Transient errors in the forwarder don't matter
                    |e| {
                        warn!("TCP forwarder failed: {e}");
                        Ok::<(), FatalError>(())
                    },
                    |_| Ok(()),
                ),
            accept_multiple
        }
    }
}
