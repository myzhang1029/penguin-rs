//! Penguin client.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod handle_remote;
mod ws_connect;

use crate::arg::ClientArgs;
use crate::mux::{Multiplexor, Role, WebSocket};
use handle_remote::handle_remote;
use log::{info, trace, warn};
use thiserror::Error;
use tokio::task::JoinSet;

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to parse remote: {0}")]
    ParseRemote(#[from] crate::parse_remote::Error),
    #[error("failed to connect WebSocket: {0}")]
    Connect(#[from] ws_connect::Error),
    #[error(transparent)]
    WebSocketIO(#[from] std::io::Error),
    #[error("max retry count reached")]
    MaxRetryCountReached,
    #[error(transparent)]
    Mux(#[from] crate::mux::Error),
}

pub async fn client_main(args: ClientArgs) -> Result<(), Error> {
    trace!("Client args: {args:?}");
    // TODO: Temporary, remove when implemented
    if args.proxy.is_some() {
        warn!("Proxy not implemented yet");
    }
    let mut current_retry_count: u32 = 0;
    let mut current_retry_interval: u64 = 1;
    // Main retry loop
    loop {
        match ws_connect::handshake(&args).await {
            Ok(ws_stream) => {
                current_retry_count = 0;
                current_retry_interval = 1;
                on_connected(ws_stream, &args).await?
            }
            Err(ws_connect::Error::Tungstenite(tungstenite::error::Error::Io(e))) => {
                if !retryable_errors(&e) {
                    return Err(e.into());
                }
                // If we get here, retry.
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        // If we get here, retry.
        warn!("Control channel not connected, retrying in {current_retry_interval} seconds.");
        current_retry_count += 1;
        if args.max_retry_count != 0 && current_retry_count > args.max_retry_count {
            warn!("Max retry count reached, giving up.");
            return Err(Error::MaxRetryCountReached);
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(current_retry_interval)).await;
        if current_retry_interval < args.max_retry_interval {
            current_retry_interval *= 2;
        }
    }
}

/// Called when the main socket is connected.
/// If this function returns `Ok`, the client will retry;
/// if it returns `Err`, the client will exit.
async fn on_connected(
    ws_stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    args: &ClientArgs,
) -> Result<(), Error> {
    let ws = WebSocket::new(ws_stream);
    let mut mux = Multiplexor::new(ws, Role::Client);
    if let Err(e) = mux.establish_control_channel().await {
        if retryable_errors(&e) {
            return Ok(());
        } else {
            return Err(e.into());
        }
    };
    info!("Connected to server.");
    let mut jobs = JoinSet::new();
    // Clone the remote list so the original is not moved into the loop
    let remotes = args.remote.clone();
    for (idx, remote) in (2..).zip(remotes) {
        trace!("Connecting to port {idx}.");
        let stream = mux.open_channel().await?;
        jobs.spawn(handle_remote(remote, stream));
        trace!("Spawned task on port {idx}.");
    }
    // Keepalive loop
    loop {
        if args.keepalive != 0 {
            tokio::time::sleep(tokio::time::Duration::from_secs(args.keepalive)).await;
            if let Err(e) = mux.ping().await {
                warn!("Failed to send keepalive: {e}");
                jobs.shutdown().await;
                return Ok(());
            }
        } else {
            // Just keep the main thread alive
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
}

/// Returns true if we should retry the connection.
fn retryable_errors(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::AddrNotAvailable
        || e.kind() == std::io::ErrorKind::ConnectionReset
        || e.kind() == std::io::ErrorKind::ConnectionRefused
}
