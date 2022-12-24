//! Penguin client.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod handle_remote;
mod ws_connect;

use crate::arg::ClientArgs;
use crate::mux::{Multiplexor, Role, WebSocket};
use futures_util::pin_mut;
use handle_remote::handle_remote;
use log::{info, trace, warn};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time;
use tokio_stream_multiplexor::DuplexStream;

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

// There is no extra information needed for the main loop
/// Type that local listeners send to the main loop to request a connection
type Command = oneshot::Sender<DuplexStream>;

pub async fn client_main(args: ClientArgs) -> Result<(), Error> {
    trace!("Client args: {args:?}");
    // TODO: Temporary, remove when implemented
    if args.proxy.is_some() {
        warn!("Proxy not implemented yet");
    }
    let mut current_retry_count: u32 = 0;
    // Initial retry interval is 200ms
    let mut current_retry_interval: u64 = 200;
    // Channel for listeners to send commands to the main loop
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(32);
    let mut jobs = JoinSet::new();
    // Spawn listeners
    for remote in args.remote {
        // According to the docs, we should clone the sender before spawning the task
        let cmd_tx = cmd_tx.clone();
        jobs.spawn(handle_remote(remote, cmd_tx));
    }
    // Main loop with retry
    loop {
        match ws_connect::handshake(
            &args.server,
            args.ws_psk.as_deref(),
            args.hostname.as_deref(),
            args.header.clone(),
            args.tls_ca.as_deref(),
            args.tls_key.as_deref(),
            args.tls_cert.as_deref(),
            args.tls_skip_verify,
        )
        .await
        {
            Ok(ws_stream) => {
                current_retry_count = 0;
                current_retry_interval = 1;
                on_connected(ws_stream, &mut cmd_rx, args.keepalive).await?;
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
        warn!("Control channel not connected, retrying in {current_retry_interval} seconds");
        current_retry_count += 1;
        if args.max_retry_count != 0 && current_retry_count > args.max_retry_count {
            warn!("Max retry count reached, giving up");
            return Err(Error::MaxRetryCountReached);
        }
        time::sleep(time::Duration::from_millis(current_retry_interval)).await;
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
    command_rx: &mut mpsc::Receiver<Command>,
    keepalive: u64,
) -> Result<(), Error> {
    let ws = WebSocket::new(ws_stream);
    let mut mux = Multiplexor::new(ws, Role::Client);
    if let Err(e) = mux.establish_control_channel().await {
        if retryable_errors(&e) {
            return Ok(());
        }
        return Err(e.into());
    };
    info!("Connected to server");
    if keepalive == 0 {
        // Just keep the main thread alive and wait for a command
        while let Some(sender) = command_rx.recv().await {
            get_send_chan(&mut mux, sender).await?;
        }
        Ok(())
    } else {
        loop {
            let try_recv_command = command_rx.recv();
            pin_mut!(try_recv_command);
            // Wait for a command or do a keepalive
            if let Ok(Some(sender)) =
                time::timeout(time::Duration::from_secs(keepalive), &mut try_recv_command).await
            {
                get_send_chan(&mut mux, sender).await?;
            }
            if let Err(e) = mux.ping().await {
                warn!("Failed to send keepalive: {e}");
                return Ok(());
            }
        }
    }
}

/// Get a new channel from the multiplexor and send it to the handler.
async fn get_send_chan(
    mux: &mut Multiplexor<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tungstenite::Message,
        tungstenite::Error,
    >,
    sender: oneshot::Sender<DuplexStream>,
) -> Result<(), Error> {
    trace!("Connecting to a new port");
    let (stream, _) = mux.open_channel().await?;
    sender.send(stream).unwrap();
    trace!("Send stream to handler");
    Ok(())
}

/// Returns true if we should retry the connection.
fn retryable_errors(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::AddrNotAvailable
        || e.kind() == std::io::ErrorKind::ConnectionReset
        || e.kind() == std::io::ErrorKind::ConnectionRefused
}
