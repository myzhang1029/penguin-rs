//! Penguin client.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod handle_remote;
pub(crate) mod ws_connect;

use crate::arg::ClientArgs;
use crate::mux::{DuplexStream, Multiplexor, Role, WebSocket};
use handle_remote::handle_remote;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time;
use tracing::{error, info, trace, warn};

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
    #[error("cannot put sender back to the queue: {0}")]
    CommandPutBack(#[from] mpsc::error::SendError<Command>),
}

// Send the information about how to send the stream to the listener
/// Type that local listeners send to the main loop to request a connection
type Command = oneshot::Sender<DuplexStream>;

#[tracing::instrument(level = "trace")]
pub async fn client_main(args: &'static ClientArgs) -> Result<(), Error> {
    // TODO: Temporary, remove when implemented
    // Blocked on `snapview/tungstenite-rs#177`
    if args.proxy.is_some() {
        warn!("Proxy not implemented yet");
    }
    let mut current_retry_count: u32 = 0;
    // Initial retry interval is 200ms
    let mut current_retry_interval: u64 = 200;
    // Channel for listeners to send commands to the main loop
    let (mut cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(32);
    let mut jobs = JoinSet::new();
    // Spawn listeners. See `handle_remote.rs` for the implementation considerations.
    for remote in &args.remote {
        // According to the docs, we should clone the sender for each task
        let cmd_tx = cmd_tx.clone();
        jobs.spawn(async move {
            if let Err(error) = handle_remote(remote, cmd_tx).await {
                error!("Listener failed: {error}");
            }
        });
    }
    // Retry loop
    loop {
        match ws_connect::handshake(
            &args.server,
            args.ws_psk.as_ref(),
            args.hostname.as_ref(),
            &args.header,
            args.tls_ca.as_deref(),
            args.tls_key.as_deref(),
            args.tls_cert.as_deref(),
            args.tls_skip_verify,
        )
        .await
        {
            Ok(ws_stream) => {
                on_connected(ws_stream, &mut cmd_rx, &mut cmd_tx, args.keepalive).await?;
                warn!("Disconnected from server");
                // Since we once connected, reset the retry count
                current_retry_count = 0;
                current_retry_interval = 200;
                // Now retry
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
        warn!("Control channel not connected, retrying in {current_retry_interval} ms");
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

/// Called when the main socket is connected. Accepts connection requests from
/// local listeners, establishes them, and sends them back to the listeners.
/// If this function returns `Ok`, the client will retry;
/// if it returns `Err`, the client will exit.
///
/// We want a copy of `command_tx` because we want to put the sender back if we
/// fail to get a new channel for the remote.
#[tracing::instrument(skip_all, level = "debug")]
async fn on_connected(
    ws_stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    command_rx: &mut mpsc::Receiver<Command>,
    command_tx: &mut mpsc::Sender<Command>,
    keepalive: u64,
) -> Result<(), Error> {
    let ws = WebSocket::new(ws_stream);
    let mut mux = Multiplexor::new(ws, Role::Client);
    mux.establish_control_channel()
        .await
        .or_else(maybe_retryable)?;
    info!("Connected to server");
    if keepalive == 0 {
        // Just keep the main thread alive and wait for a command
        while let Some(sender) = command_rx.recv().await {
            if !get_send_chan_or_put_back(&mut mux, sender, command_tx).await? {
                break;
            }
        }
    } else {
        let mut keepalive_interval = time::interval(time::Duration::from_secs(keepalive));
        loop {
            tokio::select! {
                Some(sender) = command_rx.recv() => {
                    if !get_send_chan_or_put_back(&mut mux, sender, command_tx).await? {
                        break;
                    }
                }
                // If there are too many `get_send_chan_or_put_back` requests, we may
                // not be able to send keepalive packets in time, but that's fine because
                // the connection won't be closed if we are using it.
                _ = keepalive_interval.tick() => {
                    if let Err(e) = mux.ping().await {
                        warn!("Failed to send keepalive: {e}");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Get a new channel from the multiplexor and send it to the handler.
/// If we fail, put the sender back onto the `mpsc`.
/// This carries the semantics that `Err(_)` means we should not retry.
/// Returns `true` if we got a new channel, `false` if we put the sender back
/// (and we should probably go back to the main loop and reconnect).
#[tracing::instrument(skip_all, level = "trace")]
async fn get_send_chan_or_put_back(
    mux: &mut Multiplexor<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    sender: oneshot::Sender<DuplexStream>,
    command_tx: &mut mpsc::Sender<Command>,
) -> Result<bool, Error> {
    trace!("connecting to a new port");
    match mux.open_channel().await {
        Ok(stream) => {
            trace!("got a new channel");
            // `Err(_)` means "the corresponding receiver has already been deallocated"
            // which means we don't care about the channel anymore.
            sender.send(stream).ok();
            trace!("sent stream to handler (or handler died)");
            Ok(true)
        }
        Err(crate::mux::Error::Io(e)) => {
            if retryable_errors(&e) {
                warn!("Connection error: {e}");
                command_tx.send(sender).await?;
                Ok(false)
            } else {
                error!("Connection error: {e}");
                Err(e.into())
            }
        }
        Err(crate::mux::Error::ControlChannelNotEstablished) => {
            // Not important, we'll retry
            warn!("Control channel not established");
            command_tx.send(sender).await?;
            Ok(false)
        }
        Err(e) => {
            error!("{e}");
            Err(e.into())
        }
    }
}

/// Returns true if we should retry the connection.
fn retryable_errors(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::AddrNotAvailable
        || e.kind() == std::io::ErrorKind::BrokenPipe
        || e.kind() == std::io::ErrorKind::ConnectionReset
        || e.kind() == std::io::ErrorKind::ConnectionRefused
}

/// Converts `std::io::Error` to `Ok(())` if it's retryable, `Err(_)` otherwise.
fn maybe_retryable(e: std::io::Error) -> Result<(), Error> {
    if retryable_errors(&e) {
        Ok(())
    } else {
        Err(e.into())
    }
}
