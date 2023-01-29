//! Penguin client.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod handle_remote;
mod maybe_retryable;
pub(crate) mod ws_connect;

use crate::arg::ClientArgs;
use crate::config;
use crate::dupe::Dupe;
use crate::mux::{DatagramFrame, Multiplexor, MuxStream as GMuxStream, Role};
use futures_util::stream::SplitSink;
use handle_remote::handle_remote;
use maybe_retryable::MaybeRetryableError;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::JoinSet;
use tokio::time;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{error, info, trace, warn};
use tungstenite::Message;

/// Errors
#[derive(Debug, Error)]
pub(crate) enum Error {
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
    CommandPutBack(#[from] mpsc::error::SendError<StreamCommand>),
    #[error("remote handler exited: {0}")]
    RemoteHandlerExited(#[from] handle_remote::Error),
}

type Sink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type MuxStream = GMuxStream<Sink>;

// Send the information about how to send the stream to the listener
/// Type that local listeners send to the main loop to request a connection
#[derive(Debug)]
pub(super) struct StreamCommand {
    /// Channel to send the stream back to the listener
    pub tx: oneshot::Sender<MuxStream>,
    pub host: Vec<u8>,
    pub port: u16,
}

/// Data for a function to be able to use the mux/connection
/// May be cheaply cloned for new `tokio::spawn` tasks.
#[derive(Clone, Debug)]
pub(super) struct HandlerResources {
    /// Send a request for a TCP channel to the main loop
    pub stream_command_tx: mpsc::Sender<StreamCommand>,
    /// Send a UDP datagram to the main loop
    pub datagram_tx: mpsc::Sender<DatagramFrame>,
    /// Map of client IDs to UDP sockets
    pub udp_client_id_map: Arc<RwLock<HashMap<u32, ClientIdMapEntry>>>,
}

impl Dupe for HandlerResources {
    // Explicitly providing a `dupe` implementation to prove that everything
    // can be cheaply cloned.
    fn dupe(&self) -> Self {
        Self {
            stream_command_tx: self.stream_command_tx.dupe(),
            datagram_tx: self.datagram_tx.dupe(),
            udp_client_id_map: self.udp_client_id_map.dupe(),
        }
    }
}

/// Type stored in the client ID map
#[derive(Clone, Debug)]
pub(super) struct ClientIdMapEntry {
    /// The address of the client
    pub addr: SocketAddr,
    /// The UDP socket used to communicate with the client
    pub socket: Arc<UdpSocket>,
    /// Whether responses should include a SOCKS5 header
    pub socks5: bool,
    /// When this entry should be removed
    pub expires: time::Instant,
}

impl ClientIdMapEntry {
    pub fn new(addr: SocketAddr, socket: Arc<UdpSocket>, socks5: bool) -> Self {
        Self {
            addr,
            socket,
            socks5,
            expires: time::Instant::now() + config::UDP_PRUNE_TIMEOUT,
        }
    }
}

#[tracing::instrument(level = "trace")]
pub(crate) async fn client_main(args: &'static ClientArgs) -> Result<(), Error> {
    // TODO: Temporary, remove when implemented
    // Blocked on `snapview/tungstenite-rs#177`
    if args.proxy.is_some() {
        warn!("Proxy not implemented yet");
    }
    let mut current_retry_count: u32 = 0;
    // Initial retry interval is 200ms
    let mut current_retry_interval: u64 = 200;
    // Channel for listeners to request TCP channels the main loop
    let (mut stream_cmd_tx, mut stream_cmd_rx) = mpsc::channel::<StreamCommand>(32);
    // Channel for listeners to send UDP datagrams to the main loop
    let (datagram_send_tx, mut datagram_send_rx) = mpsc::channel::<DatagramFrame>(32);
    // Map of client IDs to (source, UdpSocket, bool)
    let udp_client_id_map: HashMap<u32, ClientIdMapEntry> = HashMap::new();
    let udp_client_id_map = Arc::new(RwLock::new(udp_client_id_map));
    tokio::spawn(prune_client_id_map_task(udp_client_id_map.dupe()));
    let mut jobs = JoinSet::new();
    // Spawn listeners. See `handle_remote.rs` for the implementation considerations.
    for remote in &args.remote {
        let handler_resources = HandlerResources {
            stream_command_tx: stream_cmd_tx.dupe(),
            datagram_tx: datagram_send_tx.dupe(),
            udp_client_id_map: udp_client_id_map.dupe(),
        };
        jobs.spawn(handle_remote(remote, handler_resources));
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
                tokio::select! {
                    Some(result) = jobs.join_next() => {
                        // Quit immediately if any listener fails
                        // so maybe `systemd` can restart it
                        result.expect("JoinSet returned an error")?;
                    }
                    result = on_connected(
                        ws_stream,
                        &mut stream_cmd_rx,
                        &mut stream_cmd_tx,
                        &mut datagram_send_rx,
                        udp_client_id_map.dupe(),
                        args.keepalive,
                    ) => {
                        result?;
                        warn!("Disconnected from server");
                        // Since we once connected, reset the retry count
                        current_retry_count = 0;
                        current_retry_interval = 200;
                        // Now retry
                    }
                };
            }
            Err(e) => {
                if !e.retryable() {
                    return Err(e.into());
                }
                // If we get here, retry.
            }
        };

        // If we get here, retry.
        warn!("Reconnecting in {current_retry_interval} ms");
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
    stream_command_rx: &mut mpsc::Receiver<StreamCommand>,
    stream_command_tx: &mut mpsc::Sender<StreamCommand>,
    datagram_rx: &mut mpsc::Receiver<DatagramFrame>,
    udp_client_id_map: Arc<RwLock<HashMap<u32, ClientIdMapEntry>>>,
    keepalive: u64,
) -> Result<(), Error> {
    let keepalive_duration = match keepalive {
        0 => None,
        _ => Some(time::Duration::from_secs(keepalive)),
    };
    let mut mux = Multiplexor::new(ws_stream, Role::Client, keepalive_duration);
    info!("Connected to server");
    loop {
        tokio::select! {
            Some(sender) = stream_command_rx.recv() => {
                if !get_send_stream_chan_or_put_back(&mut mux, sender, stream_command_tx).await? {
                    break;
                }
            }
            Some(datagram) = datagram_rx.recv() => {
                if let Err(e) = mux.send_datagram(datagram).await {
                    error!("Failed to send datagram: {e}");
                }
            }
            Some(dgram_frame) = mux.get_datagram() => {
                let client_id = dgram_frame.sid;
                let data = dgram_frame.data;
                if client_id == 0 {
                    // Used for stdio
                    if let Err(e) = tokio::io::stdout().write_all(&data).await {
                        error!("Failed to write to stdout: {e}");
                    }
                } else {
                    let udp_client_id_map = udp_client_id_map.read().await;
                    if let Some(information) = udp_client_id_map.get(&client_id) {
                        if information.socks5 {
                            handle_remote::socks5::send_udp_relay_response(
                                &information.socket,
                                &information.addr,
                                &data,
                            ).await?;
                        } else if let Err(e) = information.socket.send_to(&data, &information.addr).await {
                            error!("Failed to send datagram to client: {e}");
                        }
                    } else {
                        // Just drop the datagram
                        info!("Received datagram for unknown client ID: {client_id}");
                    }
                }
            }
            else => {
                // The multiplexor has closed for some reason
                break;
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
/// Datagrams are simply dropped if we fail to get a new channel.
#[tracing::instrument(skip_all, level = "trace")]
async fn get_send_stream_chan_or_put_back(
    mux: &mut Multiplexor<Sink>,
    stream_command: StreamCommand,
    stream_command_tx: &mut mpsc::Sender<StreamCommand>,
) -> Result<bool, Error> {
    trace!("requesting a new TCP channel");
    match mux
        .client_new_stream_channel(stream_command.host.clone(), stream_command.port)
        .await
    {
        Ok(stream) => {
            trace!("got a new channel");
            // `Err(_)` means "the corresponding receiver has already been deallocated"
            // which means we don't care about the channel anymore.
            stream_command.tx.send(stream).ok();
            trace!("sent stream to handler (or handler died)");
            Ok(true)
        }
        Err(e) => {
            if e.retryable() {
                warn!("Connection error: {e}");
                stream_command_tx.send(stream_command).await?;
                Ok(false)
            } else {
                error!("Connection error: {e}");
                Err(e.into())
            }
        }
    }
}

/// Prune the client ID map of entries that have not been used for a while.
#[tracing::instrument(skip_all, level = "trace")]
async fn prune_client_id_map_task(udp_client_id_map: Arc<RwLock<HashMap<u32, ClientIdMapEntry>>>) {
    loop {
        tokio::time::sleep(2 * config::UDP_PRUNE_TIMEOUT).await;
        let mut udp_client_id_map = udp_client_id_map.write().await;
        let now = time::Instant::now();
        udp_client_id_map.retain(|_, entry| entry.expires > now);
    }
}
