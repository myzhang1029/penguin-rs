//! Penguin client.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod handle_remote;
mod maybe_retryable;
pub mod ws_connect;

use crate::arg::ClientArgs;
use crate::config;
use crate::Dupe;
use bytes::Bytes;
use handle_remote::handle_remote;
use maybe_retryable::MaybeRetryableError;
use penguin_mux::{DatagramFrame, IntKey, Multiplexor, Role};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::JoinSet;
use tokio::time;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{error, info, trace, warn};

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("Maximum retry count reached")]
    MaxRetryCountReached,
    #[error("Failed to parse remote: {0}")]
    ParseRemote(#[from] crate::parse_remote::Error),
    #[error("Remote handler exited: {0}")]
    RemoteHandlerExited(#[from] handle_remote::FatalError),
    #[error("Failed to connect WebSocket: {0}")]
    Connect(#[from] ws_connect::Error),
    #[error(transparent)]
    Mux(#[from] penguin_mux::Error),
    #[error("Stream request timed out")]
    StreamRequestTimeout,
    #[error("Remote disconnected normally")]
    RemoteDisconnected,
}

type MuxStream = penguin_mux::MuxStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

// Send the information about how to send the stream to the listener
/// Type that local listeners send to the main loop to request a connection
#[derive(Debug)]
pub struct StreamCommand {
    /// Channel to send the stream back to the listener
    pub tx: oneshot::Sender<MuxStream>,
    pub host: Bytes,
    pub port: u16,
}

/// Data for a function to be able to use the mux/connection
/// May be cheaply cloned for new `tokio::spawn` tasks.
#[derive(Clone, Debug)]
pub struct HandlerResources {
    /// Send a request for a TCP channel to the main loop
    pub stream_command_tx: mpsc::Sender<StreamCommand>,
    /// Send a UDP datagram to the main loop
    pub datagram_tx: mpsc::Sender<DatagramFrame>,
    /// Map of client IDs to UDP sockets
    pub udp_client_id_map: Arc<RwLock<HashMap<u32, ClientIdMapEntry>>>,
    /// Map of client addresses to client IDs
    pub udp_client_addr_map: Arc<RwLock<HashMap<SocketAddr, u32>>>,
}

impl Dupe for HandlerResources {
    // Explicitly providing a `dupe` implementation to prove that everything
    // can be cheaply cloned.
    fn dupe(&self) -> Self {
        Self {
            stream_command_tx: self.stream_command_tx.dupe(),
            datagram_tx: self.datagram_tx.dupe(),
            udp_client_id_map: self.udp_client_id_map.dupe(),
            udp_client_addr_map: self.udp_client_addr_map.dupe(),
        }
    }
}

impl HandlerResources {
    /// Add a new UDP client to the maps, returns the new client ID
    #[must_use = "This function returns the new client ID, which should be used to mark the datagram"]
    pub async fn add_udp_client(
        &self,
        addr: SocketAddr,
        socket: Arc<UdpSocket>,
        socks5: bool,
    ) -> u32 {
        let mut udp_client_addr_map = self.udp_client_addr_map.write().await;
        if let Some(client_id) = udp_client_addr_map.get(&addr) {
            // The client already exists, just refresh the entry
            self.udp_client_id_map
                .write()
                .await
                .get_mut(client_id)
                .expect("`client_id_map` and `client_addr_map` are inconsistent (this is a bug)")
                .refresh();
            *client_id
        } else {
            // The client doesn't exist, add it to the maps
            let mut udp_client_id_map = self.udp_client_id_map.write().await;
            let client_id = u32::next_available_key(&*udp_client_id_map);
            udp_client_id_map.insert(client_id, ClientIdMapEntry::new(addr, socket, socks5));
            udp_client_addr_map.insert(addr, client_id);
            client_id
        }
    }

    /// Prune expired entries from the UDP client maps
    async fn prune_udp_clients(&self) {
        let mut udp_client_id_map = self.udp_client_id_map.write().await;
        let mut udp_client_addr_map = self.udp_client_addr_map.write().await;
        let now = time::Instant::now();
        udp_client_id_map.retain(|_, entry| {
            if entry.expires > now {
                true
            } else {
                udp_client_addr_map.remove(&entry.addr).expect(
                    "`client_id_map` and `client_addr_map` are inconsistent (this is a bug)",
                );
                false
            }
        });
    }
}

/// Type stored in the client ID map
#[derive(Clone, Debug)]
pub struct ClientIdMapEntry {
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

    pub fn refresh(&mut self) {
        self.expires = time::Instant::now() + config::UDP_PRUNE_TIMEOUT;
    }
}

#[tracing::instrument(level = "trace")]
pub async fn client_main(args: &'static ClientArgs) -> Result<(), Error> {
    // TODO: Temporary, remove when implemented
    // Blocked on `snapview/tungstenite-rs#177`
    if args.proxy.is_some() {
        warn!("Proxy not implemented yet");
    }
    // Channel for listeners to request TCP channels the main loop
    let (stream_command_tx, mut stream_command_rx) =
        mpsc::channel::<StreamCommand>(config::STREAM_REQUEST_COMMAND_SIZE);
    // Channel for listeners to send UDP datagrams to the main loop
    let (datagram_tx, mut datagram_rx) =
        mpsc::channel::<DatagramFrame>(config::INCOMING_DATAGRAM_BUFFER_SIZE);
    // Map of client IDs to `ClientIdMapEntry`
    let udp_client_id_map = Arc::new(RwLock::new(HashMap::new()));
    let handler_resources = HandlerResources {
        stream_command_tx,
        datagram_tx,
        udp_client_id_map: udp_client_id_map.dupe(),
        udp_client_addr_map: Arc::new(RwLock::new(HashMap::new())),
    };
    let mut jobs = JoinSet::new();
    // Spawn listeners. See `handle_remote.rs` for the implementation considerations.
    for remote in &args.remote {
        jobs.spawn(handle_remote(remote, handler_resources.dupe()));
    }
    let check_listeners_future = async move {
        while let Some(result) = jobs.join_next().await {
            // Quit immediately if any handler fails
            // so maybe `systemd` can restart it
            result.expect("JoinSet panicked (this is a bug)")?;
        }
        // Quit if there is no more listeners, which means we don't need
        // to exist anymore
        Ok::<(), Error>(())
    };
    let main_future = async move {
        let mut current_retry_count: u32 = 0;
        // Initial retry interval is 200ms
        let mut current_retry_interval: u64 = 200;
        // Place to park one failed stream request so that it can be retried
        let mut failed_stream_request: Option<StreamCommand> = None;
        // Retry loop
        loop {
            match ws_connect::handshake(args).await {
                Err(e) => {
                    if !e.retryable() {
                        return Err(e.into());
                    }
                    // else, retry
                }
                Ok(ws_stream) => {
                    // This future is not cancel-safe, but if the previous
                    // future is returns, it is a fatal error and we don't
                    // care about this future anymore.
                    let error = on_connected(
                        ws_stream,
                        &mut stream_command_rx,
                        &mut failed_stream_request,
                        &mut datagram_rx,
                        udp_client_id_map.dupe(),
                        args.keepalive,
                        time::Duration::from_secs(args.channel_timeout),
                    )
                    .await;
                    warn!("Disconnected from server");
                    if !error.retryable() {
                        return Err(error);
                    }
                    // Since we once connected, reset the retry count
                    current_retry_count = 0;
                    current_retry_interval = 200;
                    // Now retry
                }
            }
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
    };
    tokio::select! {
        biased;
        result = check_listeners_future => result,
        // This future never returns
        _ = prune_client_id_map_task(handler_resources) => unreachable!("prune_client_id_map_task should never return"),
        result = main_future => result,
    }
}

/// Called when the main socket is connected. Accepts connection requests from
/// local listeners, establishes them, and sends them back to the listeners.
/// Datagrams are simply dropped if we fail to send them.
/// This function returns when the connection is lost, and the caller should
/// retry based on the error.
#[tracing::instrument(skip_all, level = "debug")]
async fn on_connected(
    ws_stream: tokio_tungstenite::WebSocketStream<MaybeTlsStream<TcpStream>>,
    stream_command_rx: &mut mpsc::Receiver<StreamCommand>,
    failed_stream_request: &mut Option<StreamCommand>,
    datagram_rx: &mut mpsc::Receiver<DatagramFrame>,
    udp_client_id_map: Arc<RwLock<HashMap<u32, ClientIdMapEntry>>>,
    keepalive: u64,
    channel_timeout: Duration,
) -> Error {
    let keepalive_duration = if keepalive == 0 {
        None
    } else {
        Some(time::Duration::from_secs(keepalive))
    };
    let mut mux_task_joinset = JoinSet::new();
    let mut mux = Multiplexor::new(
        ws_stream,
        Role::Client,
        keepalive_duration,
        Some(&mut mux_task_joinset),
    );
    info!("Connected to server");
    // If we have a failed stream request, try it first
    if let Some(sender) = failed_stream_request.take() {
        if let Err(e) =
            get_send_stream_chan(&mut mux, sender, failed_stream_request, channel_timeout).await
        {
            return e;
        }
    }
    // Main loop
    loop {
        tokio::select! {
            Some(mux_task_joinset_result) = mux_task_joinset.join_next() => {
                if let Err(e) = mux_task_joinset_result.expect("JoinSet panicked (this is a bug)") {
                    return Error::Mux(e);
                }
            }
            Some(sender) = stream_command_rx.recv() => {
                if let Err(e) = get_send_stream_chan(&mut mux, sender, failed_stream_request, channel_timeout).await {
                    return e;
                }
            }
            Some(datagram) = datagram_rx.recv() => {
                if let Err(e) = mux.send_datagram(datagram).await {
                    error!("{e}");
                }
            }
            Ok(dgram_frame) = mux.get_datagram() => {
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
                        let send_result =
                        if information.socks5 {
                            handle_remote::socks::send_udp_relay_response(
                                &information.socket,
                                &information.addr,
                                &data,
                            ).await
                        } else {
                            information.socket.send_to(&data, &information.addr).await
                        };
                        if let Err(e) = send_result {
                            warn!("Failed to send datagram to client: {e}");
                        }
                    } else {
                        // Just drop the datagram
                        info!("Received datagram for unknown client ID: {client_id}");
                    }
                }
            }
            else => {
                // The multiplexor has closed for some reason
                return Error::RemoteDisconnected;
            }
        }
    }
}

/// Get a new channel from the multiplexor and send it to the handler.
/// If we fail, put the request back in the failed_stream_request slot.
#[tracing::instrument(skip_all, level = "trace")]
async fn get_send_stream_chan(
    mux: &mut Multiplexor<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    stream_command: StreamCommand,
    failed_stream_request: &mut Option<StreamCommand>,
    channel_timeout: Duration,
) -> Result<(), Error> {
    trace!("requesting a new TCP channel");
    match tokio::time::timeout(
        channel_timeout,
        mux.client_new_stream_channel(&stream_command.host, stream_command.port),
    )
    .await
    {
        Ok(Ok(stream)) => {
            trace!("got a new channel");
            // `Err(_)` means "the corresponding receiver has already been deallocated"
            // which means we don't care about the channel anymore.
            stream_command.tx.send(stream).ok();
            trace!("sent stream to handler (or handler died)");
            Ok(())
        }
        Ok(Err(e)) => {
            failed_stream_request.replace(stream_command);
            Err(e.into())
        }
        Err(_) => {
            failed_stream_request.replace(stream_command);
            Err(Error::StreamRequestTimeout)
        }
    }
}

/// Prune the client ID map of entries that have not been used for a while.
#[tracing::instrument(skip_all, level = "trace")]
async fn prune_client_id_map_task(handler_resources: HandlerResources) {
    let mut interval = time::interval(config::UDP_PRUNE_TIMEOUT);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        handler_resources.prune_udp_clients().await;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::IpAddr;
    #[tokio::test]
    async fn test_client_map_add_client() {
        let (stub_stream_tx, _stub_stream_rx) = mpsc::channel(1);
        let (stub_datagram_tx, _stub_datagram_rx) = mpsc::channel(1);
        let handler_resources = HandlerResources {
            stream_command_tx: stub_stream_tx,
            datagram_tx: stub_datagram_tx,
            udp_client_id_map: Arc::new(RwLock::new(HashMap::new())),
            udp_client_addr_map: Arc::new(RwLock::new(HashMap::new())),
        };
        let stub_socket = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await.unwrap());
        let client_id = handler_resources
            .add_udp_client(
                (IpAddr::from([127, 0, 0, 1]), 1234).into(),
                stub_socket.dupe(),
                false,
            )
            .await;
        let client_id2 = handler_resources
            .add_udp_client(
                (IpAddr::from([127, 0, 0, 1]), 1234).into(),
                stub_socket.dupe(),
                false,
            )
            .await;
        assert_eq!(client_id, client_id2);
        let client_id3 = handler_resources
            .add_udp_client(
                (IpAddr::from([127, 0, 0, 1]), 1235).into(),
                stub_socket.dupe(),
                false,
            )
            .await;
        assert_ne!(client_id, client_id3);
    }

    #[tokio::test]
    async fn test_client_map_remove_client() {
        let (stub_stream_tx, _stub_stream_rx) = mpsc::channel(1);
        let (stub_datagram_tx, _stub_datagram_rx) = mpsc::channel(1);
        let handler_resources = HandlerResources {
            stream_command_tx: stub_stream_tx,
            datagram_tx: stub_datagram_tx,
            udp_client_id_map: Arc::new(RwLock::new(HashMap::new())),
            udp_client_addr_map: Arc::new(RwLock::new(HashMap::new())),
        };
        let stub_socket = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await.unwrap());
        let _ = handler_resources
            .add_udp_client(
                (IpAddr::from([127, 0, 0, 1]), 1234).into(),
                stub_socket.dupe(),
                false,
            )
            .await;
        tokio::time::sleep(config::UDP_PRUNE_TIMEOUT).await;
        handler_resources.prune_udp_clients().await;
        assert!(handler_resources.udp_client_id_map.read().await.is_empty());
    }
}
