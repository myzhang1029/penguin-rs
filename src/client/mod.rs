//! Penguin client.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod handle_remote;
mod maybe_retryable;
pub mod ws_connect;

use self::handle_remote::handle_remote;
use self::maybe_retryable::MaybeRetryableError;
use crate::arg::ClientArgs;
use crate::config;
use bytes::Bytes;
use futures_util::TryFutureExt;
use parking_lot::RwLock;
use penguin_mux::timing::{Backoff, OptionalDuration};
use penguin_mux::{Datagram, Dupe, IntKey, Multiplexor, MuxStream};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time;
use tokio_tungstenite::MaybeTlsStream;
use tracing::{error, info, trace, warn};

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("Maximum retry count reached (last error: {0})")]
    MaxRetryCountReached(Box<Self>),
    #[error("Failed to parse remote: {0}")]
    ParseRemote(#[from] crate::parse_remote::Error),
    #[error("Remote handler exited: {0}")]
    RemoteHandlerExited(#[from] handle_remote::FatalError),
    /// Invalid URL or cannot connect
    #[error(transparent)]
    Tungstenite(#[from] tokio_tungstenite::tungstenite::Error),
    /// TLS error
    #[error(transparent)]
    Tls(#[from] crate::tls::Error),
    #[error(transparent)]
    Mux(#[from] penguin_mux::Error),
    #[error("Initial WebSocket handshake timed out")]
    HandshakeTimeout,
    #[error("Stream request timed out")]
    StreamRequestTimeout,
    #[error("Remote disconnected normally")]
    RemoteDisconnected,
}

// Send the information about how to send the stream to the listener
/// Type that local listeners send to the main loop to request a connection
#[derive(Debug)]
pub struct StreamCommand {
    /// Channel to send the stream back to the listener
    tx: oneshot::Sender<MuxStream>,
    host: Bytes,
    port: u16,
}

/// Data for a function to be able to use the mux/connection
#[derive(Clone, Debug)]
pub struct HandlerResources {
    /// Send a request for a TCP channel to the main loop
    stream_command_tx: mpsc::Sender<StreamCommand>,
    /// Send a UDP datagram to the main loop
    datagram_tx: mpsc::Sender<Datagram>,
    /// The map of client IDs to UDP sockets and the map of client addresses to client IDs
    udp_client_map: Arc<RwLock<ClientIdMaps>>,
}

impl HandlerResources {
    /// Create a new `HandlerResources`
    pub fn create() -> (
        Self,
        mpsc::Receiver<StreamCommand>,
        mpsc::Receiver<Datagram>,
    ) {
        // Channel for listeners to request TCP channels the main loop
        let (stream_command_tx, stream_command_rx) =
            mpsc::channel(config::STREAM_REQUEST_COMMAND_SIZE);
        // Channel for listeners to send UDP datagrams to the main loop
        let (datagram_tx, datagram_rx) = mpsc::channel(config::INCOMING_DATAGRAM_BUFFER_SIZE);
        // Map of client IDs to `ClientIdMapEntry`
        let udp_client_map = Arc::new(RwLock::new(ClientIdMaps::new()));
        (
            Self {
                stream_command_tx,
                datagram_tx,
                udp_client_map: udp_client_map.dupe(),
            },
            stream_command_rx,
            datagram_rx,
        )
    }

    /// Add a new UDP client to the maps, returns the new client ID
    #[must_use = "This function returns the new client ID, which should be used to mark the datagram"]
    pub fn add_udp_client(&self, addr: SocketAddr, socket: Arc<UdpSocket>, socks5: bool) -> u32 {
        // `expect`: at this point `socket` should be bound. Otherwise, it's a bug.
        let our_addr = socket
            .local_addr()
            .expect("Failed to get local address of UDP socket (this is a bug)");
        let ClientIdMaps {
            client_id_map,
            client_addr_map,
        } = &mut *self.udp_client_map.write();
        if let Some(client_id) = client_addr_map.get(&(addr, our_addr)) {
            // The client already exists, just refresh the entry
            client_id_map
                .get_mut(client_id)
                .expect("`client_id_map` and `client_addr_map` are inconsistent (this is a bug)")
                .refresh();
            *client_id
        } else {
            // The client doesn't exist, add it to the maps
            let client_id = u32::next_available_key(client_id_map);
            client_id_map.insert(
                client_id,
                ClientIdMapEntry::new(addr, our_addr, socket, socks5),
            );
            client_addr_map.insert((addr, our_addr), client_id);
            client_id
        }
    }

    /// Prune expired entries from the UDP client maps
    fn prune_udp_clients(&self) {
        let ClientIdMaps {
            client_id_map,
            client_addr_map,
        } = &mut *self.udp_client_map.write();
        let now = time::Instant::now();
        client_id_map.retain(|_, entry| {
            if entry.expires > now {
                true
            } else {
                client_addr_map
                    .remove(&(entry.peer_addr, entry.our_addr))
                    .expect(
                        "`client_id_map` and `client_addr_map` are inconsistent (this is a bug)",
                    );
                false
            }
        });
    }
}

/// Type of the two client ID maps
/// Map of client IDs to UDP sockets and the map of client addresses to client IDs
#[derive(Clone, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct ClientIdMaps {
    /// Client ID -> Client ID map entry
    client_id_map: HashMap<u32, ClientIdMapEntry>,
    /// (client address, our address) -> client ID
    /// We need our address to make sure we send replies with the correct source address
    /// because different remotes and socks5 associations use different listeners
    client_addr_map: HashMap<(SocketAddr, SocketAddr), u32>,
}

impl ClientIdMaps {
    #[must_use]
    fn new() -> Self {
        Self {
            client_id_map: HashMap::new(),
            client_addr_map: HashMap::new(),
        }
    }

    /// Send a datagram to a client
    async fn send_datagram_reply(
        lock_self: &RwLock<Self>,
        client_id: u32,
        data: &[u8],
    ) -> Option<std::io::Result<()>> {
        if client_id == 0 {
            // Used for stdio
            return Some(tokio::io::stdout().write_all(data).await);
        }
        let info = lock_self.read().client_id_map.get(&client_id)?.dupe();

        let send_result = if info.socks5 {
            handle_remote::socks::send_udp_relay_response(&info.socket, info.peer_addr, data).await
        } else {
            info.socket.send_to(data, info.peer_addr).await
        }
        .map(|_| ());
        Some(send_result)
    }
}

/// Type stored in the first client ID map
#[derive(Clone, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct ClientIdMapEntry {
    /// The address of the client
    pub peer_addr: SocketAddr,
    /// The address of our socket (redundant information, but makes it easier to remove entries)
    pub our_addr: SocketAddr,
    /// The UDP socket used to communicate with the client
    pub socket: Arc<UdpSocket>,
    /// Whether responses should include a SOCKS5 header
    pub socks5: bool,
    /// When this entry should be removed
    pub expires: time::Instant,
}

impl Dupe for ClientIdMapEntry {
    fn dupe(&self) -> Self {
        Self {
            peer_addr: self.peer_addr,
            our_addr: self.our_addr,
            socket: self.socket.dupe(),
            socks5: self.socks5,
            expires: self.expires,
        }
    }
}

impl ClientIdMapEntry {
    #[must_use]
    pub fn new(
        peer_addr: SocketAddr,
        our_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        socks5: bool,
    ) -> Self {
        Self {
            peer_addr,
            our_addr,
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
    static HANDLER_RESOURCES: OnceLock<HandlerResources> = OnceLock::new();
    let (handler_resources, stream_command_rx, datagram_rx) = HandlerResources::create();
    HANDLER_RESOURCES
        .set(handler_resources)
        .expect("HandlerResources should only be set once (this is a bug)");
    client_main_inner(
        args,
        HANDLER_RESOURCES
            .get()
            .expect("HandlerResources should be set (this is a bug)"),
        stream_command_rx,
        datagram_rx,
    )
    .await
}

pub async fn client_main_inner(
    args: &'static ClientArgs,
    handler_resources: &'static HandlerResources,
    mut stream_command_rx: mpsc::Receiver<StreamCommand>,
    mut datagram_rx: mpsc::Receiver<Datagram>,
) -> Result<(), Error> {
    // TODO: Temporary, remove when implemented
    // Blocked on `snapview/tungstenite-rs#177`
    if args.proxy.is_some() {
        warn!("Proxy not implemented yet");
    }
    let mut jobs = JoinSet::new();
    // Spawn listeners. See `handle_remote.rs` for the implementation considerations.
    for remote in &args.remote {
        jobs.spawn(handle_remote(remote, handler_resources));
    }
    // Check if any listener has failed. If so, quit immediately.
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
        // Initial retry interval is 200ms
        let mut backoff = Backoff::new(
            Duration::from_millis(200),
            Duration::from_millis(args.max_retry_interval),
            2,
            args.max_retry_count,
        );
        // Place to park one failed stream request so that it can be retried
        let mut failed_stream_request: Option<StreamCommand> = None;
        // Retry loop
        loop {
            let r = ws_connect::handshake(args)
                .and_then(|ws_stream| {
                    on_connected(
                        ws_stream,
                        &mut stream_command_rx,
                        &mut failed_stream_request,
                        &mut datagram_rx,
                        &handler_resources.udp_client_map,
                        args.keepalive,
                        args.channel_timeout,
                    )
                    // Since we once connected, reset the retry count
                    .inspect_err(|_| backoff.reset())
                })
                .await;
            match r {
                // Will get `Ok` only if the user wants to quit
                Ok(()) => return Ok(()),
                Err(ref e) if !e.retryable() => return r,
                // else, retry
                Err(e) => {
                    warn!("Connection failed: {e}");
                    let Some(current_retry_interval) = backoff.advance() else {
                        warn!("Max retry count reached, giving up");
                        return Err(Error::MaxRetryCountReached(Box::new(e)));
                    };
                    warn!("Reconnecting in {current_retry_interval:?}");
                    time::sleep(current_retry_interval).await;
                }
            }
        }
    };
    tokio::select! {
        biased;
        result = check_listeners_future => result,
        // This future never resolves
        () = prune_client_id_map_task(handler_resources) => unreachable!("prune_client_id_map_task should never return"),
        result = main_future => result,
    }
}

/// Called when the main socket is connected. Accepts connection requests from
/// local listeners, establishes them, and sends them back to the listeners.
/// Datagrams are simply dropped if we fail to send them.
///
/// # Errors
/// This function returns when the connection is lost, and the caller should
/// retry based on the error.
#[tracing::instrument(skip_all, level = "debug")]
async fn on_connected(
    ws_stream: tokio_tungstenite::WebSocketStream<MaybeTlsStream<TcpStream>>,
    stream_command_rx: &mut mpsc::Receiver<StreamCommand>,
    failed_stream_request: &mut Option<StreamCommand>,
    datagram_rx: &mut mpsc::Receiver<Datagram>,
    udp_client_map: &RwLock<ClientIdMaps>,
    keepalive: OptionalDuration,
    channel_timeout: OptionalDuration,
) -> Result<(), Error> {
    let mut mux_task_joinset = JoinSet::new();
    let options = penguin_mux::config::Options::new().keepalive_interval(keepalive);
    let mux = Multiplexor::new(ws_stream, Some(options), Some(&mut mux_task_joinset));
    info!("Connected to server");
    // If we have a failed stream request, try it first
    if let Some(sender) = failed_stream_request.take() {
        get_send_stream_chan(&mux, sender, failed_stream_request, channel_timeout).await?;
    }
    // Main loop
    loop {
        tokio::select! {
            Some(mux_task_joinset_result) = mux_task_joinset.join_next() => {
                mux_task_joinset_result.expect("Task panicked (this is a bug)")?;
            }
            Some(sender) = stream_command_rx.recv() => {
                get_send_stream_chan(&mux, sender, failed_stream_request, channel_timeout).await?;
            }
            Some(datagram) = datagram_rx.recv() => {
                if let Err(e) = mux.send_datagram(datagram).await {
                    error!("{e}");
                }
            }
            Ok(dgram_frame) = mux.get_datagram() => {
                let client_id = dgram_frame.flow_id;
                let data = dgram_frame.data;
                match ClientIdMaps::send_datagram_reply(udp_client_map, client_id, data.as_ref()).await {
                    Some(Ok(())) => {
                        trace!("sent datagram to client {client_id:08x}");
                    }
                    Some(Err(e)) => {
                        warn!("Failed to send datagram to client {client_id:08x}: {e}");
                    }
                    None => {
                        // Just drop the datagram
                        info!("Received datagram for unknown client ID: {client_id:08x}");
                    }
                }
            }
            Ok(()) = tokio::signal::ctrl_c() => {
                // `Err` means unable to listen for Ctrl-C, which we will ignore
                info!("Received Ctrl-C, exiting once all streams are closed");
                drop(mux);
                while let Some(result) = mux_task_joinset.join_next().await {
                    result.expect("Task panicked (this is a bug)")?;
                }
                return Ok(());
            }
            else => {
                // The multiplexor has closed for some reason
                return Err(Error::RemoteDisconnected);
            }
        }
    }
}

/// Get a new channel from the multiplexor and send it to the handler.
/// If we fail, put the request back in the failed_stream_request slot.
#[tracing::instrument(skip_all, level = "trace")]
async fn get_send_stream_chan(
    mux: &Multiplexor,
    stream_command: StreamCommand,
    failed_stream_request: &mut Option<StreamCommand>,
    channel_timeout: OptionalDuration,
) -> Result<(), Error> {
    trace!("requesting a new TCP channel");
    match channel_timeout
        .timeout(mux.new_stream_channel(&stream_command.host, stream_command.port))
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
async fn prune_client_id_map_task(handler_resources: &HandlerResources) {
    let mut interval = time::interval(config::UDP_PRUNE_TIMEOUT);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        handler_resources.prune_udp_clients();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    #[tokio::test]
    async fn test_client_map_add_client() {
        crate::tests::setup_logging();
        let (stub_stream_tx, _stub_stream_rx) = mpsc::channel(1);
        let (stub_datagram_tx, _stub_datagram_rx) = mpsc::channel(1);
        let handler_resources = HandlerResources {
            stream_command_tx: stub_stream_tx,
            datagram_tx: stub_datagram_tx,
            udp_client_map: Arc::new(RwLock::new(ClientIdMaps::new())),
        };
        let stub_socket = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await.unwrap());
        let client_id = handler_resources.add_udp_client(
            (IpAddr::from([127, 0, 0, 1]), 1234).into(),
            stub_socket.dupe(),
            false,
        );
        let client_id2 = handler_resources.add_udp_client(
            (IpAddr::from([127, 0, 0, 1]), 1234).into(),
            stub_socket.dupe(),
            false,
        );
        // We should get the same client ID for the same client address and socket
        assert_eq!(client_id, client_id2);
        let stub_socket_2 = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await.unwrap());
        let client_id2 = handler_resources.add_udp_client(
            (IpAddr::from([127, 0, 0, 1]), 1234).into(),
            stub_socket_2,
            false,
        );
        // We should get a different client ID for a different socket
        assert_ne!(client_id, client_id2);
        let client_id2 = handler_resources.add_udp_client(
            (IpAddr::from([127, 0, 0, 1]), 1235).into(),
            stub_socket.dupe(),
            false,
        );
        // We should get a different client ID for a different client address
        assert_ne!(client_id, client_id2);
    }

    #[tokio::test]
    async fn test_client_map_remove_client() {
        crate::tests::setup_logging();
        let (stub_stream_tx, _stub_stream_rx) = mpsc::channel(1);
        let (stub_datagram_tx, _stub_datagram_rx) = mpsc::channel(1);
        let handler_resources = HandlerResources {
            stream_command_tx: stub_stream_tx,
            datagram_tx: stub_datagram_tx,
            udp_client_map: Arc::new(RwLock::new(ClientIdMaps::new())),
        };
        let stub_socket = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await.unwrap());
        let _ = handler_resources.add_udp_client(
            (IpAddr::from([127, 0, 0, 1]), 1234).into(),
            stub_socket.dupe(),
            false,
        );
        tokio::time::sleep(config::UDP_PRUNE_TIMEOUT).await;
        handler_resources.prune_udp_clients();
        assert!(
            handler_resources
                .udp_client_map
                .read()
                .client_id_map
                .is_empty()
        );
    }
}
