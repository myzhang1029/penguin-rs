//! Penguin server WebSocket listener.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::tcp_forwarder::start_tcp_forwarder_on_channel;
use super::udp_forwarder::start_udp_forwarder_on_channel;
use crate::mux::{Multiplexor, Role, WebSocket as MuxWebSocket};
use crate::proto_version::PROTOCOL_VERSION;
use penguin_tokio_stream_multiplexor::DuplexStream;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};
use warp::{ws::WebSocket, Filter, Rejection, Reply};

/// Error type for WebSocket connection.
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    TcpForwarder(std::io::Error),
    #[error(transparent)]
    UdpForwarder(std::io::Error),
    #[error(transparent)]
    Io(std::io::Error),
    #[error("invalid host: {0}")]
    Host(std::string::FromUtf8Error),
    #[error("invalid command: {0}")]
    Command(u8),
}

/// Dispatch the WebSocket connection to the appropriate handler.
/// See `mod.rs` for our protocol.
///
/// Should be spawned as a new task. In whatever case, it will return
/// a `Result` with the port number that was used, and `chan` will be
/// closed (dropped).
/// This function saves the port so the main loop knows which port to free
/// when the connection is closed.
/// All error types include a `u16` which is the channel's port number that was
/// used for the connection.
#[tracing::instrument(skip(chan), level = "info")]
async fn dispatch_conn(mut chan: DuplexStream, port: u16) -> Result<u16, (Error, u16)> {
    let command = chan.read_u8().await.map_err(|err| (Error::Io(err), port))?;
    let len = chan.read_u8().await.map_err(|err| (Error::Io(err), port))?;
    let mut rhost = vec![0; len as usize];
    chan.read_exact(&mut rhost)
        .await
        .map_err(|err| (Error::Io(err), port))?;
    let rhost = String::from_utf8(rhost).map_err(|err| (Error::Host(err), port))?;
    let rport = chan
        .read_u16()
        .await
        .map_err(|err| (Error::Io(err), port))?;
    chan.write_u8(0x03)
        .await
        .map_err(|err| (Error::Io(err), port))?;
    match command {
        1 => {
            // TCP
            info!("TCP connect to {rhost}:{rport}");
            start_tcp_forwarder_on_channel(chan, &rhost, rport)
                .await
                .map_err(|err| (Error::TcpForwarder(err), port))?;
            Ok(port)
        }
        3 => {
            // UDP
            info!("UDP forward to {rhost}:{rport}");
            start_udp_forwarder_on_channel(chan, &rhost, rport)
                .await
                .map_err(|err| (Error::UdpForwarder(err), port))?;
            Ok(port)
        }
        _ => Err((Error::Command(command), port)),
    }
}

/// Multiplex the WebSocket connection, create a SOCKS proxy over it,
/// and handle the forwarding requests.
#[tracing::instrument(skip(websocket), level = "debug")]
async fn handle_websocket(websocket: WebSocket) -> Result<(), super::Error> {
    let mws = MuxWebSocket::new(websocket);
    let mut mux = Multiplexor::new(mws, Role::Server);
    // Establish the control channel connection
    mux.establish_control_channel().await?;
    debug!("WebSocket connection established");
    let mut jobs = JoinSet::new();
    loop {
        match mux.open_channel().await {
            Ok((chan, port)) => {
                debug!("SOCKS listener on port {port} started");
                jobs.spawn(dispatch_conn(chan, port));
            }
            Err(err) => {
                warn!("Client disconnected: {err}");
                mux.shutdown().await?;
                break;
            }
        }
        // Check if any of the jobs have finished
        if let Ok(Some(r)) =
            tokio::time::timeout(tokio::time::Duration::from_millis(1), jobs.join_next()).await
        {
            match r {
                Ok(Ok(port)) => {
                    debug!("SOCKS listener on port {port} finished");
                    mux.close_channel(port).await;
                }
                Ok(Err((err, port))) => {
                    error!("SOCKS listener failed: {err}");
                    mux.close_channel(port).await;
                }
                Err(err) => {
                    if err.is_panic() {
                        panic!("Panic in a SOCKS listener: {err}");
                    }
                }
            }
        }
    }
    jobs.shutdown().await;
    Ok(())
}

/// Check the PSK and protocol version and upgrade to a websocket if the PSK matches (if required).
#[tracing::instrument]
pub fn ws_filter(
    predefined_ws_psk: Option<String>,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::ws()
        .and(warp::header::exact(
            "sec-websocket-protocol",
            PROTOCOL_VERSION,
        ))
        .and(warp::header::optional::<String>("x-penguin-psk"))
        .and_then(move |ws: warp::ws::Ws, psk: Option<String>| {
            let predefined_ws_psk = predefined_ws_psk.clone();
            async move {
                // Check the PSK
                match (psk, predefined_ws_psk) {
                    (Some(psk), Some(predefined_psk)) => {
                        if psk == predefined_psk {
                            debug!("Valid client PSK: {psk}");
                            Ok(ws)
                        } else {
                            info!("Ignoring invalid client PSK: {psk}");
                            Err(warp::reject::not_found())
                        }
                    }
                    (None, Some(_)) => {
                        // PSK required but not provided
                        info!("Ignoring client without PSK");
                        Err(warp::reject::not_found())
                    }
                    (_, None) => {
                        debug!("No PSK required");
                        Ok(ws)
                    }
                }
            }
        })
        .map(|ws: warp::ws::Ws| {
            debug!("Upgrading to websocket");
            // And then our closure will be called when it completes
            ws.on_upgrade(|ws| async move {
                if let Err(err) = handle_websocket(ws).await {
                    error!("Error handling websocket: {err}");
                }
            })
        })
}
