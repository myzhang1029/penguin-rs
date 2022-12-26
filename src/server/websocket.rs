//! Penguin server WebSocket listener.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::tcp_forwarder::start_tcp_forwarder_on_channel;
use super::udp_forwarder::start_udp_forwarder_on_channel;
use crate::mux::{Multiplexor, Role, WebSocket as MuxWebSocket};
use crate::proto_version::PROTOCOL_VERSION;
use penguin_tokio_stream_multiplexor::DuplexStream;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
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
#[tracing::instrument(skip(chan), level = "info")]
async fn dispatch_conn(chan: DuplexStream, port: u16) -> Result<(), Error> {
    let (chan_rx, mut chan_tx) = tokio::io::split(chan);
    let mut chan_rx = BufReader::new(chan_rx);
    let command = chan_rx.read_u8().await.map_err(Error::Io)?;
    let len = chan_rx.read_u8().await.map_err(Error::Io)?;
    let mut rhost = vec![0; len as usize];
    chan_rx.read_exact(&mut rhost).await.map_err(Error::Io)?;
    let rhost = String::from_utf8(rhost).map_err(Error::Host)?;
    let rport = chan_rx.read_u16().await.map_err(Error::Io)?;
    chan_tx.write_u8(0x03).await.map_err(Error::Io)?;
    match command {
        1 => {
            // TCP
            info!("TCP connect to {rhost}:{rport}");
            start_tcp_forwarder_on_channel(chan_rx, chan_tx, &rhost, rport)
                .await
                .map_err(Error::TcpForwarder)?;
            Ok(())
        }
        3 => {
            // UDP
            info!("UDP forward to {rhost}:{rport}");
            start_udp_forwarder_on_channel(chan_rx, chan_tx, &rhost, rport)
                .await
                .map_err(Error::UdpForwarder)?;
            Ok(())
        }
        _ => Err(Error::Command(command)),
    }
}

/// Multiplex the WebSocket connection and handle the forwarding requests.
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
                debug!("Listener on port {port} started");
                jobs.spawn(dispatch_conn(chan, port));
            }
            Err(err) => {
                warn!("Client disconnected: {err}");
                mux.shutdown().await?;
                break;
            }
        }
        // Check if any of the jobs have finished
        if let Ok(Some(Err(err))) =
            tokio::time::timeout(tokio::time::Duration::from_millis(1), jobs.join_next()).await
        {
            if err.is_panic() {
                panic!("Panic in a SOCKS listener: {err}");
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
