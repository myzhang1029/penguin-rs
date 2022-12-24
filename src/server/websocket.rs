//! Penguin server WebSocket listener.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::socks::start_socks_server_on_channel;
use crate::mux::{Multiplexor, Role, WebSocket as MuxWebSocket};
use crate::proto_version::PROTOCOL_VERSION;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};
use warp::{ws::WebSocket, Filter, Rejection, Reply};

/// Multiplex the WebSocket connection, create a SOCKS proxy over it,
/// and handle the forwarding requests.
#[tracing::instrument(skip(websocket))]
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
                // `start_socks_server_on_channel` saves the port so we know
                // which port to free when the channel is closed.
                jobs.spawn(start_socks_server_on_channel(chan, port));
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
                Ok(Err(err)) => {
                    error!("SOCKS listener failed: {err}");
                }
                Err(err) => {
                    if err.is_panic() {
                        error!("Panic in a SOCKS listener: {err}");
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
