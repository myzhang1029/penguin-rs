//! Penguin server WebSocket listener.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::forwarder::dispatch_conn;
use crate::mux::{Multiplexor, Role, WebSocket as MuxWebSocket};
use crate::proto_version::PROTOCOL_VERSION;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};
use warp::{ws::WebSocket, Filter, Rejection, Reply};

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
        tokio::select! {
            // Check if any of the jobs have finished and panicked
            Some(Err(err)) = jobs.join_next() => {
                if err.is_panic() {
                    panic!("Panic in a SOCKS listener: {err}");
                }
            }
            result = mux.open_channel() => {
                match result {
                    Ok(chan) => {
                        jobs.spawn(dispatch_conn(chan));
                    }
                    Err(err) => {
                        warn!("Client disconnected: {err}");
                        mux.shutdown().await?;
                        break;
                    }
                }
            }
        }
    }
    jobs.shutdown().await;
    Ok(())
}

/// Check the PSK and protocol version and upgrade to a websocket if the PSK matches (if required).
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
