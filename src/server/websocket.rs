//! Penguin server WebSocket listener.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::mux::{ServerMultiplexor, ServerWebSocket};
use crate::proto_version::PROTOCOL_VERSION;
use log::{debug, error, info};
use warp::{ws::WebSocket, Filter, Rejection, Reply};

/// Multiplex the WebSocket connection, create a SOCKS proxy over it,
/// and handle the forwarding requests.
async fn handle_websocket(websocket: WebSocket) {
    let mux = ServerMultiplexor::new(ServerWebSocket::new(websocket));
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
                            debug!("Valid client PSK: {}", psk);
                            Ok(ws)
                        } else {
                            info!("Ignoring invalid client PSK: {}", psk);
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
            ws.on_upgrade(handle_websocket)
        })
}
