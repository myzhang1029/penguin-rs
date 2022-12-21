//! Penguin server WebSocket listener.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::proto_version::PROTOCOL_VERSION;
use futures_util::{FutureExt, StreamExt};
use log::{error, info};
use warp::{Filter, Rejection, Reply};

/// Check the PSK and protocol version and upgrade to a websocket if the PSK matches (if required).
pub fn ws_filter(
    predefined_ws_psk: Option<String>,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::ws()
        .and(warp::header::exact(
            "Sec-WebSocket-Protocol",
            PROTOCOL_VERSION,
        ))
        .and(warp::header::optional::<String>("X-Penguin-PSK"))
        .and_then(move |ws: warp::ws::Ws, psk: Option<String>| {
            let predefined_ws_psk = predefined_ws_psk.clone();
            async move {
                // Check the PSK
                match (psk, predefined_ws_psk) {
                    (Some(psk), Some(predefined_psk)) => {
                        if psk == predefined_psk {
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
                        // No PSK required
                        Ok(ws)
                    }
                }
            }
        })
        .map(|ws: warp::ws::Ws| {
            // And then our closure will be called when it completes
            ws.on_upgrade(|websocket| {
                // Just echo all messages back
                let (tx, rx) = websocket.split();
                rx.forward(tx).map(|result| {
                    if let Err(e) = result {
                        error!("websocket error: {:?}", e);
                    }
                })
            })
        })
}
