//! Penguin server WebSocket listener.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::forwarder::dispatch_conn;
use super::WebSocket;
use crate::mux::{Multiplexor, Role};
use tokio::task::JoinSet;
use tracing::{debug, error, warn};

/// Multiplex the WebSocket connection and handle the forwarding requests.
#[tracing::instrument(skip(ws_stream), level = "debug")]
pub async fn handle_websocket(ws_stream: WebSocket) {
    let mut mux = Multiplexor::new(ws_stream, Role::Server, None);
    debug!("WebSocket connection established");
    let mut jobs = JoinSet::new();
    loop {
        tokio::select! {
            // Check if any of the jobs have finished and panicked
            Some(Err(err)) = jobs.join_next() => {
                if err.is_panic() {
                    panic!("Panic in a forwarder: {err}");
                }
            }
            result = mux.unwrap_server().send_datagramnew_stream_channel() => {
                match result {
                    Ok(chan) => {
                        jobs.spawn(dispatch_conn(chan));
                    }
                    Err(err) => {
                        warn!("Client disconnected: {err}");
                        if let Err(err) = mux.shutdown().await {
                            error!("Failed to shutdown multiplexor: {err}");
                        }
                        break;
                    }
                }
            }
        }
    }
    jobs.shutdown().await;
}
