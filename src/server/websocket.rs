//! Penguin server `WebSocket` listener.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::forwarder::tcp::start_forwarder_on_channel;
use super::forwarder::udp::udp_forward_to;
use super::WebSocket;
use crate::mux::{DatagramFrame, Multiplexor, Role};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, error, warn};

/// Multiplex the `WebSocket` connection and handle the forwarding requests.
#[tracing::instrument(skip(ws_stream), level = "debug")]
pub async fn handle_websocket(ws_stream: WebSocket) {
    let mux = Multiplexor::new(ws_stream, Role::Server, None);
    debug!("WebSocket connection established");
    let mut jobs = JoinSet::new();
    let mut udp_forwarders = JoinSet::new();
    // Channel for listeners to send UDP datagrams to the main loop
    let (datagram_send_tx, mut datagram_send_rx) = mpsc::channel::<DatagramFrame>(32);
    loop {
        tokio::select! {
            // Check if any of the jobs have finished and panicked
            Some(Err(err)) = jobs.join_next() => {
                assert!(!err.is_panic(), "Panic in a forwarder: {err}");
            }
            Some(Err(err)) = udp_forwarders.join_next() => {
                assert!(!err.is_panic(), "Panic in a UDP forwarder: {err}");
            }
            // Check if any of the listeners have sent a UDP datagram
            Some(datagram_frame) = datagram_send_rx.recv() => {
                mux.send_datagram(datagram_frame).await.unwrap_or_else(
                    |err| error!("Failed to send datagram: {err}"),
                );
            }
            Some(result) = mux.server_new_stream_channel() => {
                if let Ok(rhost) = String::from_utf8(result.dest_host.clone()) {
                    let rport = result.dest_port;
                    jobs.spawn(start_forwarder_on_channel(result, rhost, rport));
                } else {
                    warn!("Invalid host name");
                }
            }
            Some(datagram_frame) = mux.get_datagram() => {
                udp_forwarders.spawn(udp_forward_to(datagram_frame, datagram_send_tx.clone()));
            }
            else => {
                // The multiplexor has closed for some reason
                break;
            }
        }
    }
    debug!("WebSocket connection closed");
    jobs.shutdown().await;
}
