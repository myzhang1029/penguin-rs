//! Penguin server `WebSocket` listener.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::forwarder::tcp_forwarder_on_channel;
use super::forwarder::udp_forward_to;
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
    // Channel for listeners to send UDP datagrams to the main loop
    let (datagram_send_tx, mut datagram_send_rx) = mpsc::channel::<DatagramFrame>(32);
    loop {
        tokio::select! {
            // Check if any of the jobs have finished
            Some(Err(err)) = jobs.join_next() => {
                assert!(!err.is_panic(), "Panic in a forwarder: {err}");
                debug!("forwarder finished with error: {err}");
            }
            // Check if the multiplexor has received a new stream request
            Some(result) = mux.server_new_stream_channel() => {
                if let Ok(rhost) = String::from_utf8(result.dest_host.clone()) {
                    let rport = result.dest_port;
                    jobs.spawn(tcp_forwarder_on_channel(result, rhost, rport));
                } else {
                    warn!("Invalid host name");
                }
            }
            // Check if the multiplexor has received a UDP datagram
            Some(datagram_frame) = mux.get_datagram() => {
                jobs.spawn(udp_forward_to(datagram_frame, datagram_send_tx.clone()));
            }
            // Check if any of the listeners have sent a UDP datagram
            Some(datagram_frame) = datagram_send_rx.recv() => {
                mux.send_datagram(datagram_frame).await.unwrap_or_else(
                    |err| error!("Failed to send datagram: {err}"),
                );
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
