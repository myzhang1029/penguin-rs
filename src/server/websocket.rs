//! Penguin server `WebSocket` listener.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::WebSocket;
use super::forwarder::tcp_forwarder_on_channel;
use super::forwarder::udp_forward_to;
use crate::config;
use penguin_mux::{DatagramFrame, Dupe, Multiplexor, Role, timing::OptionalDuration};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, error, trace, warn};

pub(super) type MuxStream = penguin_mux::MuxStream;

/// Multiplex the `WebSocket` connection and handle the forwarding requests.
#[tracing::instrument(skip(ws_stream), level = "debug")]
pub async fn handle_websocket(ws_stream: WebSocket) {
    let mux = Multiplexor::new(ws_stream, Role::Server, OptionalDuration::NONE, None);
    debug!("WebSocket connection established");
    let mut jobs = JoinSet::new();
    // Channel for listeners to send UDP datagrams to the main loop
    let (datagram_send_tx, mut datagram_send_rx) =
        mpsc::channel::<DatagramFrame>(config::INCOMING_DATAGRAM_BUFFER_SIZE);
    loop {
        trace!("server WebSocket loop");
        tokio::select! {
            // Check if any of the jobs have finished
            Some(result) = jobs.join_next() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn!("Forwarder finished with error: {err}");
                    }
                    Err(err) => {
                        assert!(!err.is_panic(), "Panic in a forwarder: {err}");
                    }
                }
            }
            // Check if the multiplexor has received a new stream request
            Ok(result) = mux.server_new_stream_channel() => {
                jobs.spawn(tcp_forwarder_on_channel(result));
            }
            // Check if the multiplexor has received a UDP datagram
            Ok(datagram_frame) = mux.get_datagram() => {
                jobs.spawn(udp_forward_to(datagram_frame, datagram_send_tx.dupe()));
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
