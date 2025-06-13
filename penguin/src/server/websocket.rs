//! Penguin server `WebSocket` listener.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::WebSocket;
use super::forwarder::tcp_forwarder_on_channel;
use super::forwarder::udp_forward_on;
use crate::config;
use penguin_mux::{Datagram, Dupe, Multiplexor};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, error, trace, warn};

#[cfg(feature = "nohash")]
use nohash_hasher::IntMap;
#[cfg(not(feature = "nohash"))]
use std::collections::HashMap as IntMap;

/// Multiplex the `WebSocket` connection and handle the forwarding requests.
#[tracing::instrument(skip(ws_stream), level = "debug")]
pub async fn handle_websocket(ws_stream: WebSocket, reverse: bool) {
    let options = penguin_mux::config::Options::new().bind_buffer_size(if reverse {
        config::BIND_BUFFER_SIZE
    } else {
        0
    });
    let mux = Multiplexor::new(ws_stream, Some(options), None);
    let mut udp_clients: IntMap<u32, mpsc::Sender<Datagram>> = IntMap::default();
    debug!("WebSocket connection established");
    let mut jobs = JoinSet::new();
    // Channel for listeners to send UDP datagrams to the main loop
    let (datagram_send_tx, mut datagram_send_rx) =
        mpsc::channel::<Datagram>(config::INCOMING_DATAGRAM_BUFFER_SIZE);
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
            Ok(result) = mux.accept_stream_channel() => {
                jobs.spawn(tcp_forwarder_on_channel(result));
            }
            // Check if the multiplexor has received a UDP datagram
            Ok(datagram_frame) = mux.get_datagram() => {
                let flow_id = datagram_frame.flow_id;
                if let Some(sender) = udp_clients.get_mut(&flow_id) {
                    sender.try_send(datagram_frame).unwrap_or_else(|err| {
                        match err {
                            mpsc::error::TrySendError::Closed(_) => {
                                // This client has been pruned, so we should
                                // remove it from the map and hopefully
                                // the client will try again.
                                trace!("UDP client {flow_id} has been pruned");
                                udp_clients.remove(&flow_id);
                            }
                            mpsc::error::TrySendError::Full(_) => {
                                // The channel is full, so just discard the datagram
                                trace!("UDP client {flow_id} has a full channel");
                            }
                        }
                    });
                } else {
                    let (sender, receiver) = mpsc::channel::<Datagram>(config::INCOMING_DATAGRAM_BUFFER_SIZE);
                    udp_clients.insert(flow_id, sender);
                    jobs.spawn(udp_forward_on(datagram_frame, receiver, datagram_send_tx.dupe()));
                }
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
