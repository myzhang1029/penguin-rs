//! Penguin server `WebSocket` listener.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::forwarder::tcp_forwarder_on_channel;
use super::forwarder::udp_forward_to;
use super::WebSocket;
use crate::dupe::Dupe;
use crate::mux::{DatagramFrame, Multiplexor, Role};
use futures_util::stream::SplitSink;
use futures_util::stream::SplitStream;
use hyper::upgrade::Upgraded;
use tokio::{sync::mpsc, task::JoinSet};
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, trace, warn};
use tungstenite::Message;

type WSStream = WebSocketStream<Upgraded>;
pub(super) type Sink = SplitSink<WSStream, Message>;
pub(super) type Stream = SplitStream<WSStream>;
pub(super) type MuxStream = crate::mux::MuxStream<Sink, Stream>;

/// Multiplex the `WebSocket` connection and handle the forwarding requests.
#[tracing::instrument(skip(ws_stream), level = "debug")]
pub async fn handle_websocket(ws_stream: WebSocket) {
    let mux = Multiplexor::new(ws_stream, Role::Server, None);
    debug!("WebSocket connection established");
    let mut jobs = JoinSet::new();
    // Channel for listeners to send UDP datagrams to the main loop
    let (datagram_send_tx, mut datagram_send_rx) = mpsc::channel::<DatagramFrame>(32);
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
