//! Penguin server `WebSocket` listener.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::forwarder::tcp::start_forwarder_on_channel;
use super::WebSocket;
use crate::mux::{Multiplexor, Role, ServerMuxStream};
use futures_util::stream::{SplitSink, SplitStream};
use hyper::upgrade::Upgraded;
use tokio::task::JoinSet;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, trace, warn};
use tungstenite::Message;

pub(super) type Sink = SplitSink<WebSocketStream<Upgraded>, Message>;
pub(super) type Stream = SplitStream<WebSocketStream<Upgraded>>;
pub(super) type MuxStream = ServerMuxStream<Sink, Stream>;

/// Multiplex the `WebSocket` connection and handle the forwarding requests.
#[tracing::instrument(skip(ws_stream), level = "debug")]
pub async fn handle_websocket(ws_stream: WebSocket) {
    let mux = Multiplexor::new(ws_stream, Role::Server, None);
    debug!("WebSocket connection established");
    let mut jobs = JoinSet::new();
    loop {
        tokio::select! {
            // Check if any of the jobs have finished and panicked
            Some(Err(err)) = jobs.join_next() => {
                assert!(!err.is_panic(), "Panic in a forwarder: {err}");
            }
            Some(result) = mux.as_server().unwrap().new_stream_channel() => {
                if let Ok(rhost) = String::from_utf8(result.host.clone()) {
                let rport = result.dest_port;
                let (rx, tx) = tokio::io::split(result);
                jobs.spawn(start_forwarder_on_channel(rx, tx, rhost, rport));
                } else {
                    warn!("Invalid host name");
                }
            }
            Some(datagram_frame) = mux.as_server().unwrap().get_datagram() => {
                trace!("got datagram frame: {datagram_frame:?}");
                todo!();
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
