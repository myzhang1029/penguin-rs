//! Default configuration parameters for the server and client.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use tokio::time;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

pub const DEFAULT_WS_CONFIG: WebSocketConfig = WebSocketConfig {
    max_send_queue: None,
    max_message_size: Some(1 << 26),
    max_frame_size: Some(1 << 24),
    accept_unmasked_frames: false,
};

/// Both: how long to wait for responses to UDP outgoing datagrams
pub const UDP_PRUNE_TIMEOUT: time::Duration = time::Duration::from_secs(10);
/// Client side: Number of stream requests to buffer in the channels for the main
/// loop to read from.
pub const STREAM_REQUEST_COMMAND_SIZE: usize = 1 << 6;
/// Both: Number of datagrams to buffer in the channels for the main loop
/// to read from.
pub const INCOMING_DATAGRAM_BUFFER_SIZE: usize = 1 << 6;
/// Both: Maximum size of a UDP packet.
pub const MAX_UDP_PACKET_SIZE: usize = 1 << 16;
