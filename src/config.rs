//!Default configuration parameters.

use tokio::time;
use tungstenite::protocol::WebSocketConfig;

pub const DEFAULT_WS_CONFIG: WebSocketConfig = WebSocketConfig {
    max_send_queue: None,
    max_message_size: Some(64 << 20),
    max_frame_size: Some(2 << 23),
    accept_unmasked_frames: false,
};

/// Number of datagram frames to buffer in the channels before blocking
pub const DATAGRAM_BUFFER_SIZE: usize = 2 << 8;
/// Number of `MuxStream`s to buffer in the channels before blocking
pub const STREAM_BUFFER_SIZE: usize = 2 << 8;
/// Number of `StreamFrame`s to buffer in `MuxStream`'s channels before blocking
#[cfg(not(test))]
pub const STREAM_FRAME_BUFFER_SIZE: usize = 2 << 8;
#[cfg(test)]
// This new value will make it terribly slow but more likely to find problems
pub const STREAM_FRAME_BUFFER_SIZE: usize = 4;

pub const UDP_PRUNE_TIMEOUT: time::Duration = time::Duration::from_secs(60);
