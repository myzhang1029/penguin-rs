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
/// Needs to be the same as `STREAM_FRAME_BUFFER_SIZE` but as `u64`
#[cfg(not(test))]
pub const RWND: u64 = 2 << 8;

/// Number of `StreamFrame`s to buffer in `MuxStream`'s channels before blocking
#[cfg(test)]
pub const STREAM_FRAME_BUFFER_SIZE: usize = 2 << 1;
/// Needs to be the same as `STREAM_FRAME_BUFFER_SIZE` but as `u64`
#[cfg(test)]
pub const RWND: u64 = 2 << 1;

pub const UDP_PRUNE_TIMEOUT: time::Duration = time::Duration::from_secs(60);
