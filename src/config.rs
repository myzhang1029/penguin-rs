use tokio::time;
use tungstenite::protocol::WebSocketConfig;

/// Default configuration parameters.

pub const DEFAULT_WS_CONFIG: WebSocketConfig = WebSocketConfig {
    max_send_queue: None,
    max_message_size: Some(64 << 20),
    max_frame_size: Some(2 << 23),
    accept_unmasked_frames: false,
};

/// Number of frames to buffer in the channels before blocking
pub const DATAGRAM_BUFFER_SIZE: usize = 2 << 8;
pub const STREAM_BUFFER_SIZE: usize = 2 << 8;
/// Size of the `n` in `duplex(n)`
pub const DUPLEX_SIZE: usize = 2 << 21;
/// Less than `max_frame_size` - header size
pub const READ_BUF_SIZE: usize = 2 << 22;

pub const UDP_PRUNE_TIMEOUT: time::Duration = time::Duration::from_secs(60);
