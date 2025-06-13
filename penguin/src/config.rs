//! Default configuration parameters for the server and client.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::time;

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
/// Server side: Bind request buffer size
pub const BIND_BUFFER_SIZE: usize = 1 << 4;
