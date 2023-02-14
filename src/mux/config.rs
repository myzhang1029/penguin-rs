//! Default configuration parameters of the multiplexor.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

/// Number of datagram frames to buffer in the channels on the receiving end.
/// If the buffer is not read fast enough, excess datagrams will be dropped.
pub const DATAGRAM_BUFFER_SIZE: usize = 1 << 9;
/// Number of `MuxStream`s to buffer in the channels on the receiving end.
/// Since there is a handshake to obtain `MuxStream`s, there should be no
/// need to have a crazy high buffer size.
pub const STREAM_BUFFER_SIZE: usize = 1 << 5;

/// Needs to be the same as `STREAM_FRAME_BUFFER_SIZE` but as `u64`
pub const RWND: u64 = STREAM_FRAME_BUFFER_SIZE as u64;

/// Number of `StreamFrame`s to buffer in `MuxStream`'s channels before blocking
#[cfg(not(test))]
pub const STREAM_FRAME_BUFFER_SIZE: usize = 1 << 9;
/// Number of `Psh` frames between `Ack`s:
/// If too low, `Ack`s will consume too much bandwidth;
/// If too high, writers may block.
#[cfg(not(test))]
pub const RWND_THRESHOLD: u64 = 1 << 8;

/// Number of `StreamFrame`s to buffer in `MuxStream`'s channels before blocking
#[cfg(test)]
pub const STREAM_FRAME_BUFFER_SIZE: usize = 1 << 2;
/// Number of `Psh` frames between `Ack`s. In tests, we want to be able to
/// test the `Ack` mechanism, so we set this to be the same as the buffer size.
/// The downside is that tests will be slower.
#[cfg(test)]
pub const RWND_THRESHOLD: u64 = RWND;
