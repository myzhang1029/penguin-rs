//! Frames.
//! Each frame strictly fits in a `Message`.
//!
//! Architecture:
//! The system is similar to a traditional SOCKS5 proxy, but the protocol
//! allows for UDP to be transmitted over the same WebSocket connection.
//! It is essentially a SOCKS5 forwarder over a WebSocket link.
//!
//! All `Message`s carry a complete frame:
//! - 1 byte: type (1 for TCP, 3 for UDP)
//! - variable: dependent on the type (see `StreamFrame` and `DatagramFrame`).
//!
//! `Stream` messages are connection-based.
//! The frames are in the following format:
//! - 2 bytes: source port in network byte order.
//! - 2 bytes: destination port in network byte order.
//! - 1 byte: type (see below)
//! - variable: payload
//! There are six types of frames:
//! - `Syn`: the client sends this frame to request a connection to a target:
//!         - 4 bytes: initial receive window size in network byte order.
//!         - 2 bytes: forwarding destination port in network byte order.
//!         - variable: (0..256) bytes: (forwarding destination domain name or IP).
//! - `SynAck`: the server replies with this frame to confirm the connection.
//!         It is in the same format as `Ack`. Using two types of frames is to
//!         avoid having to implement a state machine.
//! - `Ack`: the server replies with this frame to confirm the data reception:
//!         - 4 bytes: number of `Psh` frames processed since the last `Ack` frame.
//! - `Rst`: one side sends this frame to indicate that the connection should
//!          be closed.
//! - `Psh`: one side sends this frame to send data.
//! - `Fin`: one side sends this frame to indicate that it has no more data to
//!          send.
//!
//! The handshake is simpler than a TCP handshake:
//! The client sends a `Syn` frame, then the server replies an `SynAck`.
//! To reduce overhead, in `Syn`, the `dport` is 0, and the server replies
//! with a usable port in the `sport` of the `SynAck` frame.
//! The client asks for a target to `connect` in the `Syn` payload (see above).
//!
//! After a certain amount of `Psh` frames are received, the mux will send
//! a `Ack` frame to confirm the data. The `Ack` frame carries the current
//! remaining space in the receive buffer as a `u64`. (Similar to TCP receiving
//! window). One side should never write more frames than the other side's
//! receive window size before receiving the next `Ack` frame.
//!
//! `Datagram` messages are connectionless. On the client side,
//! each forwarder client (i.e. (port, host) tuple) is assigned a unique
//! Source ID, and the frame also carries its intended target.
//! When the server receives datagrams from that target, it will
//! send them back to the client with the same Source ID.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
#![allow(clippy::similar_names)]

use crate::ws::Message;
use bytes::{Buf, BufMut, Bytes};
use std::{fmt::Debug, num::TryFromIntError};
use thiserror::Error;
use tracing::warn;

/// Errors that can occur when parsing a frame.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Frame is invalid or incomplete")]
    FrameTooShort,
    #[error("Invalid frame type: {0}")]
    InvalidFrameType(u8),
    #[error("Invalid stream flag: {0}")]
    InvalidStreamFlag(u8),
}

/// Stream frame types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamFlag {
    /// Initiating connection by the client.
    Syn = 0,
    /// Confirming connection by the server.
    SynAck = 1,
    /// Confirming data reception.
    Ack = 2,
    /// Aborting connection when `dport` does not exist.
    Rst = 3,
    /// Closing connection.
    Fin = 4,
    /// Sending data.
    Psh = 5,
}

/// Stream frame.
///
/// See PROTOCOL.md for details.
#[derive(Clone, PartialEq, Eq)]
#[repr(C)]
pub struct StreamFrame {
    /// Source port (2 bytes)
    pub sport: u16,
    /// Destination port (2 bytes)
    pub dport: u16,
    /// Frame type (1 byte)
    pub flag: StreamFlag,
    /// Data
    pub data: Bytes,
}

impl Debug for StreamFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamFrame")
            .field("sport", &self.sport)
            .field("dport", &self.dport)
            .field("flag", &self.flag)
            .field("data.len", &self.data.len())
            .finish()
    }
}

impl StreamFrame {
    /// Create a new [`StreamFlag::Syn`] frame.
    ///
    /// # Arguments
    /// * `dest_host`: The destination host to forward to.
    /// * `dest_port`: The destination port to forward to.
    /// * `sport`: The source port of this stream.
    /// * `rwnd`: Number of frames buffered in the client receive buffer.
    #[must_use]
    #[inline]
    pub fn new_syn(dest_host: &[u8], dest_port: u16, sport: u16, rwnd: u64) -> Self {
        let host_len = dest_host.len();
        let mut syn_payload =
            Vec::with_capacity(std::mem::size_of::<u64>() + std::mem::size_of::<u16>() + host_len);
        syn_payload.put_u64(rwnd);
        syn_payload.put_u16(dest_port);
        syn_payload.extend(dest_host);
        Self {
            sport,
            dport: 0,
            flag: StreamFlag::Syn,
            data: Bytes::from(syn_payload),
        }
    }
    /// Create a new [`StreamFlag::SynAck`] frame.
    ///
    /// # Arguments
    /// * `sport`: The source port of this stream.
    /// * `dport`: The destination port of this stream (i.e. the source port
    ///   of the `Syn` frame).
    /// * `rwnd`: Number of frames buffered in the server receive buffer.
    #[must_use]
    #[inline]
    pub fn new_synack(sport: u16, dport: u16, rwnd: u64) -> Self {
        Self {
            sport,
            dport,
            flag: StreamFlag::SynAck,
            data: Bytes::copy_from_slice(&rwnd.to_be_bytes()),
        }
    }
    /// Create a new [`StreamFlag::Ack`] frame.
    ///
    /// # Arguments
    /// * `sport`: The source port of this stream.
    /// * `dport`: The destination port of this stream.
    /// * `psh_recvd_since`: The number of `Psh` frames received since the
    ///   previous `Ack` frame.
    #[must_use]
    #[inline]
    pub fn new_ack(sport: u16, dport: u16, psh_recvd_since: u64) -> Self {
        Self {
            sport,
            dport,
            flag: StreamFlag::Ack,
            data: Bytes::copy_from_slice(&psh_recvd_since.to_be_bytes()),
        }
    }
    /// Create a new [`StreamFlag::Rst`] frame.
    ///
    /// # Arguments
    /// * `sport`: The destination port of the offending frame.
    /// * `dport`: The source port of the offending frame.
    #[must_use]
    #[inline]
    pub const fn new_rst(sport: u16, dport: u16) -> Self {
        Self {
            sport,
            dport,
            flag: StreamFlag::Rst,
            data: Bytes::new(),
        }
    }
    /// Create a new [`StreamFlag::Fin`] frame.
    ///
    /// # Arguments
    /// * `sport`: The source port of this stream.
    /// * `dport`: The destination port of this stream.
    #[must_use]
    #[inline]
    pub const fn new_fin(sport: u16, dport: u16) -> Self {
        Self {
            sport,
            dport,
            flag: StreamFlag::Fin,
            data: Bytes::new(),
        }
    }
    /// Create a new [`StreamFlag::Psh`] frame.
    ///
    /// # Arguments
    /// * `sport`: The source port of this stream.
    /// * `dport`: The destination port of this stream.
    /// * `data`: The data to send.
    #[must_use]
    #[inline]
    pub const fn new_psh(sport: u16, dport: u16, data: Bytes) -> Self {
        Self {
            sport,
            dport,
            flag: StreamFlag::Psh,
            data,
        }
    }
}

/// Datagram frame.
///
/// See PROTOCOL.md for details.
#[derive(Clone, PartialEq, Eq)]
#[repr(C)]
pub struct DatagramFrame {
    /// Target host:
    /// Host of the forwarding target
    /// host of the "remote" if sent from client;
    /// host of the "from" if sent from server.
    pub host: Bytes,
    /// Target port:
    /// Port of the forwarding target
    pub port: u16,
    /// User ID (4 bytes)
    pub sid: u32,
    /// Data
    pub data: Bytes,
}

impl Debug for DatagramFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramFrame")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("sid", &self.sid)
            .field("data.len", &self.data.len())
            .finish()
    }
}

/// Frame.
///
/// See PROTOCOL.md for details.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub enum Frame {
    /// Stream frame, encoded with `Type=0x01`
    Stream(StreamFrame),
    /// Datagram frame, encoded with `Type=0x03`
    Datagram(DatagramFrame),
}

impl From<StreamFrame> for Vec<u8> {
    /// Convert a [`StreamFrame`] to bytes.
    #[tracing::instrument(level = "trace")]
    #[inline]
    fn from(frame: StreamFrame) -> Self {
        let size = 1
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<StreamFlag>()
            + std::mem::size_of::<u32>()
            + frame.data.len();
        let mut encoded = Self::with_capacity(size);
        encoded.put_u8(1);
        encoded.put_u16(frame.sport);
        encoded.put_u16(frame.dport);
        encoded.put_u8(frame.flag as u8);
        encoded.extend(&frame.data);
        encoded
    }
}

impl TryFrom<DatagramFrame> for Vec<u8> {
    type Error = TryFromIntError;

    /// Convert a [`DatagramFrame`] to bytes. Gives an error when
    /// [`DatagramFrame::host`] is longer than 255 octets.
    #[inline]
    fn try_from(frame: DatagramFrame) -> Result<Self, Self::Error> {
        let size = 1
            + frame.host.len()
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<u32>()
            + frame.data.len();
        let mut encoded = Self::with_capacity(size);
        encoded.put_u8(3);
        encoded.put_u8(u8::try_from(frame.host.len())?);
        encoded.extend(&frame.host);
        encoded.put_u16(frame.port);
        encoded.put_u32(frame.sid);
        encoded.extend(&frame.data);
        Ok(encoded)
    }
}

impl TryFrom<Frame> for Vec<u8> {
    type Error = TryFromIntError;

    #[inline]
    fn try_from(frame: Frame) -> Result<Self, Self::Error> {
        match frame {
            Frame::Stream(frame) => Ok(frame.into()),
            Frame::Datagram(frame) => frame.try_into(),
        }
    }
}

impl TryFrom<Bytes> for StreamFrame {
    type Error = Error;

    #[inline]
    fn try_from(mut data: Bytes) -> Result<Self, Self::Error> {
        if data.remaining() < 5 {
            return Err(Error::FrameTooShort);
        }
        let sport = data.get_u16();
        let dport = data.get_u16();
        let flag = match data.get_u8() {
            0 => StreamFlag::Syn,
            1 => StreamFlag::SynAck,
            2 => StreamFlag::Ack,
            3 => StreamFlag::Rst,
            4 => StreamFlag::Fin,
            5 => StreamFlag::Psh,
            other => return Err(Error::InvalidStreamFlag(other)),
        };
        Ok(Self {
            sport,
            dport,
            flag,
            data,
        })
    }
}

impl TryFrom<Bytes> for DatagramFrame {
    type Error = Error;

    #[inline]
    fn try_from(mut data: Bytes) -> Result<Self, Self::Error> {
        if data.remaining() < 1 {
            return Err(Error::FrameTooShort);
        }
        let host_len = usize::from(data.get_u8());

        if data.remaining() < host_len + 6 {
            return Err(Error::FrameTooShort);
        }
        let host = data.split_to(host_len);
        let port = data.get_u16();
        let sid = data.get_u32();
        Ok(Self {
            host,
            port,
            sid,
            data,
        })
    }
}

impl TryFrom<Bytes> for Frame {
    type Error = Error;

    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    fn try_from(mut data: Bytes) -> Result<Self, Self::Error> {
        if data.remaining() < 1 {
            return Err(Error::FrameTooShort);
        }
        let frame_type = data.get_u8();
        match frame_type {
            1 => Ok(Self::Stream(StreamFrame::try_from(data)?)),
            3 => Ok(Self::Datagram(DatagramFrame::try_from(data)?)),
            other => Err(Error::InvalidFrameType(other)),
        }
    }
}

// I thought the rest was automatically implemented by the compiler.
// Add when needed.
impl From<StreamFrame> for Message {
    #[inline]
    fn from(frame: StreamFrame) -> Self {
        Vec::<u8>::from(frame).into()
    }
}

impl TryFrom<Vec<u8>> for Frame {
    type Error = <Self as TryFrom<Bytes>>::Error;

    #[inline]
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(Bytes::from(data))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_stream_frame() {
        let frame = Frame::Stream(StreamFrame::new_syn(&[], 5678, 1234, 128));
        assert_eq!(
            frame,
            Frame::Stream(StreamFrame {
                sport: 1234,
                dport: 0,
                flag: StreamFlag::Syn,
                data: Bytes::from_static(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x16, 0x2e
                ]),
            })
        );
        let bytes = Vec::try_from(frame.clone()).unwrap();
        let decoded = Frame::try_from(bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_datagram_frame() {
        let frame = Frame::Datagram(DatagramFrame {
            host: Bytes::from_static(&[1, 2, 3, 4]),
            port: 1234,
            sid: 5678,
            data: Bytes::from_static(&[1, 2, 3, 4]),
        });
        let bytes = Vec::try_from(frame.clone()).unwrap();
        let decoded = Frame::try_from(bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    /// These tests are to make sure that the binary representation of the
    /// frames does not change without a protocol version bump.
    #[test]
    fn test_frame_repr() {
        let frame = Frame::Stream(StreamFrame::new_syn(&[0x01, 0x02, 0x03], 5678, 1234, 512));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x04, 0xd2, // sport (u16)
                0x00, 0x00, // dport (u16)
                0x00, // flag (u8)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, // rwnd (u64)
                0x16, 0x2e, // dest_port (u16)
                0x01, 0x02, 0x03, // data (variable)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_synack(1234, 5678, 128));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x04, 0xd2, // sport (u16)
                0x16, 0x2e, // dport (u16)
                0x01, // flag (u8)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // rwnd (u64)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_ack(5678, 1234, 128));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x16, 0x2e, // sport (u16)
                0x04, 0xd2, // dport (u16)
                0x02, // flag (u8)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // psh_recvd_since (u64)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_rst(1234, 5678));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x04, 0xd2, // sport (u16)
                0x16, 0x2e, // dport (u16)
                0x03, // flag (u8)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_fin(5678, 1234));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x16, 0x2e, // sport (u16)
                0x04, 0xd2, // dport (u16)
                0x04  // flag (u8)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_psh(
            1234,
            5678,
            Bytes::from_static(&[1, 2, 3, 4]),
        ));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x04, 0xd2, // sport (u16)
                0x16, 0x2e, // dport (u16)
                0x05, // flag (u8)
                0x01, 0x02, 0x03, 0x04 // data (variable)
            ]
        );

        let frame = Frame::Datagram(DatagramFrame {
            host: Bytes::from_static(&[1, 2, 3, 4]),
            port: 1234,
            sid: 5678,
            data: Bytes::from_static(&[1, 2, 3, 4]),
        });
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x03, // frame type (u8)
                0x04, // host len (u8)
                0x01, 0x02, 0x03, 0x04, // host (variable)
                0x04, 0xd2, // port (u16)
                0x00, 0x00, 0x16, 0x2e, // sid (u32)
                0x01, 0x02, 0x03, 0x04 // data (variable)
            ]
        );
    }
}
