//! Frames.
//! Each frame strictly fits in a `Message`.
//!
//! Architecture:
//! The system is similar to a traditional SOCKS5 proxy, but the protocol
//! allows for UDP to be transmitted over the same WebSocket connection.
//!
//! For more details, see the `PROTOCOL.md` file in the project root.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
#![allow(clippy::similar_names)]

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

/// Stream operation codes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamOpCode {
    /// Initiating connection by the client
    Con = 0,
    /// Confirming data reception
    Ack = 2,
    /// Aborting connection
    Rst = 3,
    /// Closing connection
    Fin = 4,
    /// Sending data
    Psh = 5,
    /// Binding a port
    Bnd = 6,
}

/// Stream frame.
///
/// See PROTOCOL.md for details.
#[derive(Clone, PartialEq, Eq)]
#[repr(C)]
pub struct StreamFrame {
    /// Operation code (1 byte)
    pub opcode: StreamOpCode,
    /// Source port (2 bytes)
    pub sport: u16,
    /// Destination port (2 bytes)
    pub dport: u16,
    /// Data
    pub data: Bytes,
}

impl Debug for StreamFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamFrame")
            .field("opcode", &self.opcode)
            .field("sport", &self.sport)
            .field("dport", &self.dport)
            .field("data.len", &self.data.len())
            .finish()
    }
}

impl StreamFrame {
    /// Create a new [`StreamFlag::Con`] frame.
    ///
    /// # Arguments
    /// * `target_host`: The destination host to forward to (client), or the local address (server).
    /// * `target_port`: The destination port to forward to (client), or the local port (server).
    /// * `sport`: The source port of this stream.
    /// * `rwnd`: Number of frames buffered in the client receive buffer.
    #[must_use]
    #[inline]
    pub fn new_con(target_host: &[u8], target_port: u16, sport: u16, rwnd: u32) -> Self {
        let host_len = target_host.len();
        let mut con_payload =
            Vec::with_capacity(std::mem::size_of::<u32>() + std::mem::size_of::<u16>() + host_len);
        con_payload.put_u32(rwnd);
        con_payload.put_u16(target_port);
        con_payload.extend(target_host);
        Self {
            opcode: StreamOpCode::Con,
            sport,
            dport: 0,
            data: Bytes::from(con_payload),
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
    pub fn new_ack(sport: u16, dport: u16, psh_recvd_since: u32) -> Self {
        Self {
            opcode: StreamOpCode::Ack,
            sport,
            dport,
            data: Bytes::copy_from_slice(&psh_recvd_since.to_be_bytes()),
        }
    }
    /// Create a new [`StreamFlag::Rst`] frame.
    ///
    /// # Arguments
    /// * `sport`: The source port of the offending stream.
    /// * `dport`: The destination port of offending stream.
    #[must_use]
    #[inline]
    pub const fn new_rst(sport: u16, dport: u16) -> Self {
        Self {
            opcode: StreamOpCode::Rst,
            sport,
            dport,
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
            opcode: StreamOpCode::Fin,
            sport,
            dport,
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
            opcode: StreamOpCode::Psh,
            sport,
            dport,
            data,
        }
    }

    /// Create a new [`StreamFlag::Bnd`] frame.
    ///
    /// # Arguments
    /// * `sport`: An identifier for this Bind request.
    /// * `target_host`: The local address to bind to.
    /// * `target_port`: The port to bind to.
    #[must_use]
    #[inline]
    pub fn new_bnd(sport: u16, target_host: &[u8], target_port: u16) -> Self {
        let mut bnd_payload = Vec::with_capacity(std::mem::size_of::<u16>() + target_host.len());
        bnd_payload.put_u16(target_port);
        bnd_payload.extend(target_host);
        Self {
            opcode: StreamOpCode::Bnd,
            sport,
            dport: 0,
            data: Bytes::from(bnd_payload),
        }
    }
}

/// Datagram frame.
///
/// See PROTOCOL.md for details.
#[derive(Clone, PartialEq, Eq)]
#[repr(C)]
pub struct DatagramFrame {
    /// Source port (2 bytes)
    pub sport: u16,
    /// Destination port (2 bytes)
    pub dport: u16,
    /// Target host:
    /// Host of the forwarding target
    /// host of the "remote" if sent from client;
    /// host of the "from" if sent from server.
    pub target_host: Bytes,
    /// Target port:
    /// Port of the forwarding target
    pub target_port: u16,
    /// Data
    pub data: Bytes,
}

impl Debug for DatagramFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramFrame")
            .field("sport", &self.sport)
            .field("dport", &self.dport)
            .field("target_host", &self.target_host)
            .field("target_port", &self.target_port)
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
    /// This variant is used for internal purposes only
    /// It should not be leaked to the user.
    Flush,
}

impl From<StreamFrame> for Vec<u8> {
    /// Convert a [`StreamFrame`] to bytes.
    #[tracing::instrument(level = "trace")]
    #[inline]
    fn from(frame: StreamFrame) -> Self {
        let size = std::mem::size_of::<u8>()
            + std::mem::size_of::<StreamOpCode>()
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<u16>()
            + frame.data.len();
        let mut encoded = Self::with_capacity(size);
        encoded.put_u8(1);
        encoded.put_u8(frame.opcode as u8);
        encoded.put_u16(frame.sport);
        encoded.put_u16(frame.dport);
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
            + frame.target_host.len()
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<u16>()
            + frame.data.len();
        let mut encoded = Self::with_capacity(size);
        encoded.put_u8(3);
        encoded.put_u8(u8::try_from(frame.target_host.len())?);
        encoded.put_u16(frame.sport);
        encoded.put_u16(frame.dport);
        encoded.put_u16(frame.target_port);
        encoded.extend(&frame.target_host);
        encoded.extend(&frame.data);
        Ok(encoded)
    }
}

impl TryFrom<Frame> for Vec<u8> {
    type Error = TryFromIntError;

    /// Convert a [`Frame`] to bytes.
    ///
    /// # Panics
    /// This will panic if the frame is an internal `Flush` frame.
    #[inline]
    fn try_from(frame: Frame) -> Result<Self, Self::Error> {
        match frame {
            Frame::Stream(frame) => Ok(frame.into()),
            Frame::Datagram(frame) => frame.try_into(),
            // This variant should not be serialized by conforming code
            Frame::Flush => {
                panic!(
                    "Internal frame type {frame:?} should not be serialized to bytes (this is a bug)"
                )
            }
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
        let opcode = match data.get_u8() {
            0 => StreamOpCode::Con,
            // 0x01 is reserved
            2 => StreamOpCode::Ack,
            3 => StreamOpCode::Rst,
            4 => StreamOpCode::Fin,
            5 => StreamOpCode::Psh,
            6 => StreamOpCode::Bnd,
            other => return Err(Error::InvalidStreamFlag(other)),
        };
        let sport = data.get_u16();
        let dport = data.get_u16();
        Ok(Self {
            opcode,
            sport,
            dport,
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
        let sport = data.get_u16();
        let dport = data.get_u16();
        let target_port = data.get_u16();
        let target_host = data.split_to(host_len);
        Ok(Self {
            sport,
            dport,
            target_host,
            target_port,
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
impl From<StreamFrame> for Frame {
    #[inline]
    fn from(frame: StreamFrame) -> Self {
        Self::Stream(frame)
    }
}

impl From<DatagramFrame> for Frame {
    #[inline]
    fn from(frame: DatagramFrame) -> Self {
        Self::Datagram(frame)
    }
}

impl TryFrom<Frame> for Bytes {
    type Error = <Vec<u8> as TryFrom<Frame>>::Error;

    #[inline]
    fn try_from(frame: Frame) -> Result<Self, Self::Error> {
        Vec::try_from(frame).map(Self::from)
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
mod tests {
    use super::*;

    #[test]
    fn test_stream_frame() {
        crate::tests::setup_logging();
        let frame = Frame::Stream(StreamFrame::new_con(&[], 5678, 1234, 128));
        assert_eq!(
            frame,
            Frame::Stream(StreamFrame {
                opcode: StreamOpCode::Con,
                sport: 1234,
                dport: 0,
                data: Bytes::from_static(&[0x00, 0x00, 0x00, 0x80, 0x16, 0x2e]),
            })
        );
        let bytes = Vec::try_from(frame.clone()).unwrap();
        let decoded = Frame::try_from(bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_datagram_frame() {
        crate::tests::setup_logging();
        let frame = Frame::Datagram(DatagramFrame {
            sport: 5678,
            dport: 9443,
            target_host: Bytes::from_static(&[1, 2, 3, 4]),
            target_port: 1234,
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
        crate::tests::setup_logging();
        let frame = Frame::Stream(StreamFrame::new_con(&[0x01, 0x02, 0x03], 5678, 1234, 512));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x00, // opcode (u8)
                0x04, 0xd2, // sport (u16)
                0x00, 0x00, // dport (u16)
                0x00, 0x00, 0x02, 0x00, // rwnd (u32)
                0x16, 0x2e, // dest_port (u16)
                0x01, 0x02, 0x03, // host (variable)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_ack(1234, 5678, 128));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x02, // opcode (u8)
                0x04, 0xd2, // sport (u16)
                0x16, 0x2e, // dport (u16)
                0x00, 0x00, 0x00, 0x80, // psh_recvd_since (u32)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_rst(1242, 1291));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x03, // opcode (u8)
                0x04, 0xda, // sport (u16)
                0x05, 0x0b, // dport (u32)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_fin(5678, 21324));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x04, // opcode (u8)
                0x16, 0x2e, // sport (u32)
                0x53, 0x4c, // dport (u32)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_psh(
            1234,
            43131,
            Bytes::from_static(&[1, 2, 3, 4]),
        ));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x05, // opcode (u8)
                0x04, 0xd2, // sport (u32)
                0xa8, 0x7b, // dport (u32)
                0x01, 0x02, 0x03, 0x04 // data (variable)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_bnd(42132, &[1, 2, 3, 4], 1234));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x06, // opcode (u8)
                0xa4, 0x94, // sport (u16)
                0x00, 0x00, // dport (u16)
                0x04, 0xd2, // target_port (u16)
                0x01, 0x02, 0x03, 0x04 // target_host (variable)
            ]
        );

        let frame = Frame::Datagram(DatagramFrame {
            sport: 2134,
            dport: 5678,
            target_host: Bytes::from_static(&[1, 2, 3, 4]),
            target_port: 1234,
            data: Bytes::from_static(&[1, 2, 3, 4]),
        });
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x03, // frame type (u8)
                0x04, // host len (u8)
                0x08, 0x56, // sport (u16)
                0x16, 0x2e, // dport (u16)
                0x04, 0xd2, // target_port (u16)
                0x01, 0x02, 0x03, 0x04, // target_host (variable)
                0x01, 0x02, 0x03, 0x04 // data (variable)
            ]
        );
    }
}
