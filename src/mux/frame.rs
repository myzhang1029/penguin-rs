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

/// Stream operation codes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamOpCode {
    /// Initiating connection by the client
    Syn = 0,
    /// Reserved
    _Reserved = 1,
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
    /// Stream ID (2 bytes)
    pub id: u16,
    /// Data
    pub data: Bytes,
}

impl Debug for StreamFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamFrame")
            .field("id", &self.id)
            .field("opcode", &self.opcode)
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
    /// * `id`: The ID of the stream.
    /// * `rwnd`: Number of frames buffered in the client receive buffer.
    #[must_use]
    #[inline]
    pub fn new_syn(dest_host: &[u8], dest_port: u16, id: u16, rwnd: u32) -> Self {
        let host_len = dest_host.len();
        let mut syn_payload =
            Vec::with_capacity(std::mem::size_of::<u32>() + std::mem::size_of::<u16>() + host_len);
        syn_payload.put_u32(rwnd);
        syn_payload.put_u16(dest_port);
        syn_payload.extend(dest_host);
        Self {
            opcode: StreamOpCode::Syn,
            id,
            data: Bytes::from(syn_payload),
        }
    }
    /// Create a new [`StreamFlag::Ack`] frame.
    ///
    /// # Arguments
    /// * `id`: The stream ID of the frame being acknowledged.
    /// * `psh_recvd_since`: The number of `Psh` frames received since the
    ///   previous `Ack` frame.
    #[must_use]
    #[inline]
    pub fn new_ack(id: u16, psh_recvd_since: u32) -> Self {
        Self {
            opcode: StreamOpCode::Ack,
            id,
            data: Bytes::copy_from_slice(&psh_recvd_since.to_be_bytes()),
        }
    }
    /// Create a new [`StreamFlag::Rst`] frame.
    ///
    /// # Arguments
    /// * `id`: The stream ID of the offending frame.
    #[must_use]
    #[inline]
    pub const fn new_rst(id: u16) -> Self {
        Self {
            opcode: StreamOpCode::Rst,
            id,
            data: Bytes::new(),
        }
    }
    /// Create a new [`StreamFlag::Fin`] frame.
    ///
    /// # Arguments
    /// * `id`: The stream ID of the frame being closed.
    #[must_use]
    #[inline]
    pub const fn new_fin(id: u16) -> Self {
        Self {
            opcode: StreamOpCode::Fin,
            id,
            data: Bytes::new(),
        }
    }
    /// Create a new [`StreamFlag::Psh`] frame.
    ///
    /// # Arguments
    /// * `id`: The stream ID of the frame.
    /// * `data`: The data to send.
    #[must_use]
    #[inline]
    pub const fn new_psh(id: u16, data: Bytes) -> Self {
        Self {
            opcode: StreamOpCode::Psh,
            id,
            data,
        }
    }

    // TODO: Implement `new_bnd` when needed.
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
        let size = std::mem::size_of::<u8>()
            + std::mem::size_of::<StreamOpCode>()
            + std::mem::size_of::<u16>()
            + frame.data.len();
        let mut encoded = Self::with_capacity(size);
        encoded.put_u8(1);
        encoded.put_u8(frame.opcode as u8);
        encoded.put_u16(frame.id);
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
        if data.remaining() < 3 {
            return Err(Error::FrameTooShort);
        }
        let opcode = match data.get_u8() {
            0 => StreamOpCode::Syn,
            // 0x01 is reserved
            2 => StreamOpCode::Ack,
            3 => StreamOpCode::Rst,
            4 => StreamOpCode::Fin,
            5 => StreamOpCode::Psh,
            6 => StreamOpCode::Bnd,
            other => return Err(Error::InvalidStreamFlag(other)),
        };
        let id = data.get_u16();
        Ok(Self { opcode, id, data })
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
mod tests {
    use super::*;

    #[test]
    fn test_stream_frame() {
        crate::tests::setup_logging();
        let frame = Frame::Stream(StreamFrame::new_syn(&[], 5678, 1234, 128));
        assert_eq!(
            frame,
            Frame::Stream(StreamFrame {
                id: 1234,
                opcode: StreamOpCode::Syn,
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
        crate::tests::setup_logging();
        let frame = Frame::Stream(StreamFrame::new_syn(&[0x01, 0x02, 0x03], 5678, 1234, 512));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x00, // opcode (u8)
                0x04, 0xd2, // id (u16)
                0x00, 0x00, 0x02, 0x00, // rwnd (u32)
                0x16, 0x2e, // dest_port (u16)
                0x01, 0x02, 0x03, // data (variable)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_ack(5678, 128));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x02, // opcode (u8)
                0x16, 0x2e, // id (u16)
                0x00, 0x00, 0x00, 0x80, // psh_recvd_since (u32)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_rst(1291));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x03, // opcode (u8)
                0x05, 0x0b, // id (u32)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_fin(5678));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x04, // opcode (u8)
                0x16, 0x2e, // id (u32)
            ]
        );

        let frame = Frame::Stream(StreamFrame::new_psh(
            1234,
            Bytes::from_static(&[1, 2, 3, 4]),
        ));
        let bytes = Vec::try_from(frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x01, // frame type (u8)
                0x05, // opcode (u8)
                0x04, 0xd2, // id (u32)
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
