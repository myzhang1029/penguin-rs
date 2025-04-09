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
use std::{borrow::Cow, fmt::Debug, mem::size_of, num::TryFromIntError};
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

/// Types of frames
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Type {
    /// Stream frame
    Stream = 1,
    /// Datagram frame
    Datagram = 3,
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

/// Stream frame payload
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamPayload<'data> {
    /// `Con` payload
    /// `rwnd`: Number of frames buffered in the receive buffer
    /// `target_port`: The destination port to forward to (client), or the local port (server)
    /// `target_host`: The destination host to forward to (client), or the local address (server)
    Con {
        rwnd: u32,
        target_port: u16,
        target_host: Cow<'data, [u8]>,
    },
    /// `Ack` payload
    /// `psh_recvd_since`: The number of `Psh` frames received since the previous `Ack` frame
    /// or
    /// `rwnd`: Number of frames buffered in the receive buffer
    Ack(u32),
    /// `Rst` has no payload
    Rst,
    /// `Fin` has no payload
    Fin,
    /// `Psh` payload
    Psh(Cow<'data, [u8]>),
    /// `Bnd` payload
    /// `target_port`: The local port to bind to
    /// `target_host`: The local address to bind to
    Bnd {
        target_port: u16,
        target_host: Cow<'data, [u8]>,
    },
}

impl StreamPayload<'_> {
    #[inline]
    fn len(&self) -> usize {
        match self {
            StreamPayload::Con { target_host, .. } => {
                size_of::<u32>() + size_of::<u16>() + target_host.len()
            }
            StreamPayload::Ack(_) => size_of::<u32>(),
            StreamPayload::Rst | StreamPayload::Fin => 0,
            StreamPayload::Psh(data) => data.len(),
            StreamPayload::Bnd { target_host, .. } => size_of::<u16>() + target_host.len(),
        }
    }
}

impl<'data> From<&StreamPayload<'data>> for StreamOpCode {
    fn from(payload: &StreamPayload<'data>) -> Self {
        match payload {
            StreamPayload::Con { .. } => Self::Con,
            StreamPayload::Ack(_) => Self::Ack,
            StreamPayload::Rst => Self::Rst,
            StreamPayload::Fin => Self::Fin,
            StreamPayload::Psh(_) => Self::Psh,
            StreamPayload::Bnd { .. } => Self::Bnd,
        }
    }
}

/// Stream frame
///
/// See PROTOCOL.md for details.
#[derive(Clone, PartialEq, Eq)]
#[repr(C)]
pub struct StreamFrame<'data> {
    /// Source port
    pub sport: u16,
    /// Destination port
    pub dport: u16,
    /// Payload data
    pub payload: StreamPayload<'data>,
}

impl Debug for StreamFrame<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamFrame")
            .field("opcode", &StreamOpCode::from(&self.payload))
            .field("sport", &self.sport)
            .field("dport", &self.dport)
            .field("payload.len", &self.payload.len())
            .finish()
    }
}

impl<'data> StreamFrame<'data> {
    /// Create a new [`StreamFlag::Con`] frame.
    ///
    /// # Arguments
    /// * `target_host`: The destination host to forward to (client), or the local address (server).
    /// * `target_port`: The destination port to forward to (client), or the local port (server).
    /// * `sport`: The source port of this stream.
    /// * `rwnd`: Number of frames buffered in the client receive buffer.
    #[must_use]
    #[inline]
    pub const fn new_con(
        target_host: &'data [u8],
        target_port: u16,
        sport: u16,
        rwnd: u32,
    ) -> Self {
        let payload = StreamPayload::Con {
            rwnd,
            target_port,
            target_host: Cow::Borrowed(target_host),
        };
        Self {
            sport,
            dport: 0,
            payload,
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
    pub const fn new_ack(sport: u16, dport: u16, psh_recvd_since: u32) -> Self {
        let payload = StreamPayload::Ack(psh_recvd_since);
        Self {
            sport,
            dport,
            payload,
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
            sport,
            dport,
            payload: StreamPayload::Rst,
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
            payload: StreamPayload::Fin,
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
    pub const fn new_psh(sport: u16, dport: u16, data: &'data [u8]) -> Self {
        Self {
            sport,
            dport,
            payload: StreamPayload::Psh(Cow::Borrowed(data)),
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
    pub const fn new_bnd(sport: u16, target_host: &'data [u8], target_port: u16) -> Self {
        let payload = StreamPayload::Bnd {
            target_port,
            target_host: Cow::Borrowed(target_host),
        };
        Self {
            sport,
            dport: 0,
            payload,
        }
    }

    /// Copy the frame into a [`FinalizedFrame`]
    #[must_use]
    #[inline]
    pub(crate) fn finalize(self) -> FinalizedFrame {
        FinalizedFrame(Vec::from(self))
    }
}

/// Datagram frame
///
/// See PROTOCOL.md for details.
#[derive(Clone, PartialEq, Eq)]
#[repr(C)]
pub struct DatagramFrame<'data> {
    /// Source port (2 bytes)
    pub sport: u16,
    /// Destination port (2 bytes)
    pub dport: u16,
    /// Target host:
    /// Host of the forwarding target
    /// host of the "remote" if sent from client;
    /// host of the "from" if sent from server.
    pub target_host: Cow<'data, [u8]>,
    /// Target port:
    /// Port of the forwarding target
    pub target_port: u16,
    /// Data
    pub data: Cow<'data, [u8]>,
}

impl Debug for DatagramFrame<'_> {
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

impl<'data> DatagramFrame<'data> {
    /// Create a new datagram frame
    ///
    /// # Arguments
    /// * `sport`: The source port of this datagram.
    /// * `dport`: The destination port of this datagram.
    /// * `target_host`: The host to forward to.
    /// * `target_port`: The port to forward to.
    /// * `data`: The data to send.
    #[must_use]
    #[inline]
    pub const fn new(
        sport: u16,
        dport: u16,
        target_host: &'data [u8],
        target_port: u16,
        data: &'data [u8],
    ) -> Self {
        Self {
            sport,
            dport,
            target_host: Cow::Borrowed(target_host),
            target_port,
            data: Cow::Borrowed(data),
        }
    }

    /// Copy the frame into a [`FinalizedFrame`]
    #[inline]
    pub(crate) fn finalize(self) -> Result<FinalizedFrame, TryFromIntError> {
        Ok(FinalizedFrame(Vec::try_from(self)?))
    }
}

/// A frame
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame<'data> {
    /// Stream frame, encoded with `Type::Stream`
    Stream(StreamFrame<'data>),
    /// Datagram frame, encoded with `Type::Datagram`
    Datagram(DatagramFrame<'data>),
}

impl From<StreamFrame<'_>> for Vec<u8> {
    /// Encode a [`StreamFrame`] to bytes
    #[tracing::instrument(level = "trace")]
    #[inline]
    fn from(frame: StreamFrame<'_>) -> Self {
        let size = size_of::<u8>()
            + size_of::<u8>()
            + size_of::<u16>()
            + size_of::<u16>()
            + frame.payload.len();
        let opcode = StreamOpCode::from(&frame.payload) as u8;
        let mut encoded = Self::with_capacity(size);
        encoded.put_u8(Type::Stream as u8);
        encoded.put_u8(opcode);
        encoded.put_u16(frame.sport);
        encoded.put_u16(frame.dport);
        match frame.payload {
            StreamPayload::Con {
                rwnd,
                target_port,
                target_host,
            } => {
                encoded.put_u32(rwnd);
                encoded.put_u16(target_port);
                encoded.extend(target_host.as_ref());
            }
            StreamPayload::Ack(psh_recvd_since) => {
                encoded.put_u32(psh_recvd_since);
            }
            StreamPayload::Rst | StreamPayload::Fin => {}
            StreamPayload::Psh(data) => {
                encoded.extend(data.as_ref());
            }
            StreamPayload::Bnd {
                target_port,
                target_host,
            } => {
                encoded.put_u16(target_port);
                encoded.extend(target_host.as_ref());
            }
        }
        encoded
    }
}

impl TryFrom<DatagramFrame<'_>> for Vec<u8> {
    type Error = TryFromIntError;

    /// Convert a [`DatagramFrame`] to bytes. Gives an error when
    /// [`DatagramFrame::host`] is longer than 255 octets.
    #[inline]
    fn try_from(frame: DatagramFrame<'_>) -> Result<Self, Self::Error> {
        let size = size_of::<u8>()
            + frame.target_host.len()
            + size_of::<u16>()
            + size_of::<u16>()
            + size_of::<u16>()
            + frame.data.len();
        let mut encoded = Self::with_capacity(size);
        encoded.put_u8(Type::Datagram as u8);
        encoded.put_u8(u8::try_from(frame.target_host.len())?);
        encoded.put_u16(frame.sport);
        encoded.put_u16(frame.dport);
        encoded.put_u16(frame.target_port);
        encoded.extend(frame.target_host.as_ref());
        encoded.extend(frame.data.as_ref());
        Ok(encoded)
    }
}

impl<'data> TryFrom<Frame<'data>> for Vec<u8> {
    type Error = TryFromIntError;

    #[inline]
    fn try_from(frame: Frame<'data>) -> Result<Self, Self::Error> {
        match frame {
            Frame::Stream(stream_frame) => Ok(Self::from(stream_frame)),
            Frame::Datagram(datagram_frame) => Self::try_from(datagram_frame),
        }
    }
}

macro_rules! check_remaining {
    ($data:expr, $len:expr) => {
        if $data.remaining() < $len {
            return Err(Error::FrameTooShort);
        }
    };
}

impl TryFrom<Bytes> for StreamFrame<'_> {
    type Error = Error;

    #[inline]
    fn try_from(mut data: Bytes) -> Result<Self, Self::Error> {
        check_remaining!(data, size_of::<u8>() + size_of::<u16>() + size_of::<u16>());
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
        let payload = match opcode {
            StreamOpCode::Con => {
                check_remaining!(data, size_of::<u32>() + size_of::<u16>());
                let rwnd = data.get_u32();
                let target_port = data.get_u16();
                let target_host = data;
                StreamPayload::Con {
                    rwnd,
                    target_port,
                    target_host: Cow::Owned(target_host.into()),
                }
            }
            StreamOpCode::Ack => {
                check_remaining!(data, size_of::<u32>());
                let psh_recvd_since = data.get_u32();
                StreamPayload::Ack(psh_recvd_since)
            }
            StreamOpCode::Rst => StreamPayload::Rst,
            StreamOpCode::Fin => StreamPayload::Fin,
            StreamOpCode::Psh => StreamPayload::Psh(Cow::Owned(data.into())),
            StreamOpCode::Bnd => {
                check_remaining!(data, size_of::<u16>());
                let target_port = data.get_u16();
                StreamPayload::Bnd {
                    target_port,
                    target_host: Cow::Owned(data.into()),
                }
            }
        };
        Ok(Self {
            sport,
            dport,
            payload,
        })
    }
}

impl TryFrom<Vec<u8>> for StreamFrame<'_> {
    type Error = <Self as TryFrom<Bytes>>::Error;
    #[inline]
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(Bytes::from(data))
    }
}

impl TryFrom<Bytes> for DatagramFrame<'_> {
    type Error = Error;

    #[inline]
    fn try_from(mut data: Bytes) -> Result<Self, Self::Error> {
        check_remaining!(data, size_of::<u8>() + 6);
        let host_len = usize::from(data.get_u8());
        check_remaining!(data, host_len + 6);
        let sport = data.get_u16();
        let dport = data.get_u16();
        let target_port = data.get_u16();
        let target_host = data.split_to(host_len);
        Ok(Self {
            sport,
            dport,
            target_host: Cow::Owned(target_host.into()),
            target_port,
            data: Cow::Owned(data.into()),
        })
    }
}

impl TryFrom<Vec<u8>> for DatagramFrame<'_> {
    type Error = <Self as TryFrom<Bytes>>::Error;
    #[inline]
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(Bytes::from(data))
    }
}

impl TryFrom<Bytes> for Frame<'_> {
    type Error = Error;

    #[tracing::instrument(skip_all, level = "trace")]
    #[inline]
    fn try_from(mut data: Bytes) -> Result<Self, Self::Error> {
        check_remaining!(data, size_of::<u8>());
        let frame_type = data.get_u8();
        match frame_type {
            1 => Ok(Self::Stream(StreamFrame::try_from(data)?)),
            3 => Ok(Self::Datagram(DatagramFrame::try_from(data)?)),
            other => Err(Error::InvalidFrameType(other)),
        }
    }
}

impl TryFrom<Vec<u8>> for Frame<'_> {
    type Error = <Self as TryFrom<Bytes>>::Error;
    #[inline]
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(Bytes::from(data))
    }
}

/// An owned and finalized frame for single-copy operations
#[derive(Clone, PartialEq, Eq)]
pub struct FinalizedFrame(Vec<u8>);

impl FinalizedFrame {
    pub const FLUSH: Self = Self(Vec::new());

    /// Check if the frame is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the frame type
    #[inline]
    pub fn frame_type(&self) -> Option<Type> {
        match self.0.first() {
            Some(1) => Some(Type::Stream),
            Some(3) => Some(Type::Datagram),
            _ => None,
        }
    }

    /// Check if the frame is a stream frame
    #[inline]
    pub fn is_stream(&self) -> bool {
        if self.0.is_empty() {
            return false;
        }
        self.frame_type() == Some(Type::Stream)
    }

    /// Check if the frame is a stream frame with a specific opcode
    #[inline]
    pub fn is_stream_with_opcode(&self, opcode: StreamOpCode) -> bool {
        if !self.is_stream() {
            return false;
        }
        if self.0.len() < 2 {
            return false;
        }
        self.0[1] == opcode as u8
    }
}

impl Debug for FinalizedFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalizedFrame")
            .field("frame_type", &self.frame_type())
            .field("encoded_len", &self.0.len())
            .finish()
    }
}

impl<'data> TryFrom<Frame<'data>> for FinalizedFrame {
    type Error = <Vec<u8> as TryFrom<Frame<'data>>>::Error;
    #[inline]
    fn try_from(frame: Frame<'data>) -> Result<Self, Self::Error> {
        Ok(Self(Vec::try_from(frame)?))
    }
}

impl TryFrom<FinalizedFrame> for Frame<'_> {
    type Error = <Self as TryFrom<Vec<u8>>>::Error;
    #[inline]
    fn try_from(frame: FinalizedFrame) -> Result<Self, Self::Error> {
        Frame::try_from(frame.0)
    }
}

impl From<Bytes> for FinalizedFrame {
    fn from(bytes: Bytes) -> Self {
        Self(bytes.into())
    }
}

impl From<FinalizedFrame> for Bytes {
    fn from(frame: FinalizedFrame) -> Self {
        frame.0.into()
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
                sport: 1234,
                dport: 0,
                payload: StreamPayload::Con {
                    rwnd: 128,
                    target_port: 5678,
                    target_host: Cow::Borrowed(&[])
                }
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
            target_host: Cow::Borrowed(&[1, 2, 3, 4]),
            target_port: 1234,
            data: Cow::Borrowed(&[1, 2, 3, 4]),
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

        let frame = Frame::Stream(StreamFrame::new_psh(1234, 43131, &[1, 2, 3, 4]));
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
            target_host: Cow::Borrowed(&[1, 2, 3, 4]),
            target_port: 1234,
            data: Cow::Borrowed(&[1, 2, 3, 4]),
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
