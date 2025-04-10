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

use crate::proto_version;
use bytes::{Buf, BufMut, Bytes};
use std::{borrow::Cow, fmt::Debug, mem::size_of};
use thiserror::Error;

/// Errors that can occur when parsing a frame.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Frame is invalid or incomplete")]
    FrameTooShort,
    #[error("Unsupported frame version: {0}")]
    FrameVersion(u8),
    #[error("Invalid opcode: {0}")]
    InvalidOpCode(u8),
    #[error("Invalid `Bind` type: {0}")]
    InvalidBindType(u8),
}

/// Type codes for a `Bind` operation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BindType {
    /// Stream binding
    Stream = 1,
    /// Datagram binding
    Datagram = 3,
}

impl TryFrom<u8> for BindType {
    type Error = Error;
    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Stream),
            3 => Ok(Self::Datagram),
            other => Err(Error::InvalidBindType(other)),
        }
    }
}

/// Operation codes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    /// Initiating stream connection by the client
    Connect = 0,
    /// Confirming data reception or establishing connection
    Acknowledge = 1,
    /// Aborting connection or rejecting operation
    Reset = 2,
    /// Closing stream connection
    Finish = 3,
    /// Sending stream data
    Push = 4,
    /// Binding a port
    Bind = 5,
    /// Sending datagram
    Datagram = 6,
}

impl TryFrom<u8> for OpCode {
    type Error = Error;

    /// Parse a `u8` into an `OpCode`
    #[inline]
    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Connect),
            1 => Ok(Self::Acknowledge),
            2 => Ok(Self::Reset),
            3 => Ok(Self::Finish),
            4 => Ok(Self::Push),
            5 => Ok(Self::Bind),
            6 => Ok(Self::Datagram),
            other => Err(Error::InvalidOpCode(other)),
        }
    }
}

/// Payload for a [`Payload::Connect`] variant
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectPayload<'data> {
    /// Number of frames buffered in the receive buffer
    pub rwnd: u32,
    /// The destination port to forward to (client), or the local port (server)
    pub target_port: u16,
    /// The destination host to forward to (client), or the local address (server)
    pub target_host: Cow<'data, [u8]>,
}

/// Payload for a [`Payload::Bind`] variant
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindPayload<'data> {
    /// Type of socket to listen on
    pub bind_type: BindType,
    /// The local port to bind to
    pub target_port: u16,
    /// The local address to bind to
    pub target_host: Cow<'data, [u8]>,
}

/// Payload for a [`Payload::Datagram`] variant
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatagramPayload<'data> {
    /// The port of the forwarding target
    pub target_port: u16,
    /// The host of the forwarding target
    pub target_host: Cow<'data, [u8]>,
    /// The data to send
    pub data: Cow<'data, [u8]>,
}

/// Frame payload
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload<'data> {
    /// `Connect` payload. See [`ConnectPayload`]
    Connect(ConnectPayload<'data>),
    /// `Acknowledge` payload
    /// `psh_recvd_since`: The number of [`Push`] frames received since
    /// the previous [`Acknowledge`] frame, or
    /// `rwnd`: Number of frames buffered in the receive buffer
    Acknowledge(u32),
    /// `Reset` has no payload
    Reset,
    /// `Finish` has no payload
    Finish,
    /// `Push` payload
    Push(Cow<'data, [u8]>),
    /// `Bind` payload. See [`BindPayload`]
    Bind(BindPayload<'data>),
    /// `Datagram` payload. See [`DatagramPayload`]
    Datagram(DatagramPayload<'data>),
}

impl Payload<'_> {
    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Connect(ConnectPayload { target_host, .. }) => {
                size_of::<u32>() + size_of::<u16>() + target_host.len()
            }
            Self::Acknowledge(_) => size_of::<u32>(),
            Self::Reset | Self::Finish => 0,
            Self::Push(data) => data.len(),
            Self::Bind(BindPayload { target_host, .. }) => {
                size_of::<u8>() + size_of::<u16>() + target_host.len()
            }
            Self::Datagram(DatagramPayload {
                target_host, data, ..
            }) => size_of::<u8>() + size_of::<u16>() + target_host.len() + data.len(),
        }
    }
}

impl<'data> From<&Payload<'data>> for OpCode {
    fn from(payload: &Payload<'data>) -> Self {
        match payload {
            Payload::Connect { .. } => Self::Connect,
            Payload::Acknowledge(_) => Self::Acknowledge,
            Payload::Reset => Self::Reset,
            Payload::Finish => Self::Finish,
            Payload::Push(_) => Self::Push,
            Payload::Bind { .. } => Self::Bind,
            Payload::Datagram { .. } => Self::Datagram,
        }
    }
}

/// Copy-on-write Frame
///
/// See PROTOCOL.md for details.
#[derive(Clone, PartialEq, Eq)]
#[repr(C)]
pub struct Frame<'data> {
    /// Flow ID
    pub id: u32,
    /// Payload data
    pub payload: Payload<'data>,
}

impl Debug for Frame<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("opcode", &OpCode::from(&self.payload))
            .field("id", &self.id)
            .field("payload.len", &self.payload.len())
            .finish()
    }
}

impl<'data> Frame<'data> {
    /// Create a new [`OpCode::Connect`] frame.
    ///
    /// # Arguments
    /// * `target_host`: The destination host to forward to (client), or the local address (server).
    /// * `target_port`: The destination port to forward to (client), or the local port (server).
    /// * `id`: A proposed flow ID for this connection.
    /// * `rwnd`: Number of frames buffered in the client receive buffer.
    #[must_use]
    #[inline]
    pub const fn new_connect(
        target_host: &'data [u8],
        target_port: u16,
        id: u32,
        rwnd: u32,
    ) -> Self {
        let payload = Payload::Connect(ConnectPayload {
            rwnd,
            target_port,
            target_host: Cow::Borrowed(target_host),
        });
        Self { id, payload }
    }
    /// Create a new [`OpCode::Acknowledge`] frame.
    ///
    /// # Arguments
    /// * `id`: Flow ID of the acknowledged connection.
    /// * `psh_recvd_since`: The number of `Push` frames received since the
    ///   previous `Acknowldge` frame.
    #[must_use]
    #[inline]
    pub const fn new_acknowledge(id: u32, psh_recvd_since: u32) -> Self {
        let payload = Payload::Acknowledge(psh_recvd_since);
        Self { id, payload }
    }
    /// Create a new [`OpCode::Reset`] frame.
    ///
    /// # Arguments
    /// * `id`: The flow ID of the offending frame.
    #[must_use]
    #[inline]
    pub const fn new_reset(id: u32) -> Self {
        Self {
            id,
            payload: Payload::Reset,
        }
    }
    /// Create a new [`StreamFlag::Finish`] frame.
    ///
    /// # Arguments
    /// * `id`: The flow ID of the connection to shutdown.
    #[must_use]
    #[inline]
    pub const fn new_finish(id: u32) -> Self {
        Self {
            id,
            payload: Payload::Finish,
        }
    }

    /// Create a new [`StreamFlag::Push`] frame.
    ///
    /// # Arguments
    /// * `id`: The flow ID of the connection to send data on.
    /// * `data`: The data to send.
    #[must_use]
    #[inline]
    pub const fn new_push(id: u32, data: &'data [u8]) -> Self {
        Self {
            id,
            payload: Payload::Push(Cow::Borrowed(data)),
        }
    }

    /// Create a new [`StreamFlag::Push`] frame with owned data.
    #[must_use]
    #[inline]
    pub const fn new_push_owned(id: u32, data: Vec<u8>) -> Self {
        Self {
            id,
            payload: Payload::Push(Cow::Owned(data)),
        }
    }

    /// Create a new [`StreamFlag::Bind`] frame.
    ///
    /// # Arguments
    /// * `id`: An identifier for this Bind request.
    /// * `bind_type`: The type of socket this request is for.
    /// * `target_host`: The local address to bind to.
    /// * `target_port`: The port to bind to.
    #[must_use]
    #[inline]
    pub const fn new_bind(
        id: u32,
        bind_type: BindType,
        target_host: &'data [u8],
        target_port: u16,
    ) -> Self {
        let payload = Payload::Bind(BindPayload {
            bind_type,
            target_port,
            target_host: Cow::Borrowed(target_host),
        });
        Self { id, payload }
    }

    /// Create a new datagram frame
    ///
    /// # Arguments
    /// * `id`: An identifier for this datagram frame.
    /// * `target_host`: The host to forward to.
    /// * `target_port`: The port to forward to.
    /// * `data`: The data to send.
    #[must_use]
    #[inline]
    pub const fn new_datagram(
        id: u32,
        target_host: &'data [u8],
        target_port: u16,
        data: &'data [u8],
    ) -> Self {
        let payload = Payload::Datagram(DatagramPayload {
            target_host: Cow::Borrowed(target_host),
            target_port,
            data: Cow::Borrowed(data),
        });
        Self { id, payload }
    }

    /// Create a new datagram frame with owned data
    #[must_use]
    #[inline]
    pub const fn new_datagram_owned(
        id: u32,
        target_host: Vec<u8>,
        target_port: u16,
        data: Vec<u8>,
    ) -> Self {
        let payload = Payload::Datagram(DatagramPayload {
            target_host: Cow::Owned(target_host),
            target_port,
            data: Cow::Owned(data),
        });
        Self { id, payload }
    }

    /// Copy the frame into a [`FinalizedFrame`]
    #[must_use]
    #[inline]
    pub(crate) fn finalize(&self) -> FinalizedFrame {
        FinalizedFrame(Bytes::from(Vec::from(self)))
    }
}

macro_rules! check_remaining {
    ($data:expr, $len:expr) => {
        if $data.remaining() < $len {
            return Err(Error::FrameTooShort);
        }
    };
}

impl TryFrom<Bytes> for Frame<'_> {
    type Error = Error;

    #[inline]
    fn try_from(mut data: Bytes) -> Result<Self, Self::Error> {
        check_remaining!(data, size_of::<u8>() + size_of::<u32>());
        let firstbyte = data.get_u8();
        let ver = firstbyte >> 4;
        if ver != proto_version::PROTOCOL_VERSION_NUMBER {
            return Err(Error::FrameVersion(ver));
        }
        let opcode = OpCode::try_from(firstbyte & 0x0F)?;
        let id = data.get_u32();
        let payload = match opcode {
            OpCode::Connect => {
                check_remaining!(data, size_of::<u32>() + size_of::<u16>());
                let rwnd = data.get_u32();
                let target_port = data.get_u16();
                let target_host = data;
                Payload::Connect(ConnectPayload {
                    rwnd,
                    target_port,
                    target_host: Cow::Owned(target_host.into()),
                })
            }
            OpCode::Acknowledge => {
                check_remaining!(data, size_of::<u32>());
                let psh_recvd_since = data.get_u32();
                Payload::Acknowledge(psh_recvd_since)
            }
            OpCode::Reset => Payload::Reset,
            OpCode::Finish => Payload::Finish,
            OpCode::Push => Payload::Push(Cow::Owned(data.into())),
            OpCode::Bind => {
                check_remaining!(data, size_of::<u8>() + size_of::<u16>());
                let bind_type = BindType::try_from(data.get_u8())?;
                let target_port = data.get_u16();
                Payload::Bind(BindPayload {
                    bind_type,
                    target_port,
                    target_host: Cow::Owned(data.into()),
                })
            }
            OpCode::Datagram => {
                check_remaining!(data, size_of::<u8>() + 6);
                let host_len = usize::from(data.get_u8());
                check_remaining!(data, host_len + 6);
                let target_port = data.get_u16();
                let target_host = data.split_to(host_len);
                Payload::Datagram(DatagramPayload {
                    target_port,
                    target_host: Cow::Owned(target_host.into()),
                    data: Cow::Owned(data.into()),
                })
            }
        };
        Ok(Self { id, payload })
    }
}

impl From<&Frame<'_>> for Vec<u8> {
    /// Encode a [`Frame`] to bytes
    ///
    /// # Panics
    /// Panics when the frame has [`Payload::Datagram`]
    /// but the `target_host` field is longer than 255 octets.
    #[tracing::instrument(level = "trace")]
    #[inline]
    fn from(frame: &Frame<'_>) -> Self {
        let size = size_of::<u8>() + size_of::<u32>() + frame.payload.len();
        let opcode = OpCode::from(&frame.payload) as u8;
        let firstbyte = opcode | (proto_version::PROTOCOL_VERSION_NUMBER << 4);
        let mut encoded = Self::with_capacity(size);
        encoded.put_u8(firstbyte);
        encoded.put_u32(frame.id);
        match &frame.payload {
            Payload::Connect(ConnectPayload {
                rwnd,
                target_port,
                target_host,
            }) => {
                encoded.put_u32(*rwnd);
                encoded.put_u16(*target_port);
                encoded.extend(target_host.as_ref());
            }
            Payload::Acknowledge(psh_recvd_since) => {
                encoded.put_u32(*psh_recvd_since);
            }
            Payload::Reset | Payload::Finish => {}
            Payload::Push(data) => {
                encoded.extend(data.as_ref());
            }
            Payload::Bind(BindPayload {
                bind_type,
                target_port,
                target_host,
            }) => {
                encoded.put_u8(*bind_type as u8);
                encoded.put_u16(*target_port);
                encoded.extend(target_host.as_ref());
            }
            Payload::Datagram(DatagramPayload {
                target_port,
                target_host,
                data,
            }) => {
                let len_u8 =
                    u8::try_from(target_host.len()).expect("Datagram target host too long");
                encoded.put_u8(len_u8);
                encoded.put_u16(*target_port);
                encoded.extend(target_host.as_ref());
                encoded.extend(data.as_ref());
            }
        }
        encoded
    }
}

impl From<&Frame<'_>> for Bytes {
    #[inline]
    fn from(frame: &Frame<'_>) -> Self {
        Bytes::from(Vec::from(frame))
    }
}

/// An owned and finalized frame for single-copy operations
#[derive(Clone, PartialEq, Eq)]
pub struct FinalizedFrame(Bytes);

impl FinalizedFrame {
    pub const FLUSH: Self = Self(Bytes::new());

    /// Check if the frame is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check the opcode of the frame
    #[inline]
    pub fn opcode(&self) -> Result<OpCode, Error> {
        OpCode::try_from(self.0.get(0).ok_or(Error::FrameTooShort)? & 0x0F)
    }
}

impl Debug for FinalizedFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalizedFrame")
            .field("opcode", &self.opcode())
            .field("encoded_len", &self.0.len())
            .finish()
    }
}

impl<'data> From<&Frame<'data>> for FinalizedFrame {
    #[inline]
    fn from(frame: &Frame<'data>) -> Self {
        Self(Vec::from(frame).into())
    }
}

impl TryFrom<FinalizedFrame> for Frame<'_> {
    type Error = Error;
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
    fn test_frames() {
        crate::tests::setup_logging();
        let frame = Frame::new_connect(&[], 5678, 1234, 128);
        assert_eq!(
            frame,
            Frame {
                id: 1234,
                payload: Payload::Connect(ConnectPayload {
                    rwnd: 128,
                    target_port: 5678,
                    target_host: Cow::Borrowed(&[]),
                })
            }
        );
        let bytes = Bytes::try_from(&frame).unwrap();
        let decoded = Frame::try_from(bytes).unwrap();
        assert_eq!(frame, decoded);

        let frame = Frame {
            id: 5678,
            payload: Payload::Datagram(DatagramPayload {
                target_host: Cow::Borrowed(&[1, 2, 3, 4]),
                target_port: 1234,
                data: Cow::Borrowed(&[1, 2, 3, 4]),
            }),
        };
        let bytes = Bytes::try_from(&frame).unwrap();
        let decoded = Frame::try_from(bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    /// These tests are to make sure that the binary representation of the
    /// frames does not change without a protocol version bump.
    #[test]
    fn test_frame_repr() {
        crate::tests::setup_logging();
        let frame = Frame::new_connect(&[0x01, 0x02, 0x03], 5678, 1234, 512);
        let bytes = Vec::try_from(&frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x70, // ver | opcode (u8)
                0x00, 0x00, 0x04, 0xd2, // id (u32)
                0x00, 0x00, 0x02, 0x00, // rwnd (u32)
                0x16, 0x2e, // dest_port (u16)
                0x01, 0x02, 0x03, // host (variable)
            ]
        );

        let frame = Frame::new_acknowledge(5678, 128);
        let bytes = Vec::try_from(&frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x71, // ver | opcode (u8)
                0x00, 0x00, 0x16, 0x2e, // id (u32)
                0x00, 0x00, 0x00, 0x80, // psh_recvd_since (u32)
            ]
        );

        let frame = Frame::new_reset(1291);
        let bytes = Vec::try_from(&frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x72, // ver | opcode (u8)
                0x00, 0x00, 0x05, 0x0b, // id (u32)
            ]
        );

        let frame = Frame::new_finish(21324);
        let bytes = Vec::try_from(&frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x73, // ver | opcode (u8)
                0x00, 0x00, 0x53, 0x4c, // id (u32)
            ]
        );

        let frame = Frame::new_push(123443131, &[1, 2, 3, 4]);
        let bytes = Vec::try_from(&frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x74, // ver | opcode (u8)
                0x07, 0x5b, 0x97, 0xbb, // id (u32)
                0x01, 0x02, 0x03, 0x04, // data (variable)
            ]
        );

        let frame = Frame::new_bind(42132, BindType::Datagram, &[1, 2, 3, 4], 1234);
        let bytes = Vec::try_from(&frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x75, // ver | opcode (u8)
                0x00, 0x00, 0xa4, 0x94, // id (u32)
                0x03, // bind type (u8)
                0x04, 0xd2, // target_port (u16)
                0x01, 0x02, 0x03, 0x04 // target_host (variable)
            ]
        );

        let frame = Frame::new_bind(42134111, BindType::Stream, &[4, 2, 3, 4], 1234);
        let bytes = Vec::try_from(&frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x75, // ver | opcode (u8)
                0x02, 0x82, 0xea, 0x5f, // id (u32)
                0x01, // bind type (u8)
                0x04, 0xd2, // target_port (u16)
                0x04, 0x02, 0x03, 0x04 // target_host (variable)
            ]
        );

        let frame = Frame::new_datagram(2134, &[1, 2, 3, 4], 1234, &[1, 2, 3, 4]);
        let bytes = Vec::try_from(&frame).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x76, // ver | opcode (u8)
                0x00, 0x00, 0x08, 0x56, // id (u32)
                0x04, // host len (u8)
                0x04, 0xd2, // target_port (u16)
                0x01, 0x02, 0x03, 0x04, // target_host (variable)
                0x01, 0x02, 0x03, 0x04 // data (variable)
            ]
        );
    }

    #[test]
    fn test_finalized_frame() {
        const COMMON_OVERHEAD_SIZE: usize = size_of::<u8>() + size_of::<u32>();
        crate::tests::setup_logging();
        let frame = Frame::new_connect(&[0x01, 0x02, 0x03], 5678, 1234, 128);
        let payload_len = frame.payload.len();
        let finalized = frame.finalize();
        assert_eq!(finalized.0.len(), COMMON_OVERHEAD_SIZE + payload_len);
        assert_eq!(finalized.opcode().unwrap(), OpCode::Connect);
        let decoded = Frame::try_from(finalized).unwrap();
        assert_eq!(frame, decoded);

        let frame = Frame::new_datagram(2134, &[1, 2, 3, 4], 1234, &[1, 2, 3, 4]);
        let payload_len = frame.payload.len();
        let finalized = frame.finalize();
        assert_eq!(finalized.0.len(), COMMON_OVERHEAD_SIZE + payload_len);
        assert_eq!(finalized.opcode().unwrap(), OpCode::Datagram);
        let decoded = Frame::try_from(finalized).unwrap();
        assert_eq!(frame, decoded);
    }
}
