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

use crate::{Dupe, proto_version};
use bytes::{Buf, BufMut, Bytes};
use std::{fmt::Debug, mem::size_of};
use thiserror::Error;

/// Errors that can occur when parsing a frame.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Frame is invalid or incomplete
    #[error("Frame is invalid or incomplete")]
    FrameTooShort,
    /// Unsupported frame version decoded
    #[error("Unsupported frame version: {0}")]
    FrameVersion(u8),
    /// Invalid opcode in a frame
    #[error("Invalid opcode: {0}")]
    InvalidOpCode(u8),
    /// Invalid type code in a `Bind` frame
    #[error("Invalid `Bind` type: {0}")]
    InvalidBindType(u8),
}

/// A special version of `std::borrow::Cow` using `Bytes`
#[derive(Clone, Debug)]
pub(crate) enum CowBytes<'data> {
    Borrowed(&'data [u8]),
    Owned(Bytes),
}

impl PartialEq for CowBytes<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for CowBytes<'_> {}

impl Dupe for CowBytes<'_> {
    #[inline]
    fn dupe(&self) -> Self {
        match self {
            Self::Borrowed(data) => Self::Borrowed(data),
            Self::Owned(bytes) => Self::Owned(bytes.dupe()),
        }
    }
}

impl AsRef<[u8]> for CowBytes<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(data) => data,
            Self::Owned(bytes) => bytes.as_ref(),
        }
    }
}

impl Default for CowBytes<'_> {
    #[inline]
    fn default() -> Self {
        Self::Borrowed(&[])
    }
}

impl CowBytes<'_> {
    #[inline]
    pub fn into_owned(self) -> Bytes {
        match self {
            Self::Borrowed(data) => Bytes::from(data.to_vec()),
            Self::Owned(bytes) => bytes,
        }
    }

    #[inline]
    pub const fn len(&self) -> usize {
        match self {
            Self::Borrowed(data) => data.len(),
            Self::Owned(bytes) => bytes.len(),
        }
    }
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
    /// Closing stream connection or completing operation
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
pub(crate) struct ConnectPayload<'data> {
    /// Number of frames buffered in the receive buffer
    pub rwnd: u32,
    /// The destination port to forward to (client), or the local port (server)
    pub target_port: u16,
    /// The destination host to forward to (client), or the local address (server)
    pub target_host: CowBytes<'data>,
}

/// Payload for a [`Payload::Bind`] variant
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BindPayload<'data> {
    /// Type of socket to listen on
    pub bind_type: BindType,
    /// The local port to bind to
    pub target_port: u16,
    /// The local address to bind to
    pub target_host: CowBytes<'data>,
}

/// Payload for a [`Payload::Datagram`] variant
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DatagramPayload<'data> {
    /// The port of the forwarding target
    pub target_port: u16,
    /// The host of the forwarding target
    pub target_host: CowBytes<'data>,
    /// The data to send
    pub data: CowBytes<'data>,
}

/// Frame payload
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Payload<'data> {
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
    Push(CowBytes<'data>),
    /// `Bind` payload. See [`BindPayload`]
    Bind(BindPayload<'data>),
    /// `Datagram` payload. See [`DatagramPayload`]
    Datagram(DatagramPayload<'data>),
}

impl Payload<'_> {
    #[inline]
    const fn len(&self) -> usize {
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
    #[inline]
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
pub struct Frame<'data> {
    /// Flow ID
    pub id: u32,
    /// Payload data
    pub(crate) payload: Payload<'data>,
}

impl Debug for Frame<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("opcode", &OpCode::from(&self.payload))
            .field("id", &format_args!("{:08x}", self.id))
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
            target_host: CowBytes::Borrowed(target_host),
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
    /// Create a new [`OpCode::Finish`] frame.
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

    /// Create a new [`OpCode::Push`] frame.
    ///
    /// # Arguments
    /// * `id`: The flow ID of the connection to send data on.
    /// * `data`: The data to send.
    #[must_use]
    #[inline]
    pub const fn new_push(id: u32, data: &'data [u8]) -> Self {
        Self {
            id,
            payload: Payload::Push(CowBytes::Borrowed(data)),
        }
    }

    /// Create a new [`OpCode::Push`] frame with owned data.
    #[must_use]
    #[inline]
    pub const fn new_push_owned(id: u32, data: Bytes) -> Self {
        Self {
            id,
            payload: Payload::Push(CowBytes::Owned(data)),
        }
    }

    /// Create a new [`OpCode::Bind`] frame.
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
            target_host: CowBytes::Borrowed(target_host),
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
            target_host: CowBytes::Borrowed(target_host),
            target_port,
            data: CowBytes::Borrowed(data),
        });
        Self { id, payload }
    }

    /// Create a new datagram frame with owned data
    #[must_use]
    #[inline]
    pub const fn new_datagram_owned(
        id: u32,
        target_host: Bytes,
        target_port: u16,
        data: Bytes,
    ) -> Self {
        let payload = Payload::Datagram(DatagramPayload {
            target_host: CowBytes::Owned(target_host),
            target_port,
            data: CowBytes::Owned(data),
        });
        Self { id, payload }
    }

    /// Copy the frame into a [`FinalizedFrame`]
    #[must_use]
    #[inline]
    pub(crate) fn finalize(&self) -> FinalizedFrame {
        FinalizedFrame(Bytes::from(self))
    }
}

macro_rules! check_remaining {
    ($data:expr, $len:expr) => {
        let remaining = $data.remaining();
        if remaining < $len {
            // Make sure we catch any mistakes during debug but prevent
            // incorrect peers from crashing the server in production
            #[cfg(not(fuzzing))]
            debug_assert!(
                false,
                "`FrameTooShort` at {}:{}, have {}/{}",
                file!(),
                line!(),
                remaining,
                $len
            );
            return Err(Error::FrameTooShort);
        }
    };
}

impl TryFrom<Bytes> for Frame<'static> {
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
                    target_host: CowBytes::Owned(target_host),
                })
            }
            OpCode::Acknowledge => {
                check_remaining!(data, size_of::<u32>());
                let psh_recvd_since = data.get_u32();
                Payload::Acknowledge(psh_recvd_since)
            }
            OpCode::Reset => Payload::Reset,
            OpCode::Finish => Payload::Finish,
            OpCode::Push => Payload::Push(CowBytes::Owned(data)),
            OpCode::Bind => {
                check_remaining!(data, size_of::<u8>() + size_of::<u16>());
                let bind_type = BindType::try_from(data.get_u8())?;
                let target_port = data.get_u16();
                Payload::Bind(BindPayload {
                    bind_type,
                    target_port,
                    target_host: CowBytes::Owned(data),
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
                    target_host: CowBytes::Owned(target_host),
                    data: CowBytes::Owned(data),
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
    /// Panics when the frame has [`OpCode::Datagram`]
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
        // Make sure our estimated size is correct
        // so that no extra allocations are made
        debug_assert_eq!(size, encoded.len());
        encoded
    }
}

impl From<&Frame<'_>> for Bytes {
    #[inline]
    fn from(frame: &Frame<'_>) -> Self {
        Self::from(Vec::from(frame))
    }
}

/// An owned and finalized frame for single-copy operations
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FinalizedFrame(Bytes);

impl FinalizedFrame {
    /// Check the opcode of the frame
    #[inline]
    pub fn opcode(&self) -> Result<OpCode, Error> {
        let firstbyte = self.0.first().ok_or({
            // This is used in `impl Debug` so let's allow empty frames
            Error::FrameTooShort
        })?;
        let raw_opcode = firstbyte & 0x0F;
        OpCode::try_from(raw_opcode)
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
        Self(Bytes::from(frame))
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
    #[inline]
    fn from(bytes: Bytes) -> Self {
        Self(bytes)
    }
}

impl From<FinalizedFrame> for Bytes {
    #[inline]
    fn from(frame: FinalizedFrame) -> Self {
        frame.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cow_bytes() {
        crate::tests::setup_logging();
        let cow1 = CowBytes::Borrowed(&[1, 2, 3]);
        let cow2 = cow1.dupe();
        assert_eq!(cow1, cow2);
        assert_eq!(cow1.len(), 3);
        assert_eq!(cow2.len(), 3);
        let cow3 = cow1.into_owned();
        assert_eq!(cow3.as_ref(), cow2.as_ref());
        let bytes = Bytes::from(vec![4, 5, 6]);
        let cow4 = CowBytes::Owned(bytes.clone());
        assert_eq!(cow4.as_ref(), bytes.as_ref());
        assert_eq!(cow4.len(), 3);
    }

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
                    target_host: CowBytes::default(),
                })
            }
        );
        let bytes = Bytes::from(&frame);
        let decoded = Frame::try_from(bytes).unwrap();
        assert_eq!(frame, decoded);

        let frame = Frame {
            id: 5678,
            payload: Payload::Datagram(DatagramPayload {
                target_host: CowBytes::Borrowed(&[1, 2, 3, 4]),
                target_port: 1234,
                data: CowBytes::Borrowed(&[1, 2, 3, 4]),
            }),
        };
        let bytes = Bytes::from(&frame);
        let decoded = Frame::try_from(bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    // These tests are to make sure that the binary representation of the
    // frames does not change without a protocol version bump.
    #[test]
    fn test_frame_repr_connect() {
        crate::tests::setup_logging();
        let frame = Frame::new_connect(&[0x01, 0x02, 0x03], 5678, 1234, 512);
        let bytes = Vec::from(&frame);
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
        let frame_back = Frame::try_from(Bytes::from(bytes)).unwrap();
        assert_eq!(frame, frame_back);
    }

    #[test]
    fn test_frame_repr_acknowledge() {
        crate::tests::setup_logging();
        let frame = Frame::new_acknowledge(5678, 128);
        let bytes = Vec::from(&frame);
        assert_eq!(
            bytes,
            vec![
                0x71, // ver | opcode (u8)
                0x00, 0x00, 0x16, 0x2e, // id (u32)
                0x00, 0x00, 0x00, 0x80, // psh_recvd_since (u32)
            ]
        );
        let frame_back = Frame::try_from(Bytes::from(bytes)).unwrap();
        assert_eq!(frame, frame_back);
    }

    #[test]
    fn test_frame_repr_reset() {
        crate::tests::setup_logging();
        let frame = Frame::new_reset(1291);
        let bytes = Vec::from(&frame);
        assert_eq!(
            bytes,
            vec![
                0x72, // ver | opcode (u8)
                0x00, 0x00, 0x05, 0x0b, // id (u32)
            ]
        );
        let frame_back = Frame::try_from(Bytes::from(bytes)).unwrap();
        assert_eq!(frame, frame_back);
    }

    #[test]
    fn test_frame_repr_finish() {
        crate::tests::setup_logging();
        let frame = Frame::new_finish(0x534c);
        let bytes = Vec::from(&frame);
        assert_eq!(
            bytes,
            vec![
                0x73, // ver | opcode (u8)
                0x00, 0x00, 0x53, 0x4c, // id (u32)
            ]
        );
        let frame_back = Frame::try_from(Bytes::from(bytes)).unwrap();
        assert_eq!(frame, frame_back);
    }

    #[test]
    fn test_frame_repr_push() {
        crate::tests::setup_logging();
        let frame = Frame::new_push(0x75b_97bb, &[1, 2, 3, 4]);
        let bytes = Vec::from(&frame);
        assert_eq!(
            bytes,
            vec![
                0x74, // ver | opcode (u8)
                0x07, 0x5b, 0x97, 0xbb, // id (u32)
                0x01, 0x02, 0x03, 0x04, // data (variable)
            ]
        );
        let frame_back = Frame::try_from(Bytes::from(bytes)).unwrap();
        assert_eq!(frame, frame_back);
    }

    #[test]
    fn test_frame_repr_bind() {
        crate::tests::setup_logging();
        let frame = Frame::new_bind(42132, BindType::Datagram, &[1, 2, 3, 4], 1234);
        let bytes = Vec::from(&frame);
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
        let frame_back = Frame::try_from(Bytes::from(bytes)).unwrap();
        assert_eq!(frame, frame_back);

        let frame = Frame::new_bind(0x282_ea5f, BindType::Stream, &[4, 2, 3, 4], 1234);
        let bytes = Vec::from(&frame);
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
        let frame_back = Frame::try_from(Bytes::from(bytes)).unwrap();
        assert_eq!(frame, frame_back);
    }

    #[test]
    fn test_frame_repr_datagram() {
        crate::tests::setup_logging();
        let frame = Frame::new_datagram(2134, &[1, 2, 3, 4], 1234, &[1, 2, 3, 4]);
        let bytes = Vec::from(&frame);
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
        let frame_back = Frame::try_from(Bytes::from(bytes)).unwrap();
        assert_eq!(frame, frame_back);
    }

    #[test]
    #[should_panic(expected = "Datagram target host too long")]
    fn test_finalized_frame_too_long() {
        crate::tests::setup_logging();
        let long_hostname = vec![0; 256];
        let frame = Frame::new_datagram(2134, &long_hostname, 1234, &[1, 2, 3, 4]);
        let _ = frame.finalize();
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
