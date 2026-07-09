//! Frames.
//! Each frame strictly fits in a `Message`.
//!
//! For more details, see the `PROTOCOL.md` file in the project root.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::proto_version::PROTOCOL_VERSION_NUMBER;
use crate::ws::Message;
use alloc::borrow::Cow;
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::{
    mem::{ManuallyDrop, MaybeUninit, size_of, transmute},
    ptr::copy_nonoverlapping,
};
use thiserror::Error;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

/// Errors that can occur when parsing a frame.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Frame is invalid or incomplete
    #[error("frame is invalid or incomplete")]
    FrameTooShort,
    /// Invalid opcode in a frame
    #[error("invalid protocol version {} or opcode {}", .0 >> 4, .0 & 0x0f)]
    InvalidOpCode(u8),
    /// Other error from `zerocopy`
    #[error("could not parse frame")]
    Zerocopy,
}

/// Operation codes
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    IntoBytes,
    TryFromBytes,
    Unaligned,
    KnownLayout,
    Immutable,
)]
#[repr(u8)]
pub enum OpCode {
    /// Initiating stream connection by the client
    Connect = 0 | PROTOCOL_VERSION_NUMBER << 4,
    /// Confirming data reception or establishing connection
    Acknowledge = 1 | PROTOCOL_VERSION_NUMBER << 4,
    /// Aborting connection or rejecting operation
    Reset = 2 | PROTOCOL_VERSION_NUMBER << 4,
    /// Closing stream connection or completing operation
    Finish = 3 | PROTOCOL_VERSION_NUMBER << 4,
    /// Sending stream data
    Push = 4 | PROTOCOL_VERSION_NUMBER << 4,
    /// Binding a port
    Bind = 5 | PROTOCOL_VERSION_NUMBER << 4,
    /// Sending datagram
    Datagram = 6 | PROTOCOL_VERSION_NUMBER << 4,
}

impl TryFrom<u8> for OpCode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
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

/// Frame header
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Unaligned, KnownLayout, Immutable,
)]
#[repr(C, packed)]
pub struct Header {
    /// Protocol version and operation code
    pub op_code: OpCode,
    /// Flow ID
    pub flow_id: u32,
}

/// `Connect` frame
#[derive(
    Clone, Copy, PartialEq, Eq, IntoBytes, TryFromBytes, Unaligned, KnownLayout, Immutable,
)]
#[repr(C, packed)]
pub struct Connect<D: ?Sized = [u8]> {
    /// Header
    pub header: Header,
    /// Number of frames buffered in the receive buffer
    pub rwnd: u32,
    /// The destination port to forward to (client), or the local port (server)
    pub target_port: u16,
    /// The destination host to forward to (client), or the local address (server)
    pub target_host: ManuallyDrop<D>,
}

impl PartialEq for Connect<[u8]> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Connect<[u8]> {}

impl ToOwned for Connect<[u8]> {
    type Owned = Box<Self>;
    fn to_owned(&self) -> Self::Owned {
        let total_size = self.as_bytes().len();
        let allocated = Box::new_uninit_slice(total_size);
        let target = allocated.as_ptr() as *mut u8;
        unsafe {
            copy_nonoverlapping(self.as_bytes().as_ptr(), target, total_size);
            transmute::<Box<[MaybeUninit<u8>]>, Box<Self>>(allocated)
        }
    }
}

impl Debug for Connect<[u8]> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let rwnd = self.rwnd;
        let target_port = self.target_port;
        f.debug_struct("Connect")
            .field("header", &self.header)
            .field("rwnd", &rwnd)
            .field("target_port", &target_port)
            .field("target_host", &String::from_utf8_lossy(&self.target_host))
            .finish()
    }
}

impl Connect<[u8]> {
    #[must_use]
    #[inline]
    pub fn new(target_host: &[u8], target_port: u16, id: u32, rwnd: u32) -> Box<Self> {
        let target_host_len = target_host.len();
        let allocated = Box::new_uninit_slice(
            size_of::<Header>() + size_of::<u32>() + size_of::<u16>() + target_host_len,
        );
        let mut frame = unsafe { transmute::<Box<[MaybeUninit<u8>]>, Box<Self>>(allocated) };
        frame.header = Header {
            op_code: OpCode::Connect,
            flow_id: id,
        };
        frame.rwnd = rwnd;
        frame.target_port = target_port;
        let target_host_ptr = frame.target_host.as_mut_ptr();
        unsafe {
            copy_nonoverlapping(target_host.as_ptr(), target_host_ptr, target_host_len);
        }
        frame
    }
}

/// `Acknowledge` frame
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Unaligned, KnownLayout, Immutable,
)]
#[repr(C, packed)]
pub struct Acknowledge(
    /// Header
    Header,
    /// `Acknowledge` payload
    /// `psh_recvd_since`: The number of [`Push`] frames received since
    /// the previous [`Acknowledge`] frame, or
    /// `rwnd`: Number of frames buffered in the receive buffer)
    u32,
);

impl Acknowledge {
    #[must_use]
    #[inline]
    pub const fn new(id: u32, psh_recvd_since: u32) -> Self {
        Self(
            Header {
                op_code: OpCode::Acknowledge,
                flow_id: id,
            },
            psh_recvd_since,
        )
    }
}

/// `Reset` frame
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Unaligned, KnownLayout, Immutable,
)]
#[repr(C, packed)]
pub struct Reset(Header);

impl Reset {
    #[must_use]
    #[inline]
    pub const fn new(id: u32) -> Self {
        Self(Header {
            op_code: OpCode::Reset,
            flow_id: id,
        })
    }
}

/// `Finish` frame
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, Unaligned, KnownLayout, Immutable,
)]
#[repr(C, packed)]
pub struct Finish(Header);

impl Finish {
    #[must_use]
    #[inline]
    pub const fn new(id: u32) -> Self {
        Self(Header {
            op_code: OpCode::Finish,
            flow_id: id,
        })
    }
}

/// `Push` frame
#[derive(
    Clone, Copy, PartialEq, Eq, IntoBytes, TryFromBytes, Unaligned, KnownLayout, Immutable,
)]
#[repr(C, packed)]
pub struct Push<D: ?Sized = [u8]> {
    /// Header
    pub header: Header,
    /// `Push` payload
    pub payload: ManuallyDrop<D>,
}

impl PartialEq for Push<[u8]> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Push<[u8]> {}

impl ToOwned for Push<[u8]> {
    type Owned = Box<Self>;
    fn to_owned(&self) -> Self::Owned {
        let total_size = self.as_bytes().len();
        let allocated = Box::new_uninit_slice(total_size);
        let target = allocated.as_ptr() as *mut u8;
        unsafe {
            copy_nonoverlapping(self.as_bytes().as_ptr(), target, total_size);
            transmute::<Box<[MaybeUninit<u8>]>, Box<Self>>(allocated)
        }
    }
}

impl Debug for Push<[u8]> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Push")
            .field("header", &self.header)
            .field("payload.len", &self.payload.len())
            .finish()
    }
}

impl Push<[u8]> {
    #[must_use]
    #[inline]
    pub fn new(id: u32, payload: &[u8]) -> Box<Self> {
        let payload_len = payload.len();
        let allocated = Box::new_uninit_slice(size_of::<Header>() + payload_len);
        let mut frame = unsafe { transmute::<Box<[MaybeUninit<u8>]>, Box<Self>>(allocated) };
        frame.header = Header {
            op_code: OpCode::Push,
            flow_id: id,
        };
        let payload_ptr = frame.payload.as_mut_ptr();
        unsafe {
            copy_nonoverlapping(payload.as_ptr(), payload_ptr, payload_len);
        }
        frame
    }
}

/// Type codes for a `Bind` operation
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    IntoBytes,
    TryFromBytes,
    Unaligned,
    KnownLayout,
    Immutable,
)]
#[repr(u8)]
pub enum BindType {
    /// Stream binding
    Stream = 1,
    /// Datagram binding
    Datagram = 3,
}

/// `Bind` frame
#[derive(
    Clone, Copy, PartialEq, Eq, IntoBytes, TryFromBytes, Unaligned, KnownLayout, Immutable,
)]
#[repr(C, packed)]
pub struct Bind<D: ?Sized = [u8]> {
    /// Header
    pub header: Header,
    /// Type of socket to listen on
    pub bind_type: BindType,
    /// The local port to bind to
    pub target_port: u16,
    /// The local address to bind to
    pub target_host: ManuallyDrop<D>,
}

impl PartialEq for Bind<[u8]> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Bind<[u8]> {}

impl ToOwned for Bind<[u8]> {
    type Owned = Box<Self>;
    fn to_owned(&self) -> Self::Owned {
        let total_size = self.as_bytes().len();
        let allocated = Box::new_uninit_slice(total_size);
        let target = allocated.as_ptr() as *mut u8;
        unsafe {
            copy_nonoverlapping(self.as_bytes().as_ptr(), target, total_size);
            transmute::<Box<[MaybeUninit<u8>]>, Box<Self>>(allocated)
        }
    }
}

impl Debug for Bind<[u8]> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bind_type = self.bind_type;
        let target_port = self.target_port;
        f.debug_struct("Bind")
            .field("header", &self.header)
            .field("bind_type", &bind_type)
            .field("target_port", &target_port)
            .field("target_host", &String::from_utf8_lossy(&self.target_host))
            .finish()
    }
}

impl Bind<[u8]> {
    #[must_use]
    #[inline]
    pub fn new(bind_type: BindType, target_host: &[u8], target_port: u16, id: u32) -> Box<Self> {
        let target_host_len = target_host.len();
        let allocated = Box::new_uninit_slice(
            size_of::<Header>() + size_of::<BindType>() + size_of::<u16>() + target_host_len,
        );
        let mut frame = unsafe { transmute::<Box<[MaybeUninit<u8>]>, Box<Self>>(allocated) };
        frame.header = Header {
            op_code: OpCode::Bind,
            flow_id: id,
        };
        frame.bind_type = bind_type;
        frame.target_port = target_port;
        let target_host_ptr = frame.target_host.as_mut_ptr();
        unsafe {
            copy_nonoverlapping(target_host.as_ptr(), target_host_ptr, target_host_len);
        }
        frame
    }
}

/// `Datagram` frame
#[derive(
    Clone, Copy, PartialEq, Eq, IntoBytes, TryFromBytes, Unaligned, KnownLayout, Immutable,
)]
#[repr(C, packed)]
pub struct Datagram<D: ?Sized = [u8]> {
    /// Header
    pub header: Header,
    /// The length of the target host
    pub target_host_len: u8,
    /// The port of the forwarding target
    pub target_port: u16,
    /// The host of the forwarding target and the data to send
    pub target_host_and_payload: ManuallyDrop<D>,
}

impl PartialEq for Datagram<[u8]> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Datagram<[u8]> {}

impl ToOwned for Datagram<[u8]> {
    type Owned = Box<Self>;
    fn to_owned(&self) -> Self::Owned {
        let total_size = self.as_bytes().len();
        let allocated = Box::new_uninit_slice(total_size);
        let target = allocated.as_ptr() as *mut u8;
        unsafe {
            copy_nonoverlapping(self.as_bytes().as_ptr(), target, total_size);
            transmute::<Box<[MaybeUninit<u8>]>, Box<Self>>(allocated)
        }
    }
}

impl Debug for Datagram<[u8]> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let target_host_len = self.target_host_len as usize;
        let target_port = self.target_port;
        let target_host = &self.target_host_and_payload[..target_host_len];
        let payload_len = self.target_host_and_payload.len() - target_host_len;
        f.debug_struct("Datagram")
            .field("header", &self.header)
            .field("target_host", &String::from_utf8_lossy(target_host))
            .field("target_port", &target_port)
            .field("payload.len", &payload_len)
            .finish()
    }
}

impl Datagram<[u8]> {
    #[must_use]
    #[inline]
    pub fn new(id: u32, target_host: &[u8], target_port: u16, data: &[u8]) -> Box<Self> {
        let target_host_len = target_host.len();
        let data_len = data.len();
        let allocated = Box::new_uninit_slice(
            size_of::<Header>() + size_of::<u8>() + size_of::<u16>() + target_host_len + data_len,
        );
        let mut frame = unsafe { transmute::<Box<[MaybeUninit<u8>]>, Box<Self>>(allocated) };
        frame.header = Header {
            op_code: OpCode::Datagram,
            flow_id: id,
        };
        let len_u8 = u8::try_from(target_host.len()).expect("Datagram target host too long");
        frame.target_host_len = len_u8;
        frame.target_port = target_port;
        let target_host_and_payload_ptr = frame.target_host_and_payload.as_mut_ptr();
        unsafe {
            copy_nonoverlapping(
                target_host.as_ptr(),
                target_host_and_payload_ptr,
                target_host_len,
            );
            copy_nonoverlapping(
                data.as_ptr(),
                target_host_and_payload_ptr.add(target_host_len),
                data_len,
            );
        }
        frame
    }
}

/// A frame
#[derive(Debug, PartialEq, Eq)]
#[expect(private_interfaces)]
pub enum Frame<'a> {
    /// `Connect` frame
    Connect(Cow<'a, Connect<[u8]>>),
    /// `Acknowledge` frame
    Acknowledge(Acknowledge),
    /// `Reset` frame
    Reset(Reset),
    /// `Finish` frame
    Finish(Finish),
    /// `Push` frame
    Push(Cow<'a, Push<[u8]>>),
    /// `Bind` frame
    Bind(Cow<'a, Bind<[u8]>>),
    /// `Datagram` frame
    Datagram(Cow<'a, Datagram<[u8]>>),
}

impl AsRef<[u8]> for Frame<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Connect(frame) => frame.as_bytes(),
            Self::Acknowledge(frame) => frame.as_bytes(),
            Self::Reset(frame) => frame.as_bytes(),
            Self::Finish(frame) => frame.as_bytes(),
            Self::Push(frame) => frame.as_bytes(),
            Self::Bind(frame) => frame.as_bytes(),
            Self::Datagram(frame) => frame.as_bytes(),
        }
    }
}

impl From<&Frame<'_>> for Vec<u8> {
    fn from(frame: &Frame<'_>) -> Self {
        frame.as_ref().to_vec()
    }
}

impl<'a> TryFrom<&'a [u8]> for Frame<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let first_byte = value.get(0).ok_or(Error::FrameTooShort)?;
        let opcode =
            OpCode::try_from(*first_byte).map_err(|_| Error::InvalidOpCode(*first_byte))?;
        let frame = match opcode {
            OpCode::Connect => Self::Connect(Cow::Borrowed(
                Connect::try_ref_from_bytes(value).map_err(|_| Error::Zerocopy)?,
            )),
            OpCode::Acknowledge => Self::Acknowledge(
                *Acknowledge::try_ref_from_bytes(value).map_err(|_| Error::Zerocopy)?,
            ),
            OpCode::Reset => {
                Self::Reset(*Reset::try_ref_from_bytes(value).map_err(|_| Error::Zerocopy)?)
            }
            OpCode::Finish => {
                Self::Finish(*Finish::try_ref_from_bytes(value).map_err(|_| Error::Zerocopy)?)
            }
            OpCode::Push => Self::Push(Cow::Borrowed(
                Push::try_ref_from_bytes(value).map_err(|_| Error::Zerocopy)?,
            )),
            OpCode::Bind => Self::Bind(Cow::Borrowed(
                Bind::try_ref_from_bytes(value).map_err(|_| Error::Zerocopy)?,
            )),
            OpCode::Datagram => Self::Datagram(Cow::Borrowed(
                Datagram::try_ref_from_bytes(value).map_err(|_| Error::Zerocopy)?,
            )),
        };
        Ok(frame)
    }
}

impl From<Frame<'_>> for Message {
    fn from(frame: Frame<'_>) -> Self {
        let bytes = Vec::from(&frame);
        Message::Binary(bytes::Bytes::from(bytes))
    }
}

impl Frame<'static> {
    /// Create a new [`OpCode::Connect`] frame.
    ///
    /// # Arguments
    /// * `target_host`: The destination host to forward to (client), or the local address (server).
    /// * `target_port`: The destination port to forward to (client), or the local port (server).
    /// * `id`: A proposed flow ID for this connection.
    /// * `rwnd`: Number of frames buffered in the client receive buffer.
    #[must_use]
    #[inline]
    pub fn new_connect(target_host: &[u8], target_port: u16, id: u32, rwnd: u32) -> Self {
        Self::Connect(Cow::Owned(Connect::new(target_host, target_port, id, rwnd)))
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
        Self::Acknowledge(Acknowledge::new(id, psh_recvd_since))
    }

    /// Create a new [`OpCode::Reset`] frame.
    ///
    /// # Arguments
    /// * `id`: The flow ID of the offending frame.
    #[must_use]
    #[inline]
    pub const fn new_reset(id: u32) -> Self {
        Self::Reset(Reset::new(id))
    }
    /// Create a new [`OpCode::Finish`] frame.
    ///
    /// # Arguments
    /// * `id`: The flow ID of the connection to shutdown.
    #[must_use]
    #[inline]
    pub const fn new_finish(id: u32) -> Self {
        Self::Finish(Finish::new(id))
    }

    /// Create a new [`OpCode::Push`] frame.
    ///
    /// # Arguments
    /// * `id`: The flow ID of the connection to send data on.
    /// * `data`: The data to send.
    #[must_use]
    #[inline]
    pub fn new_push(id: u32, data: &[u8]) -> Self {
        Self::Push(Cow::Owned(Push::new(id, data)))
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
    pub fn new_bind(id: u32, bind_type: BindType, target_host: &[u8], target_port: u16) -> Self {
        Self::Bind(Cow::Owned(Bind::new(
            bind_type,
            target_host,
            target_port,
            id,
        )))
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
    pub fn new_datagram(id: u32, target_host: &[u8], target_port: u16, data: &[u8]) -> Self {
        Self::Datagram(Cow::Owned(Datagram::new(
            id,
            target_host,
            target_port,
            data,
        )))
    }

    /// Append data to a `Push` frame after it has been encoded to bytes.
    ///
    /// # Panics
    /// Panics if the frame is not a valid frame, or if the `OpCode` is not `Push`.
    #[inline]
    pub fn append_push_data(&mut self, data: &[u8]) {
        let Frame::Push(Cow::Owned(frame)) = self else {
            panic!("`append_push_data` can only be called on an owned `Push` frame");
        };
        let frame_bytes = frame.as_mut().as_bytes();
        let frame_ptr = frame_bytes.as_ptr() as *mut u8;
        let mut old_data =
            unsafe { Vec::from_raw_parts(frame_ptr, frame_bytes.len(), frame_bytes.len()) };
        old_data.extend_from_slice(data);
        todo!();
    }

    /// Get the `OpCode` of the frame.
    #[inline]
    #[must_use]
    pub fn opcode(&self) -> OpCode {
        match self {
            Self::Connect(_) => OpCode::Connect,
            Self::Acknowledge(_) => OpCode::Acknowledge,
            Self::Reset(_) => OpCode::Reset,
            Self::Finish(_) => OpCode::Finish,
            Self::Push(_) => OpCode::Push,
            Self::Bind(_) => OpCode::Bind,
            Self::Datagram(_) => OpCode::Datagram,
        }
    }

    /// Get the flow ID of the frame.
    #[inline]
    #[must_use]
    pub fn flow_id(&self) -> u32 {
        match self {
            Self::Connect(frame) => frame.header.flow_id,
            Self::Acknowledge(frame) => frame.0.flow_id,
            Self::Reset(frame) => frame.0.flow_id,
            Self::Finish(frame) => frame.0.flow_id,
            Self::Push(frame) => frame.header.flow_id,
            Self::Bind(frame) => frame.header.flow_id,
            Self::Datagram(frame) => frame.header.flow_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

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
        let frame_back = Frame::try_from(&*bytes).unwrap();
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
        let frame_back = Frame::try_from(&*bytes).unwrap();
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
        let frame_back = Frame::try_from(&*bytes).unwrap();
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
        let frame_back = Frame::try_from(&*bytes).unwrap();
        assert_eq!(frame, frame_back);
    }

    #[test]
    fn test_frame_repr_push() {
        crate::tests::setup_logging();
        let frame = Frame::new_push(0x125b_97bb, &[1, 2, 3, 4]);
        let bytes = Vec::from(&frame);
        assert_eq!(
            bytes,
            vec![
                0x74, // ver | opcode (u8)
                0x12, 0x5b, 0x97, 0xbb, // id (u32)
                0x01, 0x02, 0x03, 0x04, // data (variable)
            ]
        );
        let frame_back = Frame::try_from(&*bytes).unwrap();
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
        let frame_back = Frame::try_from(&*bytes).unwrap();
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
        let frame_back = Frame::try_from(&*bytes).unwrap();
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
        let frame_back = Frame::try_from(&*bytes).unwrap();
        assert_eq!(frame, frame_back);
    }

    #[test]
    fn test_push_frame_append() {
        crate::tests::setup_logging();
        let mut frame = Frame::new_push(0x75b_97bb, &[1, 2, 3, 4]);
        append_push_data(&mut frame, &[5, 6, 7, 8]);
        assert_eq!(
            frame,
            Frame::new_push(0x75b_97bb, &[1, 2, 3, 4, 5, 6, 7, 8])
        );
        assert_eq!(
            frame.as_bytes(),
            vec![
                0x74, // ver | opcode (u8)
                0x07, 0x5b, 0x97, 0xbb, // id (u32)
                0x01, 0x02, 0x03, 0x04, // data (variable)
                0x05, 0x06, 0x07, 0x08 // appended data
            ]
        );
    }

    #[test]
    fn test_frame_debug_not_too_long() {
        crate::tests::setup_logging();
        let data = vec![0; 256];
        let frame = Frame::new_push(0x75b_97bb, &data);
        let debug_str = alloc::format!("{frame:?}");
        assert!(debug_str.len() < 64);
        assert!(debug_str.contains("opcode: Push"));
        assert!(debug_str.contains("id: 075b97bb"));
        assert!(debug_str.contains("payload.len: 256"));
    }
}
