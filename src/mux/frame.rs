//! Frames.
//! Each frame strictly fits in a `Message`.
//!
//! Architecture:
//! The system is similar to a traditional SOCKS5 proxy, but the protocol
//! allows for UDP to be transmitted over the same `WebSocket` connection.
//! It is essentially a SOCKS5 forwarder over a `WebSocket`.
//!
//! All `Message`s carry a frame:
//! - 1 byte: type (1 for TCP, 3 for UDP)
//! - variable: dependent on the type (see `StreamFrame` and `DatagramFrame`).
//!
//! `Stream` messages are connection-based. The handshake is simpler than a
//! TCP handshake: the client sends a `Syn` frame, then the server replies an
//! `Ack`. To reduce overhead, in `Syn`, the `dport` is 0, and the server
//! replies with a usable port in the `sport` of the `Ack` frame. The client
//! asks for a target to `connect` in the `Syn` payload:
//! - variable: 1 + (0..256) bytes: length + (domain name or IP)
//! - 2 bytes: port in network byte order
//!
//! `Datagram` messages are connectionless. On the client side,
//! each forwarder client (i.e. (port, host) tuple) is assigned a unique
//! Source ID, and the frame also carries its intended target.
//! When the server receives datagrams from that target, it will
//! send them back to the client with the same Source ID.

use bytes::{Buf, Bytes};
use std::{fmt::Debug, num::TryFromIntError};
use thiserror::Error;
use tracing::warn;
use tungstenite::Message;

/// Conversion errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid frame type: {0}")]
    InvalidFrameType(u8),
    #[error("invalid stream flag: {0}")]
    InvalidStreamFlag(u8),
    #[error("host longer than 255 octets")]
    HostLength(#[from] TryFromIntError),
}

/// Stream frame flags
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
#[non_exhaustive]
pub enum StreamFlag {
    /// New connection
    Syn = 0,
    /// Confirm connection
    Ack = 2,
    /// When `dport` is not open
    Rst = 3,
    /// Close connection
    Fin = 4,
    /// Data
    Psh = 5,
}

/// Stream frame
#[derive(Clone, PartialEq, Eq)]
#[repr(C)]
pub struct StreamFrame {
    pub sport: u16,
    pub dport: u16,
    pub flag: StreamFlag,
    pub data: Vec<u8>,
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
    /// Create a new `Syn` frame.
    #[must_use]
    pub fn new_syn(dest_host: &[u8], dest_port: u16, sport: u16) -> Result<Self, Error> {
        let host_len = dest_host.len();
        let mut syn_payload =
            Vec::with_capacity(std::mem::size_of::<u8>() + std::mem::size_of::<u16>() + host_len);
        syn_payload.push(u8::try_from(host_len)?);
        syn_payload.extend_from_slice(dest_host);
        syn_payload.extend_from_slice(&dest_port.to_be_bytes());
        Ok(Self {
            sport,
            dport: 0,
            flag: StreamFlag::Syn,
            data: syn_payload,
        })
    }
    /// Create a new `Ack` frame.
    #[must_use]
    pub const fn new_ack(sport: u16, dport: u16) -> Self {
        Self {
            sport,
            dport,
            flag: StreamFlag::Ack,
            data: vec![],
        }
    }
    /// Create a new `Rst` frame.
    #[must_use]
    pub const fn new_rst(sport: u16, dport: u16) -> Self {
        Self {
            sport,
            dport,
            flag: StreamFlag::Rst,
            data: vec![],
        }
    }
    /// Create a new `Fin` frame.
    #[must_use]
    pub const fn new_fin(sport: u16, dport: u16) -> Self {
        Self {
            sport,
            dport,
            flag: StreamFlag::Fin,
            data: vec![],
        }
    }
    /// Create a new `Psh` frame.
    #[must_use]
    pub const fn new_psh(sport: u16, dport: u16, data: Vec<u8>) -> Self {
        Self {
            sport,
            dport,
            flag: StreamFlag::Psh,
            data,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
#[repr(C)]
pub struct DatagramFrame {
    /// Host of the other end
    /// host of the "remote" if sent from client;
    /// host of the "from" if sent from server.
    pub host: Vec<u8>,
    pub port: u16,
    /// Source ID
    pub sid: u32,
    /// Payload
    pub data: Vec<u8>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub enum Frame {
    /// Stream frame, encoded with Type=0x01
    Stream(StreamFrame),
    /// Datagram frame, encoded with Type=0x03
    Datagram(DatagramFrame),
}

impl TryFrom<Frame> for Vec<u8> {
    type Error = Error;

    /// Convert a `Frame` to bytes. Gives an error when
    /// `DatagramFrame::host` is longer than 255 octets.
    #[tracing::instrument(level = "trace")]
    fn try_from(frame: Frame) -> Result<Vec<u8>, Self::Error> {
        match frame {
            Frame::Stream(mut frame) => {
                let size = 1
                    + std::mem::size_of::<u16>()
                    + std::mem::size_of::<u16>()
                    + std::mem::size_of::<StreamFlag>()
                    + std::mem::size_of::<u32>()
                    + frame.data.len();
                let mut encoded = Vec::with_capacity(size);
                encoded.push(1);
                encoded.extend_from_slice(&frame.sport.to_be_bytes());
                encoded.extend_from_slice(&frame.dport.to_be_bytes());
                encoded.extend_from_slice(&(frame.flag as u8).to_be_bytes());
                encoded.append(&mut frame.data);
                Ok(encoded)
            }
            Frame::Datagram(mut frame) => {
                let size = 1
                    + frame.host.len()
                    + std::mem::size_of::<u16>()
                    + std::mem::size_of::<u32>()
                    + frame.data.len();
                let mut encoded = Vec::with_capacity(size);
                encoded.push(3);
                encoded.push(u8::try_from(frame.host.len())?);
                encoded.append(&mut frame.host);
                encoded.extend_from_slice(&frame.port.to_be_bytes());
                encoded.extend_from_slice(&frame.sid.to_be_bytes());
                encoded.append(&mut frame.data);
                Ok(encoded)
            }
        }
    }
}

impl TryFrom<Frame> for Message {
    type Error = <Vec<u8> as TryFrom<Frame>>::Error;

    fn try_from(frame: Frame) -> Result<Self, Self::Error> {
        let bytes = Vec::try_from(frame)?;
        Ok(Message::Binary(bytes))
    }
}

impl TryFrom<Bytes> for StreamFrame {
    type Error = Error;

    fn try_from(mut data: Bytes) -> Result<Self, Self::Error> {
        let sport = data.get_u16();
        let dport = data.get_u16();
        let flag = match data.get_u8() {
            0 => StreamFlag::Syn,
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
            data: Vec::from(data),
        })
    }
}

impl From<Bytes> for DatagramFrame {
    fn from(mut data: Bytes) -> Self {
        let host_len = data.get_u8();
        let host = data.split_to(host_len as usize).into();
        let port = data.get_u16();
        let sid = data.get_u32();
        Self {
            host,
            port,
            sid,
            data: Vec::from(data),
        }
    }
}

impl TryFrom<Vec<u8>> for Frame {
    type Error = Error;

    #[tracing::instrument(skip_all, level = "trace")]
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        let mut data = Bytes::from(data);
        let frame_type = data.get_u8();
        match frame_type {
            1 => Ok(Frame::Stream(StreamFrame::try_from(data)?)),
            3 => Ok(Frame::Datagram(DatagramFrame::from(data))),
            other => Err(Error::InvalidFrameType(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_frame() {
        let frame = Frame::Stream(StreamFrame::new_syn(&[], 5678, 1234).unwrap());
        assert_eq!(
            frame,
            Frame::Stream(StreamFrame {
                sport: 1234,
                dport: 0,
                flag: StreamFlag::Syn,
                data: vec![0x00, 0x16, 0x2e]
            })
        );
        let bytes = Vec::try_from(frame.to_owned()).unwrap();
        let decoded = Frame::try_from(bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_datagram_frame() {
        let frame = Frame::Datagram(DatagramFrame {
            host: vec![1, 2, 3, 4],
            port: 1234,
            sid: 5678,
            data: vec![1, 2, 3, 4],
        });
        let bytes = Vec::try_from(frame.to_owned()).unwrap();
        let decoded = Frame::try_from(bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    /// These tests are to make sure that the binary representation of the
    /// frames does not change without a protocol version bump.
    #[test]
    fn test_frame_repr() {
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

        let frame = Frame::Stream(StreamFrame::new_psh(1234, 5678, vec![1, 2, 3, 4]));
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

        let frame = Frame::Datagram(DatagramFrame {
            host: vec![1, 2, 3, 4],
            port: 1234,
            sid: 5678,
            data: vec![1, 2, 3, 4],
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
