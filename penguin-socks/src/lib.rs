//! SOCKS server on an asynchronous stream.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

#![deny(rust_2018_idioms, missing_docs, missing_debug_implementations)]
#![deny(clippy::pedantic, clippy::cargo, clippy::nursery, clippy::unwrap_used)]
#![allow(clippy::multiple_crate_versions)]

pub mod magics;
pub mod v4;
pub mod v5;

/// Errors that can occur while handling a SOCKS request
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Client sent a request with an unknown SOCKS version
    #[error("client with version={0} is not SOCKSv4 or SOCKSv5")]
    SocksVersion(u8),
    /// Invalid command
    #[error("unsupported SOCKS command: {0}")]
    InvalidCommand(u8),
    /// Invalid address type
    #[error("invalid SOCKS address type: {0}")]
    AddressType(u8),
    /// An IO error occurred while processing a SOCKS request
    #[error("cannot {0} in SOCKS request: {1}")]
    ProcessSocksRequest(&'static str, std::io::Error),
    /// The `ASSOCIATE` command is malformed
    #[error("cannot parse SOCKS associate datagram")]
    ParseAssociate,
    /// Fragmented UDP packets are not implemented
    #[error("fragmented UDP packets are not implemented")]
    FragmentedUdp,
    /// Unknown address type
    #[error("unknown address type: {0}")]
    UnknownAddressType(u8),
}
