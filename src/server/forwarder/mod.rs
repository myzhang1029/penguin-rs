//! Server-side forwarding implementation.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

pub(super) mod tcp;
pub(super) mod udp;

use thiserror::Error;

/// Error type for the forwarder.
#[derive(Error, Debug)]
pub(super) enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid host: {0}")]
    Host(std::string::FromUtf8Error),
    #[error("invalid command: {0}")]
    Command(u8),
}
