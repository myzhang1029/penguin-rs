//! Server-side forwarding implementation.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
//!
//! Architecture:
//! The system is similar to a traditional SOCKS5 proxy, but the protocol
//! allows for UDP to be transmitted over the same WebSocket connection.
//! It is essentially a SOCKS5 forwarder over a WebSocket.
//!
//! - The client and the server communicate over a WebSocket.
//! - (`mux`) The WebSocket is converted to a `AsyncRead + AsyncWrite` stream.
//!   and multiplexed to allow multiple simultaneous connections.
//!   Upon handshake, the client sends the type, destination address, and port
//!   in a way similar to SOCKS5:
//!   - 1 byte: command (1 for TCP, 3 for UDP)
//!   - variable: 1 + (0..256) bytes: length + (domain name or IP)
//!   - 2 bytes: port in network byte order
//!   Then, the server responds with a u8 (0x03) on success. On failure, the
//!   channel is closed.
//! - (`tcp_forwarder`) The multiplexed channel is converted to a TCP stream.
//! - (`udp_forwarder`) The multiplexed channel is converted to UDP datagrams.

mod tcp;
mod udp;

use penguin_tokio_stream_multiplexor::DuplexStream;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tracing::info;

/// Error type for the forwarder.
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(std::io::Error),
    #[error("invalid host: {0}")]
    Host(std::string::FromUtf8Error),
    #[error("invalid command: {0}")]
    Command(u8),
}

/// Dispatch requests on a channel to the appropriate forwarders.
///
/// Should be spawned as a new task. In whatever case, `chan` will be
/// closed (dropped) when this task exits.
#[tracing::instrument(skip(chan), level = "trace")]
pub async fn dispatch_conn(chan: DuplexStream) -> Result<(), Error> {
    let (chan_rx, mut chan_tx) = tokio::io::split(chan);
    let mut chan_rx = BufReader::new(chan_rx);
    // Handshake
    let command = chan_rx.read_u8().await.map_err(Error::Io)?;
    let len = chan_rx.read_u8().await.map_err(Error::Io)?;
    let mut rhost = vec![0; len as usize];
    chan_rx.read_exact(&mut rhost).await.map_err(Error::Io)?;
    let rhost = String::from_utf8(rhost).map_err(Error::Host)?;
    let rport = chan_rx.read_u16().await.map_err(Error::Io)?;
    chan_tx.write_u8(0x03).await.map_err(Error::Io)?;
    match command {
        1 => {
            info!("TCP connect to {rhost}:{rport}");
            tcp::start_forwarder_on_channel(chan_rx, chan_tx, &rhost, rport)
                .await
                .map_err(Error::Io)?;
            Ok(())
        }
        3 => {
            info!("UDP forward to {rhost}:{rport}");
            udp::start_forwarder_on_channel(chan_rx, chan_tx, &rhost, rport)
                .await
                .map_err(Error::Io)?;
            Ok(())
        }
        _ => Err(Error::Command(command)),
    }
}
