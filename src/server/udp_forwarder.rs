//! Forwards UDP Datagrams to and from another host.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::mux::DuplexStream;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};
use tracing::debug;
// We return this `Error` so the main loop can get consistent types.
use super::websocket::Error as WsError;

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid host: {0}")]
    Host(#[from] std::string::FromUtf8Error),
}

/// Start a UDP forwarder server on the given listener.
/// Should be the entry point for a new task.
#[tracing::instrument(skip(chan), level = "debug")]
pub async fn start_udp_forwarder_on_channel(
    mut chan: DuplexStream,
    port: u16,
) -> Result<u16, WsError> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(<std::io::Error as Into<Error>>::into)?;
    let mut addr_len: usize = 0;
    loop {
        let next = chan
            .read_u8()
            .await
            .map_err(<std::io::Error as Into<Error>>::into)?;
        addr_len += next as usize;
        if next != 0xff {
            break;
        }
    }
    let mut addr = vec![0; addr_len];
    chan.read_exact(&mut addr)
        .await
        .map_err(<std::io::Error as Into<Error>>::into)?;
    let addr =
        String::from_utf8(addr).map_err(<std::string::FromUtf8Error as Into<Error>>::into)?;
    let port = chan
        .read_u16()
        .await
        .map_err(<std::io::Error as Into<Error>>::into)?;
    let len = chan
        .read_u64()
        .await
        .map_err(<std::io::Error as Into<Error>>::into)?;
    let mut data = vec![0; len as usize];
    chan.read_exact(&mut data)
        .await
        .map_err(<std::io::Error as Into<Error>>::into)?;
    debug!(
        "UDP forwarder read data: {} bytes from {}:{}: {:?}",
        len, addr, port, data
    );
    socket
        .send_to(&data, (addr, port))
        .await
        .map_err(<std::io::Error as Into<Error>>::into)?;
    let mut buf = [0; 1024];
    let (len, _) = socket
        .recv_from(&mut buf)
        .await
        .map_err(<std::io::Error as Into<Error>>::into)?;
    debug!(
        "UDP forwarder read data: {} bytes from socket: {:?}",
        len,
        &buf[..len]
    );
    chan.write_u64(len as u64)
        .await
        .map_err(<std::io::Error as Into<Error>>::into)?;
    chan.write_all(&buf[..len])
        .await
        .map_err(<std::io::Error as Into<Error>>::into)?;
    Ok(port)
}
