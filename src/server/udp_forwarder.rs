//! Forwards UDP Datagrams to and from another host.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::mux::DuplexStream;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};
use tracing::debug;

/// Start a UDP forwarder server on the given listener.
/// Should be the entry point for a new task.
#[tracing::instrument(skip(chan), level = "debug")]
pub async fn start_udp_forwarder_on_channel(
    mut chan: DuplexStream,
    rhost: &str,
    rport: u16,
) -> std::io::Result<()> {
    let mut buf = [0u8; 65507];
    let mut rbuf = [0u8; 65507];
    let rsocket = UdpSocket::bind("0.0.0.0:0").await?;
    loop {
        let len = chan.read(&mut buf).await?;
        if len == 0 {
            debug!("UDP forwarder: EOF on channel");
            return Ok(());
        }
        debug!("UDP forwarder: read {} bytes", len);
        rsocket.send_to(&buf[..len], (rhost, rport)).await?;
        // TODO: handle UDP deadline, timeout, etc.
        let (rlen, _) = rsocket.recv_from(&mut rbuf).await?;
        debug!("UDP forwarder: read {} bytes from remote", rlen);
        chan.write_all(&rbuf[..rlen]).await?;
    }
}
