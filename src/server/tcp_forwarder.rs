//! Pipe TCP streams.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::mux::{pipe_streams, DuplexStream};

/// Start a TCP forwarding server on the given listener.
#[tracing::instrument(skip(chan), level = "debug")]
pub async fn start_tcp_forwarder_on_channel(
    chan: DuplexStream,
    rhost: &str,
    rport: u16,
) -> std::io::Result<()> {
    let mut rstream = tokio::net::TcpStream::connect((rhost, rport)).await?;
    let (rread, rwrite) = rstream.split();
    let (lread, lwrite) = tokio::io::split(chan);
    pipe_streams(rread, rwrite, lread, lwrite).await?;
    Ok(())
}
