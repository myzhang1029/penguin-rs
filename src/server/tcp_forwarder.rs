//! Pipe TCP streams.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::mux::pipe_streams;
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    net::TcpStream,
};

/// Start a TCP forwarding server on the given listener.
#[tracing::instrument(skip(chan_rx, chan_tx), level = "debug")]
pub async fn start_tcp_forwarder_on_channel<R, W>(
    chan_rx: R,
    chan_tx: W,
    rhost: &str,
    rport: u16,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let mut rstream = TcpStream::connect((rhost, rport)).await?;
    let (rread, rwrite) = rstream.split();
    let rread = BufReader::new(rread);
    pipe_streams(rread, rwrite, chan_rx, chan_tx).await?;
    Ok(())
}
