//! Pipe TCP streams.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::mux::pipe_streams;
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader, BufWriter},
    net::TcpStream,
};

/// Start a TCP forwarding server on the given listener.
///
/// This forwarder is trivial: it just pipes the TCP stream to and from the
/// channel.
///
/// # Errors
/// It carries the errors from the underlying TCP or channel IO functions.
#[tracing::instrument(skip(chan_rx, chan_tx), level = "debug")]
pub(in super::super) async fn start_forwarder_on_channel<R, W>(
    chan_rx: R,
    chan_tx: W,
    rhost: String,
    rport: u16,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let chan_rx = BufReader::new(chan_rx);
    let chan_tx = BufWriter::new(chan_tx);
    let mut rstream = TcpStream::connect((rhost, rport)).await?;
    let (rread, rwrite) = rstream.split();
    let rread = BufReader::new(rread);
    let rwrite = BufWriter::new(rwrite);
    // chan_X should have already been buffered
    pipe_streams(rread, rwrite, chan_rx, chan_tx).await?;
    Ok(())
}
