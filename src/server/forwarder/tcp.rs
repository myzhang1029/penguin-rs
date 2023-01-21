//! Pipe TCP streams.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

/// Start a TCP forwarding server on the given listener.
///
/// This forwarder is trivial: it just pipes the TCP stream to and from the
/// channel.
///
/// # Errors
/// It carries the errors from the underlying TCP or channel IO functions.
#[tracing::instrument(skip(channel), level = "debug")]
pub(in super::super) async fn start_forwarder_on_channel<RW>(
    mut channel: RW,
    rhost: String,
    rport: u16,
) -> std::io::Result<()>
where
    RW: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut rstream = TcpStream::connect((rhost, rport)).await?;
    tokio::io::copy_bidirectional(&mut channel, &mut rstream).await?;
    Ok(())
}
