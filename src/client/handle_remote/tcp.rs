//! Run a remote TCP connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::Error;
use crate::mux::pipe_streams;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// Handshaking stuff. See `server/forwarder/mod.rs`.
#[inline]
pub(crate) async fn channel_tcp_handshake<R, W>(
    mut channel_rx: R,
    mut channel_tx: W,
    rhost: &str,
    rport: u16,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let command = 0x01;
    let rhost_len = u8::try_from(rhost.len())?;
    let mut encoded_rhost = rhost.into();
    let mut data = vec![command, rhost_len];
    data.append(&mut encoded_rhost);
    channel_tx.write_all(&data).await?;
    channel_tx.write_u16(rport).await?;
    if channel_rx.read_u8().await? != 0x03 {
        Err(Error::ServerHandshake)
    } else {
        Ok(())
    }
}

/// Handle a TCP connection.
#[tracing::instrument(skip(channel_rx, channel_tx, tcp_rx, tcp_tx), level = "debug")]
pub(crate) async fn handle_tcp_connection<ReadChan, WriteChan, ReadTcp, WriteTcp>(
    mut channel_rx: ReadChan,
    mut channel_tx: WriteChan,
    rhost: &str,
    rport: u16,
    mut tcp_rx: ReadTcp,
    mut tcp_tx: WriteTcp,
) -> Result<(), Error>
where
    ReadChan: AsyncRead + Unpin,
    ReadTcp: AsyncRead + Unpin,
    WriteChan: AsyncWrite + Unpin,
    WriteTcp: AsyncWrite + Unpin,
{
    channel_tcp_handshake(&mut channel_rx, &mut channel_tx, rhost, rport).await?;
    pipe_streams(&mut tcp_rx, &mut tcp_tx, &mut channel_rx, &mut channel_tx).await?;
    debug!("TCP connection closed");
    Ok(())
}
