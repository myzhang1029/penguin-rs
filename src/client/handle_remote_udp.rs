//! Run a remote UDP connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::handle_remote::{request_channel, Error};
use super::Command;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::error;

macro_rules! complete_or_break {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => {
                break err;
            }
        }
    };
}

/// Handshaking stuff. See `server/mod.rs`.
#[inline]
pub(crate) async fn channel_udp_handshake<R, W>(
    mut channel_rx: R,
    mut channel_tx: W,
    rhost: &str,
    rport: u16,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let command = 0x03;
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

/// Handle a UDP socket.
/// The format of the datagram on the channel is:
/// - 4 bytes: length of the payload (big endian)
///   4 bytes is to future-proof us against IPv6 jumbo frames.
/// - `length` bytes: the payload
#[tracing::instrument(skip(command_tx, socket))]
pub(crate) async fn handle_udp_socket(
    command_tx: mpsc::Sender<Command>,
    socket: UdpSocket,
    rhost: String,
    rport: u16,
) -> Result<(), Error> {
    // Outer loop to handle channel reconnects
    loop {
        let channel = request_channel(&command_tx).await?;
        let (mut channel_rx, mut channel_tx) = tokio::io::split(channel);
        channel_udp_handshake(&mut channel_rx, &mut channel_tx, &rhost, rport).await?;
        let mut buf = [0u8; 65536];
        let e = loop {
            // XXX: Note that we block on reading from the channel. This means that
            // only one client can use the channel at a time.
            let (len, addr) = socket.recv_from(&mut buf).await?;
            complete_or_break!(channel_tx.write_u32(len as u32).await);
            complete_or_break!(channel_tx.write_all(&buf[..len]).await);
            let len = complete_or_break!(channel_rx.read_u32().await);
            let len = len as usize;
            complete_or_break!(channel_rx.read_exact(&mut buf[..len]).await);
            socket.send_to(&buf[..len], &addr).await?;
        };
        if super::retryable_errors(&e) {
            continue;
        } else {
            error!("UDP socket error: {e}");
            break Err(e.into());
        }
    }
}
