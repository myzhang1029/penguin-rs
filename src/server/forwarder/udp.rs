//! Forwards UDP Datagrams to and from another host.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
};
use tracing::debug;

/// Start a UDP forwarder server on the given listener.
///
/// I'm pretty sure this `Future` won't linger around after the other end of
/// the channel is closed.
///
/// This forwarder expects to receive a 32-bit length prefix before each UDP
/// datagram, and then the datagram itself. It will then forward the datagram
/// to the remote host.
/// When it receives datagrams from the remote host, it will send them to the
/// channel with the same 32-bit length prefix.
/// The entire system effectively acts as a full-cone NAT.
/// A length of 0 can be used to indicate EOF.
///
/// # Errors
/// It carries the errors from the underlying UDP or channel IO functions.
#[tracing::instrument(skip(chan_rx, chan_tx), level = "debug")]
pub async fn start_forwarder_on_channel<R, W>(
    mut chan_rx: R,
    mut chan_tx: W,
    rhost: &str,
    rport: u16,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let rsocket = UdpSocket::bind("0.0.0.0:0").await?;
    let arc_socket = std::sync::Arc::new(rsocket);
    let reader_job = {
        let socket = arc_socket.clone();
        // The final `Ok` is for type inference.
        #[allow(unreachable_code)]
        tokio::spawn(async move {
            let mut buf = [0u8; 65507];
            loop {
                let (len, _) = socket.recv_from(&mut buf).await?;
                debug!("read {len} bytes from remote, sending to channel");
                chan_tx.write_u32(len as u32).await?;
                chan_tx.write_all(&buf[..len]).await?;
                chan_tx.flush().await?;
            }
            Ok::<(), std::io::Error>(())
        })
    };
    let result = loop {
        match chan_rx.read_u32().await {
            Ok(len) => {
                let len = len as usize;
                debug!("read {len} bytes from channel, forwarding to {rhost}:{rport}");
                let mut buf = vec![0u8; len];
                if let Err(e) = chan_rx.read_exact(&mut buf).await {
                    // use `break` so we can await the reader job
                    break Err(e);
                }
                if let Err(e) = arc_socket.send_to(&buf, (rhost, rport)).await {
                    // use `break` so we can await the reader job
                    break Err(e);
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    // I guess this is normal?
                    break Ok(());
                }
                break Err(e);
            }
        }
    };
    debug!("aborting reader job");
    reader_job.abort();
    result
}
