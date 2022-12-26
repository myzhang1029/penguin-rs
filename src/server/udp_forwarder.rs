//! Forwards UDP Datagrams to and from another host.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
};
use tracing::debug;

/// Start a UDP forwarder server on the given listener.
/// Should be the entry point for a new task.
/// I'm pretty sure this `Future` won't linger around after the other end of
/// the channel is closed.
#[tracing::instrument(skip(chan_rx, chan_tx), level = "debug")]
pub async fn start_udp_forwarder_on_channel<R, W>(
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
                debug!("UDP forwarder: read {} bytes from remote", len);
                chan_tx.write_all(&buf[..len]).await?;
            }
            Ok::<(), std::io::Error>(())
        })
    };
    let result = loop {
        match chan_rx.read_u32().await {
            Ok(len) => {
                let len = len as usize;
                debug!("UDP forwarder: read {} bytes from channel", len);
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
                    break Ok(());
                }
                break Err(e);
            }
        }
    };
    reader_job.abort();
    result
}
