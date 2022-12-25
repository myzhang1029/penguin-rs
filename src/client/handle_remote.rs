//! Run a remote connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::mux::{pipe_streams, ChannelType, DuplexStream};
use crate::parse_remote::Remote;
use crate::parse_remote::{LocalSpec, Protocol, RemoteSpec};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter, AsyncBufReadExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info};

use super::Command;

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("socks5 proxy failed: {0}")]
    Socks(#[from] async_socks5::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    #[error("cannot receive stream from the main loop")]
    ReceiveStream(#[from] oneshot::error::RecvError),
    #[error("main loop cannot send stream")]
    SendStream(#[from] mpsc::error::SendError<Command>),
}

/// Construct a remote based on the description.
/// For UDP, there is a brief handshake to exchange the destination,
/// similar to SOCKS5. Then, the sockets are connected to each other.
#[tracing::instrument(skip(command_tx))]
pub async fn handle_remote(remote: Remote, command_tx: mpsc::Sender<Command>) -> Result<(), Error> {
    debug!("Opening remote {remote}");
    match (remote.local_addr, remote.protocol) {
        (LocalSpec::Inet((lhost, lport)), Protocol::Tcp) => {
            let listener = TcpListener::bind((lhost, lport)).await?;
            info!("Listening on port {lport}");
            loop {
                let (tcp_stream, _) = listener.accept().await?;
                let (tx, rx) = oneshot::channel();
                command_tx.send((tx, ChannelType::Stream)).await?;
                let stream = rx.await?;
                let (tcp_rx, tcp_tx) = tokio::io::split(tcp_stream);
                let rspec = remote.remote_addr.clone();
                tokio::spawn(
                    async move { handle_tcp_connection(stream, rspec, tcp_rx, tcp_tx).await },
                );
            }
        }
        (LocalSpec::Inet((lhost, lport)), Protocol::Udp) => {
            let socket = tokio::net::UdpSocket::bind((lhost, lport)).await?;
            let (rhost, rport) = if let RemoteSpec::Inet((rhost, rport)) = remote.remote_addr {
                (rhost, rport)
            } else {
                unreachable!("Should have been caught by the parser");
            };
            info!("Listening on port {lport}");
            loop {
                let (tx, rx) = oneshot::channel();
                command_tx.send((tx, ChannelType::Datagram)).await?;
                let mut stream = rx.await?;
                let mut rhost_len = rhost.len();
                // Send the destination address length.
                // If the length is greater than 255, we send 255 and
                // the server should keep reading until it is not 255.
                while rhost_len > 0xff {
                    stream.write_u8(0xff).await?;
                    rhost_len -= 255;
                }
                // XXX: Everything is a hack.
                stream.write_u8(rhost_len as u8).await?;
                // Send the destination address.
                stream.write_all(rhost.as_bytes()).await?;
                // Send the destination port.
                stream.write_u16(rport).await?;
                let mut buf = vec![0; 1024];
                let (len, addr) = socket.recv_from(&mut buf).await?;
                stream.write_u64(len as u64).await?;
                stream.write_all(&buf[..len]).await?;
                let len = stream.read_u64().await? as usize;
                stream.read_exact(&mut buf[..len]).await?;
                socket.send_to(&buf[..len], addr).await?;
            }
        }
        (LocalSpec::Stdio, Protocol::Tcp) => {
            let (tx, rx) = oneshot::channel();
            command_tx.send((tx, ChannelType::Stream)).await?;
            let stream = rx.await?;
            let rspec = remote.remote_addr.clone();
            handle_tcp_connection(stream, rspec, tokio::io::stdin(), tokio::io::stdout()).await
        }
        (LocalSpec::Stdio, Protocol::Udp) => {
            // XXX: What does this even mean?
            let (rhost, rport) = if let RemoteSpec::Inet((rhost, rport)) = remote.remote_addr {
                (rhost, rport)
            } else {
                unreachable!("Should have been caught by the parser");
            };
            let (tx, rx) = oneshot::channel();
            command_tx.send((tx, ChannelType::Datagram)).await?;
            let mut stream = rx.await?;
            let stdin_reader = BufReader::new(tokio::io::stdin());
            let mut stdin_lines = stdin_reader.lines();
            let mut stdout_writer = BufWriter::new(tokio::io::stdout());
            while let Some(line) = stdin_lines.next_line().await? {
                let mut rhost_len = rhost.len();
                // Send the destination address length.
                // If the length is greater than 255, we send 255 and
                // the server should keep reading until it is not 255.
                while rhost_len > 0xff {
                    stream.write_u8(0xff).await?;
                    rhost_len -= 255;
                }
                // XXX: Everything is a hack.
                stream.write_u8(rhost_len as u8).await?;
                // Send the destination address.
                stream.write_all(rhost.as_bytes()).await?;
                // Send the destination port.
                stream.write_u16(rport).await?;
                let len = line.len();
                stream.write_u64(len as u64).await?;
                stream.write_all(line.as_bytes()).await?;
                let len = stream.read_u64().await? as usize;
                let mut buf = vec![0; len];
                stream.read_exact(&mut buf).await?;
                stdout_writer.write_all(&buf).await?;
            }
            Ok(())
        }
    }
}

/// Handle a TCP connection.
#[tracing::instrument(skip(stream, local_rx, local_tx))]
async fn handle_tcp_connection<R, T>(
    mut stream: DuplexStream,
    rspec: RemoteSpec,
    mut local_rx: R,
    mut local_tx: T,
) -> Result<(), Error>
where
    R: AsyncReadExt + Unpin + Send + 'static,
    T: AsyncWriteExt + Unpin + Send + 'static,
{
    // I could have used a giant match here, but I think this is more readable.
    if rspec == RemoteSpec::Socks {
        debug!("Forwarding local to the internal socks5 proxy");
        let (mut rx, mut tx) = tokio::io::split(stream);
        pipe_streams(&mut local_rx, &mut local_tx, &mut rx, &mut tx).await?;
        debug!("SOCKS connection closed");
        Ok(())
    } else {
        // We want to ask the socks5 proxy to connect to another port.
        let (rhost, rport) = match rspec {
            RemoteSpec::Inet((rhost, rport)) => (rhost, rport),
            RemoteSpec::Socks => unreachable!("already matched this case above"),
        };
        debug!("Forwarding local to the remote socks5 proxy");
        async_socks5::connect(&mut stream, (rhost, rport), None).await?;
        let (mut socksified_rx, mut socksified_tx) = tokio::io::split(stream);
        pipe_streams(
            &mut local_rx,
            &mut local_tx,
            &mut socksified_rx,
            &mut socksified_tx,
        )
        .await?;
        debug!("SOCKS connection closed");
        Ok(())
    }
}
