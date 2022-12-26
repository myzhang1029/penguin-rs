//! Run a remote connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::client::socks::handle_socks_connection;
use crate::mux::{pipe_streams, DuplexStream};
use crate::parse_remote::{LocalSpec, RemoteSpec};
use crate::parse_remote::{Protocol, Remote};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use super::Command;

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    #[error("cannot receive stream from the main loop")]
    ReceiveStream(#[from] oneshot::error::RecvError),
    #[error("main loop cannot send stream")]
    SendStream(#[from] mpsc::error::SendError<Command>),
    #[error("remote host longer than 255 octets")]
    RHostTooLong(#[from] std::num::TryFromIntError),
    #[error("server did not complete the handshake")]
    ServerHandshake,

    // These are for the socks server
    #[error("only supports SOCKSv5")]
    Socksv4,
    #[error("invalid domain name: {0}")]
    DomainName(#[from] std::string::FromUtf8Error),
    #[error("only supports NOAUTH")]
    OtherAuth,
    #[error("cannot read socks request")]
    SocksRequest,
}

/// Construct a TCP remote based on the description. These are simple because
/// a new channel can be created for each new connection and they do not need
/// to persist afther the connection.
/// This should be spawned as tasks and they will remain as long as `client`
/// is alive. Individual connection tasks are spawned as connections appear.
#[tracing::instrument(skip(command_tx))]
pub async fn handle_remote(
    remote: Remote,
    mut command_tx: mpsc::Sender<Command>,
) -> Result<(), Error> {
    debug!("Opening remote {remote}");
    match (remote.local_addr, remote.remote_addr, remote.protocol) {
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Inet((rhost, rport)), Protocol::Tcp) => {
            let listener = TcpListener::bind((lhost, lport)).await?;
            info!("Listening on port {lport}");
            loop {
                let (tcp_stream, _) = listener.accept().await?;
                // A new channel is created for each incoming TCP connection.
                // It's already TCP, anyways.
                let channel = request_channel(&mut command_tx).await?;
                // Don't use `BufWriter` here because it will buffer the handshake
                let rhost = rhost.clone();
                tokio::spawn(async move {
                    let (tcp_rx, tcp_tx) = tokio::io::split(tcp_stream);
                    let tcp_rx = BufReader::new(tcp_rx);
                    let (channel_rx, channel_tx) = tokio::io::split(channel);
                    let channel_rx = BufReader::new(channel_rx);
                    handle_tcp_connection(channel_rx, channel_tx, &rhost, rport, tcp_rx, tcp_tx)
                        .await
                });
            }
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Inet((rhost, rport)), Protocol::Udp) => {
            let socket = UdpSocket::bind((lhost, lport)).await?;
            info!("Bound on port {lport}");
            let command_tx = command_tx.clone();
            let rhost = rhost.clone();
            tokio::spawn(handle_udp_socket(command_tx, socket, rhost, rport));
            Ok(())
        }
        (LocalSpec::Stdio, RemoteSpec::Inet((rhost, rport)), _) => {
            let (mut stdin, mut stdout) = (tokio::io::stdin(), tokio::io::stdout());
            // We want `loop` to be able to continue after a connection failure
            loop {
                let channel = request_channel(&mut command_tx).await?;
                let (channel_rx, mut channel_tx) = tokio::io::split(channel);
                let mut channel_rx = BufReader::new(channel_rx);
                channel_tcp_handshake(&mut channel_rx, &mut channel_tx, &rhost, rport).await?;
                match pipe_streams(&mut stdin, &mut stdout, channel_rx, channel_tx).await {
                    Err(err) => {
                        warn!("Remote disconnected");
                        if !super::retryable_errors(&err) {
                            break Err(err.into());
                        }
                        // Else just retry
                    }
                    Ok(_) => {
                        break Ok(());
                    }
                }
            }
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Socks, _) => {
            // The parser guarantees that the protocol is TCP
            let listener = TcpListener::bind((lhost, lport)).await?;
            info!("Listening on port {lport}");
            loop {
                let (tcp_stream, _) = listener.accept().await?;
                let (tcp_rx, tcp_tx) = tokio::io::split(tcp_stream);
                tokio::spawn(handle_socks_connection(command_tx.clone(), tcp_rx, tcp_tx));
            }
        }
        (LocalSpec::Stdio, RemoteSpec::Socks, _) => {
            // The parser guarantees that the protocol is TCP
            Ok(
                handle_socks_connection(
                    command_tx.clone(),
                    tokio::io::stdin(),
                    tokio::io::stdout(),
                )
                .await?,
            )
        }
    }
}

/// Request a channel from the mux
/// We use a `&mut` to make sure we have the exclusive borrow.
/// Just to make my life easier.
#[inline]
pub(crate) async fn request_channel(
    command_tx: &mut mpsc::Sender<Command>,
) -> Result<DuplexStream, Error> {
    let (tx, rx) = oneshot::channel();
    command_tx.send(tx).await?;
    Ok(rx.await?)
}

/// Handshaking stuff. See `server/mod.rs`.
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

/// Handle a TCP connection.
#[tracing::instrument(skip(channel_rx, channel_tx, tcp_rx, tcp_tx))]
async fn handle_tcp_connection<ReadChan, WriteChan, ReadTcp, WriteTcp>(
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
    debug!("SOCKS connection closed");
    Ok(())
}

/// Handle a UDP socket.
#[tracing::instrument(skip(command_tx, socket))]
async fn handle_udp_socket(
    mut command_tx: mpsc::Sender<Command>,
    socket: UdpSocket,
    rhost: String,
    rport: u16,
) -> Result<(), Error> {
    let channel = request_channel(&mut command_tx).await?;
    let (mut channel_rx, mut channel_tx) = tokio::io::split(channel);
    channel_udp_handshake(&mut channel_rx, &mut channel_tx, &rhost, rport).await?;
    let mut buf = [0u8; 65536];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        channel_tx.write_all(&buf[..len]).await?;
        let len = channel_rx.read(&mut buf).await?;
        socket.send_to(&buf[..len], &addr).await?;
    }
}
