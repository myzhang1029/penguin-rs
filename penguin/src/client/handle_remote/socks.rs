//! SOCKS server.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::common::request_tcp_channel;
use super::{FatalError, HandlerResources};
use crate::client::StreamCommand;
use crate::config;
use async_acceptor::{AsyncAcceptable, AsyncAcceptableExt};
use bytes::Bytes;
use penguin_mux::Datagram;
use penguin_socks::{Error as SocksError, magics, v4, v5};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, info, trace, warn};

// Errors that can occur while handling a SOCKS request
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Socks(#[from] SocksError),
    /// IO error during payload data transfer
    #[error("data transfer error: {0}")]
    DataTransfer(std::io::Error),
    /// The client does not support NOAUTH
    #[error("client does not support NOAUTH")]
    OtherAuth,
    /// Fatal error that we should propagate to main
    #[error(transparent)]
    Fatal(#[from] FatalError),
}

pub(super) async fn handle_socks<L>(
    listener: L,
    lhost: &'static str,
    hr: &'static HandlerResources,
) -> Result<(), FatalError>
where
    L: AsyncAcceptable + Send + Sync,
    <L as AsyncAcceptable>::Stream: Unpin,
{
    let mut socks_jobs: JoinSet<Result<(), FatalError>> = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            Some(finished) = socks_jobs.join_next() => {
                finished.expect("SOCKS job panicked (this is a bug)")?;
            }
            result = listener.accept() => {
                // A failed accept() is a fatal error and should be propagated.
                let stream = result.map_err(super::FatalError::ClientIo)?;
                socks_jobs.spawn(on_socks_accept_wrapped(BufReader::new(stream), lhost, hr));
            }
        }
    }
}

#[inline]
async fn on_socks_accept_wrapped<RW>(
    bufreader: BufReader<RW>,
    local_addr: &str,
    hr: &'static HandlerResources,
) -> Result<(), FatalError>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    on_socks_accept(bufreader, local_addr, hr)
        .await
        .or_else(|e| {
            if let Error::Fatal(e) = e {
                Err(e)
            } else {
                info!("{e}");
                Ok(())
            }
        })
}

/// Handle a SOCKS5 connection.
/// Based on socksv5's example.
/// We need to be able to request additional channels, so we need `hr`
#[tracing::instrument(skip(bufreader, hr), level = "trace")]
async fn on_socks_accept<RW>(
    mut bufreader: BufReader<RW>,
    local_addr: &str,
    hr: &'static HandlerResources,
) -> Result<(), Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let version = bufreader
        .read_u8()
        .await
        .map_err(|e| SocksError::ProcessSocksRequest("read version", e))?;
    match version {
        magics::VER_4 => socks4(bufreader, hr).await,
        magics::VER_5 => socks5(bufreader, local_addr, hr).await,
        version => Err(Error::Socks(SocksError::SocksVersion(version))),
    }
}

#[tracing::instrument(skip_all, fields(host, port, cmd))]
async fn socks4<RW>(mut stream: BufReader<RW>, hr: &HandlerResources) -> Result<(), Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let (command, rhost, rport) = v4::read_request(&mut stream).await?;
    tracing::Span::current().record("host", format_args!("{}", String::from_utf8_lossy(&rhost)));
    tracing::Span::current().record("port", rport);
    tracing::Span::current().record("cmd", command);
    debug!("SOCKSv4 request");
    if command == magics::CMD_CONNECT {
        // This fails only if main has exited, which is a fatal error.
        let stream_command_tx_permit = hr
            .stream_command_tx
            .reserve()
            .await
            .or(Err(FatalError::RequestStream))?;
        handle_connect(stream, rhost.into(), rport, stream_command_tx_permit, false).await
    } else {
        v4::write_response(&mut stream, magics::REP_V4_FAIL).await?;
        Err(Error::Socks(SocksError::InvalidCommand(command)))
    }
}

#[tracing::instrument(skip_all, fields(host, port, cmd, local = %local_addr))]
async fn socks5<RW>(
    mut stream: BufReader<RW>,
    local_addr: &str,
    hr: &'static HandlerResources,
) -> Result<(), Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    // Complete the handshake
    let methods = v5::read_auth_methods(&mut stream).await?;
    if !methods.contains(&magics::AUTH_NOAUTH) {
        // Send back NO ACCEPTABLE METHODS
        // Note that we are not compliant with RFC 1928 here, as we MUST
        // support GSSAPI and SHOULD support USERNAME/PASSWORD
        v5::write_auth_method(&mut stream, magics::AUTH_NOACCEPT).await?;
        return Err(Error::OtherAuth);
    }
    // Send back NO AUTHENTICATION REQUIRED
    v5::write_auth_method(&mut stream, magics::AUTH_NOAUTH).await?;
    // Read the request
    let (command, rhost, rport) = v5::read_request(&mut stream).await?;
    tracing::Span::current().record("host", format_args!("{}", String::from_utf8_lossy(&rhost)));
    tracing::Span::current().record("port", rport);
    tracing::Span::current().record("cmd", command);
    debug!("SOCKSv5 request");
    match command {
        magics::CMD_CONNECT => {
            // CONNECT
            // This fails only if main has exited, which is a fatal error.
            let stream_command_tx_permit = hr
                .stream_command_tx
                .reserve()
                .await
                .or(Err(FatalError::RequestStream))?;
            handle_connect(stream, rhost.into(), rport, stream_command_tx_permit, true).await
        }
        // UDP ASSOCIATE
        magics::CMD_ASSOC => handle_associate(&mut stream, local_addr, hr).await,
        // We don't support BIND because I can't ask the remote host to bind
        _ => {
            v5::write_response_unspecified(&mut stream, magics::REP_CMDUNSUP).await?;
            Err(Error::Socks(SocksError::InvalidCommand(command)))
        }
    }
}

#[tracing::instrument(skip_all, level = "trace")]
async fn handle_connect<RW>(
    mut stream: BufReader<RW>,
    rhost: Bytes,
    rport: u16,
    stream_command_tx_permit: mpsc::Permit<'_, StreamCommand>,
    version_is_5: bool,
) -> Result<(), Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    // Establish a connection to the remote host
    let channel = request_tcp_channel(stream_command_tx_permit, rhost, rport)
        .await
        .or(Err(FatalError::MainLoopExitWithoutSendingStream))?;
    // Send back a successful response
    if version_is_5 {
        v5::write_response_unspecified(&mut stream, magics::REP_SUCC).await?;
    } else {
        v4::write_response(&mut stream, magics::REP_V4_SUCC).await?;
    }
    trace!("SOCKS starting copy");
    channel
        .into_copy_bidirectional_with_leftover(stream)
        .await
        .map_err(Error::DataTransfer)?;
    Ok(())
}

#[tracing::instrument(skip_all, level = "trace")]
async fn handle_associate<RW>(
    stream: &mut RW,
    local_addr: &str,
    hr: &'static HandlerResources,
) -> Result<(), Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let socket = match UdpSocket::bind((local_addr, 0)).await {
        Ok(s) => s,
        Err(e) => {
            v5::write_response_unspecified(stream, magics::REP_GENFAIL).await?;
            return Err(Error::Socks(SocksError::ProcessSocksRequest(
                "bind udp socket",
                e,
            )));
        }
    };
    let sock_local_addr = match socket.local_addr() {
        Ok(a) => a,
        Err(e) => {
            v5::write_response_unspecified(stream, magics::REP_GENFAIL).await?;
            return Err(Error::Socks(SocksError::ProcessSocksRequest(
                "get udp socket local addr",
                e,
            )));
        }
    };
    trace!("SOCKS relaying at {sock_local_addr}");
    let relay_task = tokio::spawn(udp_relay(hr, socket));
    // Send back a successful response
    v5::write_response(stream, magics::REP_SUCC, sock_local_addr).await?;
    // My crude way to detect when the client closes the connection
    // I cannot pass a zero-length buffer to read_exact, because so it
    // skips `poll_read` and just returns
    stream.read_exact(&mut [0; 1]).await.ok();
    relay_task.abort();
    Ok(())
}

/// UDP task spawned by the TCP connection
#[tracing::instrument(skip_all, level = "trace")]
async fn udp_relay(hr: &HandlerResources, socket: UdpSocket) -> Result<(), Error> {
    let socket = Arc::new(socket);
    loop {
        let Some((target_host, target_port, data, src, sport)) =
            handle_udp_relay_header(&socket).await?
        else {
            continue;
        };
        let client_id = hr.add_udp_client(
            (src, sport).into(),
            socket.clone(), // cheap
            true,
        );
        let datagram_frame = Datagram {
            target_host,
            target_port,
            flow_id: client_id,
            data,
        };
        // This fails only if main has exited, which is a fatal error.
        hr.datagram_tx
            .send(datagram_frame)
            .await
            .or(Err(FatalError::SendDatagram))?;
    }
}

/// Parse a UDP relay request.
/// Returns (dst, dport, data, src, sport)
async fn handle_udp_relay_header(
    socket: &UdpSocket,
) -> Result<Option<(Bytes, u16, Bytes, IpAddr, u16)>, Error> {
    let mut buf = vec![0; config::MAX_UDP_PACKET_SIZE];
    let (len, addr) = socket
        .recv_from(&mut buf)
        .await
        .map_err(Error::DataTransfer)?;
    trace!("received {len} bytes from {addr}");
    buf.truncate(len);
    let buf = Bytes::from(buf);
    match v5::parse_udp_relay_header(buf) {
        Err(SocksError::FragmentedUdp) => {
            warn!("Fragmented UDP packets are not implemented");
            Ok(None)
        }
        Err(e) => Err(Error::Socks(e)),
        Ok((dst, port, buf)) => {
            trace!("Parsed packet: dst {dst:?} port {port}");
            Ok(Some((dst, port, buf, addr.ip(), addr.port())))
        }
    }
}

/// Send a UDP relay response
#[inline]
pub async fn send_udp_relay_response(
    socket: &UdpSocket,
    target: SocketAddr,
    data: &[u8],
) -> std::io::Result<usize> {
    let content = v5::udp_relay_response(target, data);
    socket.send_to(&content, target).await
}
