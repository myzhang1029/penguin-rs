//! SOCKS server.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod v4;
mod v5;

use super::tcp::{open_tcp_listener, request_tcp_channel};
use super::HandlerResources;
use crate::client::StreamCommand;
use crate::{config, Dupe};
use bytes::{Buf, Bytes};
use penguin_mux::DatagramFrame;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, BufStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, info, trace, warn};

// Errors that can occur while handling a SOCKS request.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error writing to the client that is
    /// not our fault.
    #[error(transparent)]
    Write(#[from] std::io::Error),
    #[error("Client with version={0} is not SOCKSv4 or SOCKSv5")]
    SocksVersion(u8),
    #[error("Unsupported SOCKS command: {0}")]
    InvalidCommand(u8),
    #[error("Invalid SOCKS address type: {0}")]
    AddressType(u8),
    #[error("Cannot {0} in SOCKS request: {1}")]
    ProcessSocksRequest(&'static str, std::io::Error),
    #[error("Client does not support NOAUTH")]
    OtherAuth,
    /// Fatal error that we should propagate to main.
    #[error(transparent)]
    Fatal(#[from] super::FatalError),
}

pub(super) async fn handle_socks(
    lhost: &'static str,
    lport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), super::FatalError> {
    // Failing to open the listener is a fatal error and should be propagated.
    let listener = open_tcp_listener(lhost, lport)
        .await
        .map_err(super::FatalError::ClientIo)?;
    let mut socks_jobs = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            Some(finished) = socks_jobs.join_next() => {
                if let Err(e) = finished.expect("SOCKS job panicked (this is a bug)") {
                    if let Error::Fatal(e) = e {
                        return Err(e);
                    }
                    info!("{e}");
                }
            }
            result = listener.accept() => {
                // A failed accept() is a fatal error and should be propagated.
                let (stream, _) = result.map_err(super::FatalError::ClientIo)?;
                let handler_resources = handler_resources.dupe();
                socks_jobs.spawn(async move {
                    handle_socks_connection(stream, lhost, &handler_resources).await
                });
            }
        }
    }
}

#[inline]
pub(super) async fn handle_socks_stdio(
    handler_resources: &HandlerResources,
) -> Result<(), super::FatalError> {
    if let Err(e) =
        handle_socks_connection(super::Stdio::new(), "localhost", handler_resources).await
    {
        if let Error::Fatal(e) = e {
            return Err(e);
        }
        info!("{e}");
    }
    Ok(())
}

/// Handle a SOCKS5 connection.
/// Based on socksv5's example.
/// We need to be able to request additional channels, so we need `command_tx`
#[tracing::instrument(skip_all, level = "trace")]
#[inline]
pub(super) async fn handle_socks_connection<RW>(
    stream: RW,
    local_addr: &str,
    handler_resources: &HandlerResources,
) -> Result<(), Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let mut bufrw = BufStream::new(stream);
    let version = bufrw
        .read_u8()
        .await
        .map_err(|e| Error::ProcessSocksRequest("read version", e))?;
    match version {
        4 => handle_socks4_connection(bufrw, handler_resources).await,
        5 => handle_socks5_connection(bufrw, local_addr, handler_resources).await,
        version => Err(Error::SocksVersion(version)),
    }
}

#[inline]
async fn handle_socks4_connection<RW>(
    mut stream: RW,
    handler_resources: &HandlerResources,
) -> Result<(), Error>
where
    RW: AsyncBufRead + AsyncWrite + Unpin,
{
    let (command, rhost, rport) = v4::read_request(&mut stream).await?;
    trace!("SOCKSv4 request rhost={rhost:?} rport={rport}");
    if command == 0x01 {
        // CONNECT
        // This fails only if main has exited, which is a fatal error.
        let stream_command_tx_permit = handler_resources
            .stream_command_tx
            .reserve()
            .await
            .map_err(|_| super::FatalError::RequestStream)?;
        handle_connect(stream, rhost, rport, stream_command_tx_permit, false).await
    } else {
        v4::write_response(&mut stream, 0x5b).await?;
        Err(Error::InvalidCommand(command))
    }
}

#[inline]
async fn handle_socks5_connection<RW>(
    mut stream: RW,
    local_addr: &str,
    handler_resources: &HandlerResources,
) -> Result<(), Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    // Complete the handshake
    let methods = v5::read_auth_methods(&mut stream).await?;
    if !methods.contains(&0x00) {
        // Send back NO ACCEPTABLE METHODS
        // Note that we are not compliant with RFC 1928 here, as we MUST
        // support GSSAPI and SHOULD support USERNAME/PASSWORD
        v5::write_auth_method(&mut stream, 0xff).await?;
        return Err(Error::OtherAuth);
    }
    // Send back NO AUTHENTICATION REQUIRED
    v5::write_auth_method(&mut stream, 0x00).await?;
    // Read the request
    let (command, rhost, rport) = v5::read_request(&mut stream).await?;
    trace!("SOCKSv5 cmd={command} rhost={rhost:?} rport={rport}");
    match command {
        0x01 => {
            // CONNECT
            // This fails only if main has exited, which is a fatal error.
            let stream_command_tx_permit = handler_resources
                .stream_command_tx
                .reserve()
                .await
                .map_err(|_| super::FatalError::RequestStream)?;
            handle_connect(stream, rhost, rport, stream_command_tx_permit, true).await
        }
        0x03 => {
            // UDP ASSOCIATE
            handle_associate(stream, rhost, rport, local_addr, handler_resources).await
        }
        // We don't support BIND because I can't ask the remote host to bind
        _ => {
            v5::write_response_unspecified(&mut stream, 0x07).await?;
            Err(Error::InvalidCommand(command))
        }
    }
}

#[inline]
#[tracing::instrument(
    skip_all,
    fields(
        host = %String::from_utf8_lossy(&rhost),
        port = rport,
        v = if version_is_5 { 5 } else { 4 },
    ),
)]
async fn handle_connect<RW>(
    mut stream: RW,
    rhost: Bytes,
    rport: u16,
    stream_command_tx_permit: mpsc::Permit<'_, StreamCommand>,
    version_is_5: bool,
) -> Result<(), Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    debug!("SOCKS connect");
    // Establish a connection to the remote host
    let mut channel = request_tcp_channel(stream_command_tx_permit, rhost, rport)
        .await
        .map_err(|_| super::FatalError::MainLoopExitWithoutSendingStream)?;
    // Send back a successful response
    if version_is_5 {
        v5::write_response_unspecified(&mut stream, 0x00).await?;
    } else {
        v4::write_response(&mut stream, 0x5a).await?;
    };
    stream.flush().await?;
    tokio::io::copy_bidirectional(&mut stream, &mut channel).await?;
    Ok(())
}

#[inline]
#[tracing::instrument(
    skip_all,
    fields(
        host = %String::from_utf8_lossy(&rhost),
        port = rport,
    ),
)]
async fn handle_associate<RW>(
    mut stream: RW,
    rhost: Bytes,
    rport: u16,
    local_addr: &str,
    handler_resources: &HandlerResources,
) -> Result<(), Error>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    debug!("SOCKS associate");
    let socket = match UdpSocket::bind((local_addr, 0)).await {
        Ok(s) => s,
        Err(e) => {
            v5::write_response_unspecified(&mut stream, 0x01).await?;
            return Err(Error::ProcessSocksRequest("bind udp socket", e));
        }
    };
    let sock_local_addr = match socket.local_addr() {
        Ok(a) => a,
        Err(e) => {
            v5::write_response_unspecified(&mut stream, 0x01).await?;
            return Err(Error::ProcessSocksRequest("get udp socket local addr", e));
        }
    };
    let relay_task = tokio::spawn(udp_relay(rhost, rport, handler_resources.dupe(), socket));
    // Send back a successful response
    v5::write_response(&mut stream, 0x00, sock_local_addr).await?;
    // My crude way to detect when the client closes the connection
    stream.read(&mut [0; 1]).await.ok();
    relay_task.abort();
    Ok(())
}

/// UDP task spawned by the TCP connection
#[allow(clippy::similar_names)]
async fn udp_relay(
    _rhost: Bytes,
    _rport: u16,
    handler_resources: HandlerResources,
    socket: UdpSocket,
) -> Result<(), Error> {
    let socket = Arc::new(socket);
    loop {
        let Some((dst, dport, data, src, sport)) = handle_udp_relay_header(&socket).await? else {
            continue
        };
        let client_id = handler_resources
            .add_udp_client((src, sport).into(), socket.dupe(), true)
            .await;
        let datagram_frame = DatagramFrame {
            host: dst,
            port: dport,
            sid: client_id,
            data,
        };
        // This fails only if main has exited, which is a fatal error.
        handler_resources
            .datagram_tx
            .send(datagram_frame)
            .await
            .map_err(|_| super::FatalError::SendDatagram)?;
    }
}

/// Parse a UDP relay request.
/// Returns (dst, dport, data, src, sport)
#[inline]
async fn handle_udp_relay_header(
    socket: &UdpSocket,
) -> Result<Option<(Bytes, u16, Bytes, IpAddr, u16)>, Error> {
    let mut buf = vec![0; config::MAX_UDP_PACKET_SIZE];
    let (len, addr) = socket.recv_from(&mut buf).await?;
    buf.truncate(len);
    let mut buf = Bytes::from(buf);
    let _reserved = buf.get_u16();
    let frag = buf.get_u8();
    if frag != 0 {
        warn!("Fragmented UDP packets are not implemented");
        return Ok(None);
    }
    let atyp = buf.get_u8();
    let (dst, port) = match atyp {
        0x01 => {
            // IPv4
            let addr = buf.get_u32();
            let dst = Ipv4Addr::from(addr).to_string();
            let port = buf.get_u16();
            (dst.into(), port)
        }
        0x03 => {
            // Domain name
            let len = usize::from(buf.get_u8());
            let dst = buf.split_to(len);
            let port = buf.get_u16();
            (dst, port)
        }
        0x04 => {
            // IPv6
            let addr = buf.get_u128();
            let dst = Ipv6Addr::from(addr).to_string();
            let port = buf.get_u16();
            (dst.into(), port)
        }
        _ => {
            warn!("Dropping datagram with invalid address type {atyp}");
            return Ok(None);
        }
    };
    Ok(Some((dst, port, buf, addr.ip(), addr.port())))
}

/// Send a UDP relay response
#[inline]
pub async fn send_udp_relay_response(
    socket: &UdpSocket,
    target: &SocketAddr,
    data: &[u8],
) -> std::io::Result<usize> {
    // Write the header
    let mut content = vec![0; 3];
    match target.ip() {
        IpAddr::V4(ip) => {
            content.extend(ip.octets());
            content.extend([0x01]);
        }
        IpAddr::V6(ip) => {
            content.extend(ip.octets());
            content.extend([0x04]);
        }
    }
    content.extend(&target.port().to_be_bytes());
    content.extend(data);
    socket.send_to(&content, target).await
}
