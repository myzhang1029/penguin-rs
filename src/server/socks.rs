//! SOCKS 5 server.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::mux::pipe_streams;
use log::{debug, trace};
use socksv5::v5::SocksV5Host;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_stream_multiplexor::DuplexStream;

const SOCKS5_HOST_UNKNOWN: SocksV5Host = SocksV5Host::Ipv4([0, 0, 0, 0]);

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("only supports SOCKSv5")]
    Socksv4,
    #[error("cannot read socks version: {0}")]
    SocksVersion(#[from] socksv5::SocksVersionError),
    #[error("cannot read socks handshake: {0}")]
    SocksHandshake(#[from] socksv5::v5::SocksV5HandshakeError),
    #[error("cannot read socks request: {0}")]
    SocksRequest(#[from] socksv5::v5::SocksV5RequestError),
    #[error("only supports NOAUTH")]
    OtherAuth,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid domain name: {0}")]
    DomainName(#[from] std::string::FromUtf8Error),
    #[error("cannot resolve domain name")]
    ResolveDomainName,
    #[error("cannot connect")]
    Connect,
    #[error("invalid command: {0:?}")]
    Command(socksv5::v5::SocksV5Command),
}

/// Start a SOCKS server on the given listener.
/// Should be the entry point for a new task.
pub async fn start_socks_server_on_channel(chan: DuplexStream) -> Result<(), Error> {
    debug!("SOCKS connection accepted");
    let (mut reader1, mut writer1) = tokio::io::split(chan);
    let server_socket = handshake(&mut reader1, &mut writer1).await?;
    let (mut reader2, mut writer2) = tokio::io::split(server_socket);
    pipe_streams(&mut reader1, &mut writer1, &mut reader2, &mut writer2).await?;
    debug!("SOCKS connection closed");
    Ok(())
}

/// Perform the SOCKS handshake.
/// Based on socksv5's example.
async fn handshake<R, W>(mut reader: R, mut writer: W) -> Result<TcpStream, Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if socksv5::read_version(&mut reader).await? != socksv5::SocksVersion::V5 {
        debug!("Client is not SOCKSv5");
        return Err(Error::Socksv4);
    }
    let handshake = socksv5::v5::read_handshake_skip_version(&mut reader).await?;

    if !handshake
        .methods
        .into_iter()
        .any(|m| m == socksv5::v5::SocksV5AuthMethod::Noauth)
    {
        debug!("Client does not support NOAUTH");
        return Err(Error::OtherAuth);
    }

    socksv5::v5::write_auth_method(&mut writer, socksv5::v5::SocksV5AuthMethod::Noauth).await?;

    let request = socksv5::v5::read_request(&mut reader).await?;

    match request.command {
        socksv5::v5::SocksV5Command::Connect => {
            let host = match request.host {
                SocksV5Host::Ipv4(ip) => SocketAddr::new(IpAddr::V4(ip.into()), request.port),
                SocksV5Host::Ipv6(ip) => SocketAddr::new(IpAddr::V6(ip.into()), request.port),
                SocksV5Host::Domain(domain) => {
                    let domain = String::from_utf8(domain)?;
                    let mut addr = (&domain as &str, request.port)
                        .to_socket_addrs()?
                        .next()
                        .ok_or(Error::ResolveDomainName)?;
                    addr.set_port(request.port);
                    addr
                }
            };

            let server_socket = TcpStream::connect(host).await;

            match server_socket {
                Ok(server_socket) => {
                    // Some clients require this?
                    let (lhost, lport) = match server_socket.local_addr() {
                        Ok(addr) => {
                            trace!("Local address is {}", addr);
                            (sockaddr_to_socksv5host(&addr), addr.port())
                        }
                        Err(e) => {
                            debug!("Local address is unknown: {}", e);
                            (SOCKS5_HOST_UNKNOWN, 0)
                        }
                    };
                    socksv5::v5::write_request_status(
                        &mut writer,
                        socksv5::v5::SocksV5RequestStatus::Success,
                        lhost,
                        lport,
                    )
                    .await?;
                    Ok(server_socket)
                }
                Err(e) => {
                    // Unix error codes.
                    let status = ioerror_to_socksv5status(&e);
                    socksv5::v5::write_request_status(&mut writer, status, SOCKS5_HOST_UNKNOWN, 0)
                        .await?;
                    debug!("Cannot connect to the requested destination: {}", e);
                    Err(Error::Connect)
                }
            }
        }
        cmd => {
            socksv5::v5::write_request_status(
                &mut writer,
                socksv5::v5::SocksV5RequestStatus::CommandNotSupported,
                SOCKS5_HOST_UNKNOWN,
                0,
            )
            .await?;
            debug!("Unsupported command: {:?}", cmd);
            Err(Error::Command(cmd))
        }
    }
}

/// Convert `SocketAddr` to `SocksV5Host`.
/// Why is this not in the library?
fn sockaddr_to_socksv5host(addr: &SocketAddr) -> SocksV5Host {
    match addr {
        SocketAddr::V4(addr) => SocksV5Host::Ipv4(addr.ip().octets()),
        SocketAddr::V6(addr) => SocksV5Host::Ipv6(addr.ip().octets()),
    }
}

/// Convert `std::io::Error` to `SocksV5RequestStatus`.
/// Would be nice when io_error_more is stabilized.
#[cfg(nightly)]
fn ioerror_to_socksv5status(e: &std::io::Error) -> socksv5::v5::SocksV5RequestStatus {
    match e.kind() {
        std::io::ErrorKind::NetworkUnreachable => {
            socksv5::v5::SocksV5RequestStatus::NetworkUnreachable
        }
        std::io::ErrorKind::TimedOut => socksv5::v5::SocksV5RequestStatus::TtlExpired,
        std::io::ErrorKind::ConnectionRefused => {
            socksv5::v5::SocksV5RequestStatus::ConnectionRefused
        }
        std::io::ErrorKind::HostUnreachable => socksv5::v5::SocksV5RequestStatus::HostUnreachable,
        _ => socksv5::v5::SocksV5RequestStatus::ServerFailure,
    }
}
#[cfg(not(nightly))]
fn ioerror_to_socksv5status(e: &std::io::Error) -> socksv5::v5::SocksV5RequestStatus {
    match e.raw_os_error() {
        // ENETUNREACH
        Some(101) => socksv5::v5::SocksV5RequestStatus::NetworkUnreachable,
        // ETIMEDOUT
        Some(110) => socksv5::v5::SocksV5RequestStatus::TtlExpired,
        // ECONNREFUSED
        Some(111) => socksv5::v5::SocksV5RequestStatus::ConnectionRefused,
        // EHOSTUNREACH
        Some(113) => socksv5::v5::SocksV5RequestStatus::HostUnreachable,
        // Unhandled error code
        _ => socksv5::v5::SocksV5RequestStatus::ServerFailure,
    }
}
