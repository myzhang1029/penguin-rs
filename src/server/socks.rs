//! SOCKS 5 server.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::mux::WebSocket as MuxWebSocket;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_stream_multiplexor::MuxListener;
use warp::{
    ws::{Message, WebSocket},
    Error as WarpError,
};

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
    #[error("{0}")]
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
pub async fn start_socks_server_on_listener(
    listener: MuxListener<MuxWebSocket<WebSocket, Message, WarpError>>,
) {
    // Loop forever so that clients can reconnect.
    loop {
        let chan = listener.accept().await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(chan);
        let mut server_socket = handshake(&mut reader, &mut writer).await.unwrap();
        let mut chan = reader.unsplit(writer);
        tokio::io::copy_bidirectional(&mut server_socket, &mut chan)
            .await
            .unwrap();
    }
}

async fn handshake<R, W>(mut reader: R, mut writer: W) -> Result<TcpStream, Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if socksv5::read_version(&mut reader).await? != socksv5::SocksVersion::V5 {
        return Err(Error::Socksv4);
    }
    let handshake = socksv5::v5::read_handshake_skip_version(&mut reader).await?;

    if !handshake
        .methods
        .into_iter()
        .any(|m| m == socksv5::v5::SocksV5AuthMethod::Noauth)
    {
        return Err(Error::OtherAuth);
    }

    socksv5::v5::write_auth_method(&mut writer, socksv5::v5::SocksV5AuthMethod::Noauth).await?;

    let request = socksv5::v5::read_request(&mut reader).await?;

    match request.command {
        socksv5::v5::SocksV5Command::Connect => {
            let host = match request.host {
                socksv5::v5::SocksV5Host::Ipv4(ip) => {
                    SocketAddr::new(IpAddr::V4(ip.into()), request.port)
                }
                socksv5::v5::SocksV5Host::Ipv6(ip) => {
                    SocketAddr::new(IpAddr::V6(ip.into()), request.port)
                }
                socksv5::v5::SocksV5Host::Domain(domain) => {
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
                    socksv5::v5::write_request_status(
                        &mut writer,
                        socksv5::v5::SocksV5RequestStatus::Success,
                        socksv5::v5::SocksV5Host::Ipv4([0, 0, 0, 0]),
                        0,
                    )
                    .await?;
                    Ok(server_socket)
                }
                Err(e) => {
                    // Unix error codes.
                    let status = match e.raw_os_error() {
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
                    };
                    socksv5::v5::write_request_status(
                        &mut writer,
                        status,
                        socksv5::v5::SocksV5Host::Ipv4([0, 0, 0, 0]),
                        0,
                    )
                    .await?;
                    Err(Error::Connect)
                }
            }
        }
        cmd => {
            socksv5::v5::write_request_status(
                &mut writer,
                socksv5::v5::SocksV5RequestStatus::CommandNotSupported,
                socksv5::v5::SocksV5Host::Ipv4([0, 0, 0, 0]),
                0,
            )
            .await?;
            Err(Error::Command(cmd))
        }
    }
}
