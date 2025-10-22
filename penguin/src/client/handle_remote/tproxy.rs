//! Support for Linux Transparent Proxy
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::{FatalError, HandlerResources, tcp::request_tcp_channel};
use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, UdpSocket, lookup_host};
use tracing::{debug, info, warn};

fn prepare_sock_socket2(
    sockaddr: SocketAddr,
    ty: Type,
    proto: Protocol,
) -> std::io::Result<(Socket, Domain)> {
    let addrtype = Domain::for_address(sockaddr);
    let socket = Socket::new(addrtype, ty, Some(proto))?;
    socket.set_reuse_address(true)?;
    #[cfg(not(any(
        target_os = "solaris",
        target_os = "illumos",
        target_os = "cygwin",
        target_os = "windows"
    )))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    if addrtype == Domain::IPV4 {
        socket.set_ip_transparent_v4(true)?;
    }
    // `IPV6_TRANSPARENT` not in `socket2` yet
    // rust-lang/socket2#510,#608
    socket.bind(&sockaddr.into())?;
    if ty == Type::STREAM {
        socket.listen(128)?;
    }
    Ok((socket, addrtype))
}

trait UdpOrTcp: Sized {
    const TYPE: Type;
    const PROTO: Protocol;
    fn from_socket(socket: Socket) -> std::io::Result<Self>;

    /// Bind a socket to the given [`SocketAddr`].
    #[inline]
    fn bind_socket2(sockaddr: SocketAddr) -> std::io::Result<(Self, Domain)> {
        let (socket, domain) = prepare_sock_socket2(sockaddr, Self::TYPE, Self::PROTO)?;
        let local_addr = socket
            .local_addr()
            .expect("Failed to get local address of socket (this is a bug)")
            .as_socket()
            .expect("this socket should be `AF_INET` or `AF_INET6` (this is a bug)");
        let listener = Self::from_socket(socket)?;
        info!("Listening on {local_addr}");
        Ok((listener, domain))
    }

    /// Bind and potentially listen on a socket configured for use with TPROXY.
    async fn bind_tproxy(lhost: &str, lport: u16) -> Result<(Self, Domain), FatalError> {
        let addrs = lookup_host((lhost, lport))
            .await
            .map_err(FatalError::ClientIo)?;
        let mut last_err = None;
        for addr in addrs {
            match Self::bind_socket2(addr) {
                Ok((sock, domain)) => {
                    return Ok((sock, domain));
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        Err(FatalError::ClientIo(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "could not resolve to any address",
            )
        })))
    }
}

impl UdpOrTcp for TcpListener {
    const TYPE: Type = Type::STREAM;
    const PROTO: Protocol = Protocol::TCP;
    fn from_socket(socket: Socket) -> std::io::Result<Self> {
        Self::from_std(socket.into())
    }
}

impl UdpOrTcp for UdpSocket {
    const TYPE: Type = Type::DGRAM;
    const PROTO: Protocol = Protocol::UDP;
    fn from_socket(socket: Socket) -> std::io::Result<Self> {
        Self::from_std(socket.into())
    }
}

/// Get the original destination address from a TPROXY socket.
#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "windows",
))]
fn get_tcp_orig_addr(
    stream: TcpStream,
    domain: Domain,
) -> std::io::Result<(TcpStream, Option<SocketAddr>)> {
    // Get the original destination
    let sock = Socket::from(stream.into_std()?);
    let (self_back, orig_dst) = match domain {
        Domain::IPV4 => {
            let addr = sock.original_dst_v4()?;
            (TcpStream::from_std(sock.into())?, addr.as_socket())
        }
        Domain::IPV6 => {
            let addr = sock.original_dst_v6()?;
            (TcpStream::from_std(sock.into())?, addr.as_socket())
        }
        _ => unreachable!("`bind_tproxy` should only return IPv4 or IPv6 domains"),
    };
    Ok((self_back, orig_dst))
}

/// Get the original destination address from a TPROXY socket.
#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "windows",
)))]
fn get_tcp_orig_addr(
    _stream: TcpStream,
    _domain: Domain,
) -> std::io::Result<(TcpStream, Option<SocketAddr>)> {
    Err(std::io::ErrorKind::Unsupported.into())
}

pub(super) async fn handle_tproxy_tcp(
    lhost: &str,
    lport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), FatalError> {
    let (listener, domain) = TcpListener::bind_tproxy(lhost, lport).await?;
    loop {
        // This fails only if main has exited, which is a fatal error.
        let stream_command_tx_permit = handler_resources
            .stream_command_tx
            .reserve()
            .await
            .map_err(|_| FatalError::RequestStream)?;
        // Only `accept` when we have a permit to send a request.
        // This way, the backpressure is propagated to the TCP listener.
        // Not being able to accept a TCP connection is a fatal error.
        let (tcp_stream, _) = listener.accept().await.map_err(FatalError::ClientIo)?;
        let (mut tcp_stream, orig_dst) =
            get_tcp_orig_addr(tcp_stream, domain).map_err(FatalError::ClientIo)?;
        let Some(orig_dst) = orig_dst else {
            warn!("Could not get original destination address; dropping connection");
            continue;
        };
        debug!("Transparent TCP connection to {orig_dst}");
        // `expect`: the main loop should either hold the sender or send a channel
        let mut channel = request_tcp_channel(
            stream_command_tx_permit,
            Bytes::from(orig_dst.ip().to_string()),
            orig_dst.port(),
        )
        .await
        .expect("Main loop dropped sender before sending a channel (this is a bug)");
        tokio::spawn(async move {
            if let Err(error) = tokio::io::copy_bidirectional(&mut channel, &mut tcp_stream).await {
                warn!("TCP forwarder failed: {error}");
            }
        });
    }
}

pub(super) async fn handle_tproxy_udp(
    _lhost: &str,
    _lport: u16,
    _handler_resources: &HandlerResources,
) -> Result<(), FatalError> {
    // Required `IP_RECVORIGDSTADDR` or `IPV6_RECVORIGDSTADDR` socket options are not
    // in `socket2` yet.
    Err(FatalError::TproxyNotEnabled)
}

// There are not many meaningful ways to test Transparent Proxy.
// Most functionality depends on kernel configuration and network setup
mod tests {
    #[tokio::test]
    async fn test_tproxy_tcp_bind() {
        use super::UdpOrTcp;
        let (listener, domain) = tokio::net::TcpListener::bind_tproxy("127.0.0.1", 0)
            .await
            .expect("Failed to bind TPROXY TCP listener");
        assert_eq!(domain, socket2::Domain::IPV4);
        let local_addr = listener.local_addr().expect("Failed to get local address");
        assert_eq!(
            local_addr.ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        let sock = socket2::Socket::from(listener.into_std().unwrap());
        #[cfg(target_os = "linux")]
        assert!(sock.ip_transparent_v4().unwrap());
        #[cfg(not(any(
            target_os = "solaris",
            target_os = "illumos",
            target_os = "cygwin",
            target_os = "windows"
        )))]
        assert!(sock.reuse_port().unwrap());
        assert!(sock.reuse_address().unwrap());
        #[cfg(unix)]
        assert!(sock.nonblocking().unwrap());
    }
}
