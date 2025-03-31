//! Support for Linux Transparent Proxy
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::net::SocketAddr;

use super::{tcp::request_tcp_channel, FatalError, HandlerResources};
use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{lookup_host, TcpListener};
use tracing::{info, warn};

async fn bind_tcp_socket2(sockaddr: SocketAddr) -> std::io::Result<TcpListener> {
    let addrtype = Domain::for_address(sockaddr);
    let socket = Socket::new(addrtype, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.set_ip_transparent(true)?;
    socket.bind(&sockaddr.into())?;
    socket.listen(128)?;
    Ok(TcpListener::from_std(socket.into())?)
}

pub(super) async fn start_tproxy_listener(
    lhost: &str,
    lport: u16,
    handler_resources: &HandlerResources,
) -> Result<TcpListener, FatalError> {
    let addrs = lookup_host((lhost, lport))
        .await
        .map_err(FatalError::ClientIo)?;
    let mut last_err = None;
    for addr in addrs {
        match bind_tcp_socket2(addr).await {
            Ok(listener) => {
                let local_addr = listener
                    .local_addr()
                    .map_or(format!("{lhost}:{lport}"), |addr| addr.to_string());
                info!("Listening on {local_addr}");
                return Ok(listener);
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

pub(super) async fn handle_tproxy_tcp(
    lhost: &str,
    lport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), FatalError> {
    let listener = start_tproxy_listener(lhost, lport, handler_resources).await?;
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
        let (mut tcp_stream, _) = listener.accept().await.map_err(FatalError::ClientIo)?;
        // Tproxy converts the destination address to our local address.
        let target_addr = tcp_stream
            .local_addr()
            .map_err(|e| FatalError::ClientIo(e.into()))?;
        let target_ip = target_addr.ip();
        let target_port = target_addr.port();
        // `expect`: the main loop should either hold the sender or send a channel
        let mut channel = request_tcp_channel(
            stream_command_tx_permit,
            Bytes::from(target_ip.to_string()),
            target_port,
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
    lhost: &str,
    lport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), FatalError> {
    todo!()
}
