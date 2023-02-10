//! Run a remote UDP connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::super::MaybeRetryableError;
use super::FatalError;
use crate::client::HandlerResources;
use crate::{config, Dupe};
use bytes::Bytes;
use penguin_mux::DatagramFrame;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// Handle a UDP Inet->Inet remote.
#[inline]
#[tracing::instrument(skip(handler_resources), level = "debug")]
pub(super) async fn handle_udp(
    lhost: &'static str,
    lport: u16,
    rhost: &'static str,
    rport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), FatalError> {
    // Not being able to bind to the local port is a fatal error.
    let socket = UdpSocket::bind((lhost, lport))
        .await
        .map_err(FatalError::ClientIo)?;
    let socket = Arc::new(socket);
    let local_addr = socket
        .local_addr()
        .map_or(format!("{lhost}:{lport}"), |addr| addr.to_string());
    info!("Bound on {local_addr}");
    loop {
        let mut buf = vec![0; config::MAX_UDP_PACKET_SIZE];
        // `recv_from` can fail if the socket is closed, which is a fatal error.
        let (len, addr) = socket
            .recv_from(&mut buf)
            .await
            .map_err(FatalError::ClientIo)?;
        buf.truncate(len);
        debug!("received {len} bytes from {addr}");
        let client_id = handler_resources
            .add_udp_client(addr, socket.dupe(), false)
            .await;
        let frame = DatagramFrame {
            host: Bytes::from_static(rhost.as_bytes()),
            port: rport,
            sid: client_id,
            data: Bytes::from(buf),
        };
        // This fails only if main has exited, which is a fatal error.
        handler_resources
            .datagram_tx
            .send(frame)
            .await
            .map_err(|_| FatalError::SendDatagram)?;
    }
}

/// Handle a UDP Stdio->Inet remote.
#[inline]
#[tracing::instrument(skip(handler_resources), level = "debug")]
pub(super) async fn handle_udp_stdio(
    rhost: &'static str,
    rport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), FatalError> {
    let mut stdin = BufReader::new(tokio::io::stdin());
    loop {
        let mut line = String::new();
        super::complete_or_continue_if_retryable!(stdin.read_line(&mut line).await);
        let frame = DatagramFrame {
            host: Bytes::from_static(rhost.as_bytes()),
            port: rport,
            sid: 0,
            data: line.into(),
        };
        // This fails only if main has exited, which is a fatal error.
        handler_resources
            .datagram_tx
            .send(frame)
            .await
            .map_err(|_| FatalError::SendDatagram)?;
    }
}
