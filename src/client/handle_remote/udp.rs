//! Run a remote UDP connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::super::MaybeRetryableError;
use super::Error;
use crate::client::{ClientIdMapEntry, HandlerResources};
use crate::dupe::Dupe;
use crate::mux::{DatagramFrame, IntKey};
use bytes::{Bytes, BytesMut};
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
) -> Result<(), Error> {
    let socket = UdpSocket::bind((lhost, lport)).await?;
    let socket = Arc::new(socket);
    let local_addr = socket
        .local_addr()
        .map_or(format!("{lhost}:{lport}"), |addr| addr.to_string());
    info!("Bound on {local_addr}");
    loop {
        let mut buf = BytesMut::zeroed(65536);
        let (len, addr) = socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        debug!("received {len} bytes from {addr}");
        let mut udp_client_id_map = handler_resources.udp_client_id_map.write().await;
        let client_id = u32::next_available_key(&*udp_client_id_map);
        udp_client_id_map.insert(client_id, ClientIdMapEntry::new(addr, socket.dupe(), false));
        drop(udp_client_id_map);
        let frame = DatagramFrame {
            host: Bytes::from_static(rhost.as_bytes()),
            port: rport,
            sid: client_id,
            data: buf.freeze(),
        };
        handler_resources
            .datagram_tx
            .send(frame)
            .await
            .map_err(|_| Error::SendDatagram)?;
    }
}

/// Handle a UDP Stdio->Inet remote.
#[inline]
#[tracing::instrument(skip(handler_resources), level = "debug")]
pub(super) async fn handle_udp_stdio(
    rhost: &'static str,
    rport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), Error> {
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
        handler_resources
            .datagram_tx
            .send(frame)
            .await
            .map_err(|_| Error::SendDatagram)?;
    }
}
