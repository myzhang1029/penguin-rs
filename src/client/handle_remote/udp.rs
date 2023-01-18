//! Run a remote UDP connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::Error;
use crate::client::{ClientIdMapEntry, HandlerResources};
use crate::mux::{DatagramFrame, IntKey};
use std::ops::Deref;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

/// Handle a UDP Inet->Inet remote.
#[inline]
#[tracing::instrument(skip(handler_resources), level = "debug")]
pub(super) async fn handle_udp(
    lhost: &str,
    lport: u16,
    rhost: &str,
    rport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), Error> {
    let socket = UdpSocket::bind((lhost, lport)).await?;
    let socket = Arc::new(socket);
    info!("Bound on {lhost}:{lport}");
    loop {
        let mut buf = [0u8; 65536];
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let mut udp_client_id_map = handler_resources.udp_client_id_map.write().await;
        let client_id = u32::next_available_key(udp_client_id_map.deref());
        udp_client_id_map.insert(
            client_id,
            ClientIdMapEntry::new(addr, socket.clone(), false),
        );
        drop(udp_client_id_map);
        let frame = DatagramFrame {
            host: rhost.as_bytes().to_vec(),
            port: rport,
            sid: client_id,
            data: buf[..len].to_vec(),
        };
        handler_resources.datagram_tx.send(frame).await?;
    }
}

/// Handle a UDP Stdio->Inet remote.
#[inline]
#[tracing::instrument(skip(handler_resources), level = "debug")]
pub(super) async fn handle_udp_stdio(
    rhost: &str,
    rport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), Error> {
    let mut stdin = BufReader::new(tokio::io::stdin());
    loop {
        let mut line = String::new();
        super::complete_or_continue_if_retryable!(stdin.read_line(&mut line).await);
        let frame = DatagramFrame {
            host: rhost.as_bytes().to_vec(),
            port: rport,
            sid: 0,
            data: line.as_bytes().to_vec(),
        };
        handler_resources.datagram_tx.send(frame).await?;
    }
}
