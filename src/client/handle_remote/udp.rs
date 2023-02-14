//! Run a remote UDP connection.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::FatalError;
use crate::client::HandlerResources;
use crate::{config, Dupe};
use bytes::Bytes;
use penguin_mux::DatagramFrame;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;
use tracing::{debug, info};

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
    // `expect`: at this point `listener` should be bound. Otherwise, it's a bug.
    let local_addr = socket
        .local_addr()
        .expect("Failed to get local address of UDP socket (this is a bug)");
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
        // We should stop if we fail to read from stdin.
        stdin
            .read_line(&mut line)
            .await
            .map_err(FatalError::ClientIo)?;
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::client::ClientIdMaps;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn test_handle_udp() {
        let (datagram_tx, mut datagram_rx) = tokio::sync::mpsc::channel(1);
        let (stream_command_tx, _) = tokio::sync::mpsc::channel(1);
        let udp_client_map = Arc::new(RwLock::new(ClientIdMaps::new()));
        let handler_resources = HandlerResources {
            datagram_tx,
            stream_command_tx,
            udp_client_map: udp_client_map.dupe(),
        };
        static LHOST: &'static str = "127.0.0.1";
        static RHOST: &'static str = "127.0.0.1";
        let forwarding_task =
            tokio::spawn(
                async move { handle_udp(LHOST, 14196, RHOST, 255, &handler_resources).await },
            );
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        socket.connect("127.0.0.1:14196").await.unwrap();
        socket.send(b"hello").await.unwrap();
        let frame = datagram_rx.recv().await.unwrap();
        assert_eq!(frame.host, Bytes::from_static(RHOST.as_bytes()));
        assert_eq!(frame.port, 255);
        assert_eq!(frame.data, Bytes::from("hello"));
        let client_id = *udp_client_map
            .read()
            .await
            .client_addr_map
            .get(&(local_addr, ([127, 0, 0, 1], 14196).into()))
            .unwrap();
        assert_eq!(frame.sid, client_id);
        forwarding_task.abort();
    }
}
