//! Server-side forwarding implementation.
//! Pipes TCP streams or forwards UDP Datagrams to and from another host.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::{config, Dupe};
use bytes::Bytes;
use penguin_mux::DatagramFrame;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::{
    net::{lookup_host, UdpSocket},
    sync::mpsc::Sender,
};
use tracing::{debug, trace};

/// Error type for the forwarder.
#[derive(Error, Debug)]
pub(super) enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Invalid host: {0}")]
    Host(#[from] std::str::Utf8Error),
}

/// Bind a UDP socket with the same address family as the given target,
/// connect to the target, and send the given data.
/// Finally, return the bound socket and the target address.
#[inline]
async fn bind_and_send(target: (&str, u16), data: &[u8]) -> Result<(UdpSocket, SocketAddr), Error> {
    let targets = lookup_host(target).await?;
    let mut last_err = None;
    for target in targets {
        let socket = match if target.is_ipv4() {
            UdpSocket::bind(("0.0.0.0", 0)).await
        } else {
            UdpSocket::bind(("::", 0)).await
        } {
            Ok(socket) => socket,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        // `expect`: at this point `listener` should be bound. Otherwise, it's a bug.
        let local_addr = socket
            .local_addr()
            .expect("Failed to get local address of UDP socket (this is a bug)");
        debug!("bound to {local_addr}");
        if let Err(e) = socket.connect(target).await {
            last_err = Some(e);
            continue;
        }
        socket.send(data).await?;
        return Ok((socket, target));
    }
    Err(last_err
        .unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "could not resolve to any address",
            )
        })
        .into())
}

/// Send a UDP datagram to the given host and port and wait for a response
/// in the following `UDP_PRUNE_TIMEOUT` seconds.
#[tracing::instrument(skip(datagram_tx), level = "debug")]
pub(super) async fn udp_forward_to(
    datagram_frame: DatagramFrame,
    datagram_tx: Sender<DatagramFrame>,
) -> Result<(), Error> {
    trace!("got datagram frame: {datagram_frame:?}");
    let rhost = datagram_frame.host;
    let rhost_str = std::str::from_utf8(&rhost)?;
    let rport = datagram_frame.port;
    let data = datagram_frame.data;
    let client_id = datagram_frame.sid;
    let (socket, target) = bind_and_send((rhost_str, rport), &data).await?;
    trace!("sent UDP packet to {target}");
    loop {
        let mut buf = vec![0; config::MAX_UDP_PACKET_SIZE];
        match tokio::time::timeout(config::UDP_PRUNE_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                trace!("got UDP response from {target}");
                buf.truncate(len);
                let datagram_frame = DatagramFrame {
                    sid: client_id,
                    host: rhost.dupe(),
                    port: rport,
                    data: Bytes::from(buf),
                };
                if datagram_tx.send(datagram_frame).await.is_err() {
                    // The main loop has exited, so we should exit too.
                    break;
                }
            }
            Ok(Err(e)) => {
                return Err(e.into());
            }
            Err(_) => {
                trace!("UDP prune timeout");
                break;
            }
        };
    }
    debug!("UDP forwarding finished");
    Ok(())
}

/// Start a TCP forwarding server on the given listener.
///
/// This forwarder is trivial: it just pipes the TCP stream to and from the
/// channel.
///
/// # Errors
/// It carries the errors from the underlying TCP or channel IO functions.
#[tracing::instrument(skip(channel), level = "debug")]
pub(super) async fn tcp_forwarder_on_channel(
    mut channel: super::websocket::MuxStream,
) -> Result<(), Error> {
    let rhost = std::str::from_utf8(&channel.dest_host)?;
    let rport = channel.dest_port;
    trace!("attempting TCP connect to {rhost} port={rport}");
    let mut rstream = TcpStream::connect((rhost, rport)).await?;
    debug!("TCP forwarding to {:?}", rstream.peer_addr());
    tokio::io::copy_bidirectional(&mut channel, &mut rstream).await?;
    trace!("TCP forwarding finished");
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_bind_and_send_v4() {
        let target_sock = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let target_addr = target_sock.local_addr().unwrap();
        let (socket, target) = bind_and_send(("127.0.0.1", target_addr.port()), b"hello")
            .await
            .unwrap();
        assert_eq!(target, target_addr);
        let mut buf = vec![0; 5];
        let (len, addr) = target_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(addr, socket.local_addr().unwrap());
        assert_eq!(buf, b"hello");
        target_sock.send_to(b"world", addr).await.unwrap();
        socket.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"world");
    }

    #[tokio::test]
    async fn test_bind_and_send_v6() {
        let target_sock = UdpSocket::bind(("::1", 0)).await.unwrap();
        let target_addr = target_sock.local_addr().unwrap();
        let (socket, target) = bind_and_send(("::1", target_addr.port()), b"hello")
            .await
            .unwrap();
        assert_eq!(target, target_addr);
        let mut buf = vec![0; 5];
        let (len, addr) = target_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(addr, socket.local_addr().unwrap());
        assert_eq!(buf, b"hello");
        target_sock.send_to(b"world", addr).await.unwrap();
        socket.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"world");
    }

    #[tokio::test]
    async fn test_udp_forward_to_v4() {
        let target_sock = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let target_addr = target_sock.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let datagram_frame = DatagramFrame {
            sid: 0,
            host: Bytes::from_static(b"127.0.0.1"),
            port: target_addr.port(),
            data: Bytes::from_static(b"hello"),
        };
        let forwarder = tokio::spawn(udp_forward_to(datagram_frame, tx));
        let mut buf = vec![0; 5];
        let (len, addr) = target_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(buf, b"hello");
        target_sock.send_to(b"test 1", addr).await.unwrap();
        target_sock.send_to(b"test 2", addr).await.unwrap();
        target_sock.send_to(b"test 3", addr).await.unwrap();
        forwarder.await.unwrap().unwrap();
        let datagram_frame = rx.recv().await.unwrap();
        assert_eq!(datagram_frame.data.as_ref(), b"test 1");
        let datagram_frame = rx.recv().await.unwrap();
        assert_eq!(datagram_frame.data.as_ref(), b"test 2");
        let datagram_frame = rx.recv().await.unwrap();
        assert_eq!(datagram_frame.data.as_ref(), b"test 3");
    }

    #[tokio::test]
    async fn test_udp_forward_to_v6() {
        let target_sock = UdpSocket::bind(("::1", 0)).await.unwrap();
        let target_addr = target_sock.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let datagram_frame = DatagramFrame {
            sid: 0,
            host: Bytes::from_static(b"::1"),
            port: target_addr.port(),
            data: Bytes::from_static(b"hello"),
        };
        let forwarder = tokio::spawn(udp_forward_to(datagram_frame, tx));
        let mut buf = vec![0; 5];
        let (len, addr) = target_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(buf, b"hello");
        target_sock.send_to(b"test 1", addr).await.unwrap();
        target_sock.send_to(b"test 2", addr).await.unwrap();
        target_sock.send_to(b"test 3", addr).await.unwrap();
        forwarder.await.unwrap().unwrap();
        let datagram_frame = rx.recv().await.unwrap();
        assert_eq!(datagram_frame.data.as_ref(), b"test 1");
        let datagram_frame = rx.recv().await.unwrap();
        assert_eq!(datagram_frame.data.as_ref(), b"test 2");
        let datagram_frame = rx.recv().await.unwrap();
        assert_eq!(datagram_frame.data.as_ref(), b"test 3");
    }
}
