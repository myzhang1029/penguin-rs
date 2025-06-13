//! Server-side forwarding implementation.
//! Pipes TCP streams or forwards UDP Datagrams to and from another host.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::config;
use penguin_mux::{Datagram, Dupe, MuxStream};
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::mpsc;
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
/// and return the bound socket and the matched target address.
/// Note that we don't connect or send the socket here.
async fn bind_for_target(target: (&str, u16)) -> Result<(UdpSocket, SocketAddr), Error> {
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

/// Sit on a random port, send a UDP datagram to the given target,
/// and wait for a response in the following `UDP_PRUNE_TIMEOUT` seconds.
#[tracing::instrument(skip_all, level = "debug", fields(flow_id = %format_args!("{:08x}", first_datagram_frame.flow_id)))]
pub(super) async fn udp_forward_on(
    first_datagram_frame: Datagram,
    mut datagram_rx: mpsc::Receiver<Datagram>,
    datagram_tx: mpsc::Sender<Datagram>,
) -> Result<(), Error> {
    trace!("got datagram frame: {first_datagram_frame:?}");
    let Datagram {
        target_host: rhost,
        target_port: rport,
        flow_id,
        data,
    } = first_datagram_frame;
    let rhost_str = std::str::from_utf8(&rhost)?;
    let (socket, target) = bind_for_target((rhost_str, rport)).await?;
    socket.send_to(&data, target).await?;
    trace!("sent UDP packet to {target}");
    loop {
        // Reset this timeout each time we see traffic
        let this_round_timeout = tokio::time::sleep(config::UDP_PRUNE_TIMEOUT);
        let mut buf = vec![0; config::MAX_UDP_PACKET_SIZE];
        tokio::select! {
            // Check if the socket has received a datagram
            Ok((len, addr)) = socket.recv_from(&mut buf) => {
                buf.truncate(len);
                trace!("got UDP response from {addr}");
                let frame = Datagram {
                    target_host: rhost.dupe(),
                    target_port: rport,
                    flow_id,
                    data: buf.into(),
                };
                if let Err(error) = datagram_tx.try_send(frame) {
                    match error {
                        mpsc::error::TrySendError::Closed(_) => {
                            // The mux loop has exited
                            trace!("UDP forwarder exiting due to closed mux");
                            break;
                        }
                        mpsc::error::TrySendError::Full(_) => {
                            // The channel is full, so just discard the datagram
                            debug!("UDP forwarder channel is full");
                        }
                    }
                }
            }
            // Check if the channel has received a datagram
            Some(datagram_frame) = datagram_rx.recv() => {
                // If this returns `None`, the mux loop has exited
                // I don't want to handle this case here because
                // the timeout branch will handle it for us anyway.
                let target = (
                    std::str::from_utf8(&datagram_frame.target_host)?,
                    datagram_frame.target_port,
                );
                trace!("got new datagram frame: {datagram_frame:?} for {target:?}");
                socket.send_to(&datagram_frame.data, target).await?;
            }
            // Check if the timeout has expired
            () = this_round_timeout => {
                trace!("UDP prune timeout expired");
                break;
            }
        }
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
#[tracing::instrument(skip_all, level = "debug")]
#[inline]
pub(super) async fn tcp_forwarder_on_channel(channel: MuxStream) -> Result<(), Error> {
    let rhost = std::str::from_utf8(&channel.dest_host)?;
    let rport = channel.dest_port;
    trace!("attempting TCP connect to {rhost} port={rport}");
    let mut rstream = TcpStream::connect((rhost, rport)).await?;
    // Here `rstream` should be connected. Pass the error (unlikely) otherwise
    debug!("TCP forwarding to {}", rstream.peer_addr()?);
    channel.into_copy_bidirectional(&mut rstream).await?;
    trace!("TCP forwarding finished");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_bind_and_send_v4() {
        crate::tests::setup_logging();
        let target_sock = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let target_addr = target_sock.local_addr().unwrap();
        let (socket, target) = bind_for_target(("127.0.0.1", target_addr.port()))
            .await
            .unwrap();
        assert_eq!(target, target_addr);
        socket.send_to(b"hello", target).await.unwrap();
        let mut buf = vec![0; 5];
        let (len, addr) = target_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(addr.port(), socket.local_addr().unwrap().port());
        assert_eq!(buf, b"hello");
        target_sock.send_to(b"world", addr).await.unwrap();
        socket.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"world");
    }

    #[tokio::test]
    async fn test_bind_and_send_v6() {
        crate::tests::setup_logging();
        let target_sock = UdpSocket::bind(("::1", 0)).await.unwrap();
        let target_addr = target_sock.local_addr().unwrap();
        let (socket, target) = bind_for_target(("::1", target_addr.port())).await.unwrap();
        assert_eq!(target, target_addr);
        socket.send_to(b"hello", target).await.unwrap();
        let mut buf = vec![0; 5];
        let (len, addr) = target_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(addr.port(), socket.local_addr().unwrap().port());
        assert_eq!(buf, b"hello");
        target_sock.send_to(b"world", addr).await.unwrap();
        socket.recv(&mut buf).await.unwrap();
        assert_eq!(buf, b"world");
    }

    #[tokio::test]
    async fn test_udp_forward_to_v4() {
        crate::tests::setup_logging();
        let target_sock = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let target_addr = target_sock.local_addr().unwrap();
        let (recv_tx, mut recv_rx) = tokio::sync::mpsc::channel(4);
        let (send_tx, send_rx) = tokio::sync::mpsc::channel(4);
        let datagram_frame = Datagram {
            flow_id: 0,
            target_host: Bytes::from_static(b"127.0.0.1"),
            target_port: target_addr.port(),
            data: Bytes::from_static(b"hello"),
        };
        drop(send_tx);
        let forwarder = tokio::spawn(udp_forward_on(datagram_frame, send_rx, recv_tx));
        let mut buf = vec![0; 5];
        let (len, addr) = target_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(buf, b"hello");
        target_sock.send_to(b"test 1", addr).await.unwrap();
        target_sock.send_to(b"test 2", addr).await.unwrap();
        target_sock.send_to(b"test 3", addr).await.unwrap();
        forwarder.await.unwrap().unwrap();
        let datagram_frame: Datagram = recv_rx.recv().await.unwrap();
        assert_eq!(*datagram_frame.data, *b"test 1");
        let datagram_frame = recv_rx.recv().await.unwrap();
        assert_eq!(*datagram_frame.data, *b"test 2");
        let datagram_frame = recv_rx.recv().await.unwrap();
        assert_eq!(*datagram_frame.data, *b"test 3");
    }

    #[tokio::test]
    async fn test_udp_forward_to_v6() {
        crate::tests::setup_logging();
        let target_sock = UdpSocket::bind(("::1", 0)).await.unwrap();
        let target_addr = target_sock.local_addr().unwrap();
        let (recv_tx, mut recv_rx) = tokio::sync::mpsc::channel(4);
        let (send_tx, send_rx) = tokio::sync::mpsc::channel(4);
        let datagram_frame = Datagram {
            flow_id: 0,
            target_host: Bytes::from_static(b"::1"),
            target_port: target_addr.port(),
            data: Bytes::from_static(b"hello"),
        };
        drop(send_tx);
        let forwarder = tokio::spawn(udp_forward_on(datagram_frame, send_rx, recv_tx));
        let mut buf = vec![0; 5];
        let (len, addr) = target_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(buf, b"hello");
        target_sock.send_to(b"test 1", addr).await.unwrap();
        target_sock.send_to(b"test 2", addr).await.unwrap();
        target_sock.send_to(b"test 3", addr).await.unwrap();
        forwarder.await.unwrap().unwrap();
        let datagram_frame = recv_rx.recv().await.unwrap();
        assert_eq!(*datagram_frame.data, *b"test 1");
        let datagram_frame = recv_rx.recv().await.unwrap();
        assert_eq!(*datagram_frame.data, *b"test 2");
        let datagram_frame = recv_rx.recv().await.unwrap();
        assert_eq!(*datagram_frame.data, *b"test 3");
    }
}
