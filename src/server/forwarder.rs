//! Server-side forwarding implementation.
//! Pipes TCP streams or forwards UDP Datagrams to and from another host.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::config;
use crate::mux::DatagramFrame;
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
    #[error("invalid host: {0}")]
    Host(#[from] std::str::Utf8Error),
    #[error("cannot send `DatagramFrame` to main loop: {0}")]
    DatagramSend(#[from] tokio::sync::mpsc::error::SendError<crate::mux::DatagramFrame>),
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
    let target = lookup_host((rhost_str, rport))
        .await?
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "could not resolve to any address",
            )
        })?;
    let socket = if target.is_ipv4() {
        UdpSocket::bind(("0.0.0.0", 0)).await?
    } else {
        UdpSocket::bind(("::", 0)).await?
    };
    debug!("bound to {}", socket.local_addr()?);
    socket.connect(target).await?;
    socket.send(&data).await?;
    trace!("sent UDP packet to {target}");
    loop {
        let mut buf = [0u8; 65536];
        match tokio::time::timeout(config::UDP_PRUNE_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                trace!("got UDP response from {target}");
                let datagram_frame = DatagramFrame {
                    sid: client_id,
                    host: rhost.clone(),
                    port: rport,
                    data: buf[..len].to_vec(),
                };
                datagram_tx.send(datagram_frame).await?;
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
    debug!("TCP forwarding to {}:{}", rhost, rport);
    let mut rstream = TcpStream::connect((rhost, rport)).await?;
    trace!("connected to {:?}", rstream.peer_addr());
    tokio::io::copy_bidirectional(&mut channel, &mut rstream).await?;
    trace!("TCP forwarding finished");
    Ok(())
}
