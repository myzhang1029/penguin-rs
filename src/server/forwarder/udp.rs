//! Forwards UDP Datagrams to and from another host.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::mux::DatagramFrame;
use tokio::{
    net::{lookup_host, UdpSocket},
    sync::mpsc::Sender,
    time,
};
use tracing::trace;

const UDP_PRUNE_TIMEOUT: time::Duration = time::Duration::from_secs(60);

/// Send a UDP datagram to the given host and port and wait for a response
/// in the following `UDP_PRUNE_TIMEOUT` seconds.
pub(in super::super) async fn udp_forward_to(
    datagram_frame: DatagramFrame,
    datagram_tx: Sender<DatagramFrame>,
) -> Result<(), super::Error> {
    trace!("got datagram frame: {datagram_frame:?}");
    let rhost = datagram_frame.host;
    let rhost = String::from_utf8(rhost)?;
    let rport = datagram_frame.port;
    let data = datagram_frame.data;
    let client_id = datagram_frame.sid;
    let target = lookup_host((&*rhost, rport)).await?.next().unwrap();
    let socket = if target.is_ipv4() {
        UdpSocket::bind("0.0.0.0:0").await?
    } else {
        UdpSocket::bind("[::]:0").await?
    };
    socket.send_to(&data, target).await?;
    loop {
        let mut buf = [0u8; 65536];
        tokio::select! {
            _ = time::sleep(UDP_PRUNE_TIMEOUT) => {
                trace!("UDP prune timeout");
                break;
            }
            result = socket.recv_from(&mut buf) => {
                let (len, addr) = result?;
                if addr == target {
                    trace!("got UDP response from {addr}");
                    let datagram_frame = DatagramFrame {
                        sid: client_id,
                        host: rhost.into_bytes(),
                        port: rport,
                        data: buf[..len].to_vec(),
                    };
                    datagram_tx.send(datagram_frame).await?;
                    break;
                }
            }
        }
    }
    Ok(())
}
