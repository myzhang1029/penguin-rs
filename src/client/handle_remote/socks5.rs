//! SOCKS 5 server.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::tcp::request_tcp_channel;
use super::{pipe_streams, Error, HandlerResources};
use crate::client::ClientIdMapEntry;
use crate::mux::{DatagramFrame, IntKey};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::BufWriter;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

/// Execute an expression, and if it returns an error, write an error response to the client and return the error.
///
/// $ex: The expression to execute
/// $err: The error code to send to the client (RFC 1928)
/// $edesc: The error description to log
/// $writer: The writer to write the error response to
macro_rules! execute_or_pass_error {
    ($ex:expr, $err:literal, $edesc:literal, $writer:expr) => {
        match $ex {
            Ok(v) => v,
            Err(e) => {
                $writer
                    .write_all(&[0x05, $err, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .await?;
                $writer.flush().await?;
                return Err(e.into());
            }
        }
    };
}

/// Handle a SOCKS5 connection.
/// Based on socksv5's example.
/// We need to be able to request additional channels, so we need `command_tx`
#[tracing::instrument(skip_all, level = "debug")]
pub(super) async fn handle_socks_connection<R, W>(
    reader: R,
    writer: W,
    local_addr: &str,
    handler_resources: &HandlerResources,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut breader = BufReader::new(reader);
    let mut bwriter = BufWriter::new(writer);
    // Complete the handshake
    let version = breader.read_u8().await?;
    if version != 5 {
        debug!("client is not SOCKSv5");
        return Err(Error::Socksv4);
    }
    let nmethods = breader.read_u8().await?;
    let mut methods = vec![0; nmethods as usize];
    breader.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        debug!("client does not support NOAUTH");
        // Send back NO ACCEPTABLE METHODS
        // Note that we are not compliant with RFC 1928 here, as we MUST
        // support GSSAPI and SHOULD support USERNAME/PASSWORD
        bwriter.write_all(&[0x05, 0xFF]).await?;
        bwriter.flush().await?;
        return Err(Error::OtherAuth);
    }
    // Send back NO AUTHENTICATION REQUIRED
    bwriter.write_all(&[0x05, 0x00]).await?;
    bwriter.flush().await?;
    // Read the request
    let version = breader.read_u8().await?;
    if version != 5 {
        debug!("client is not SOCKSv5");
        return Err(Error::Socksv4);
    }
    let command = execute_or_pass_error!(
        breader.read_u8().await,
        0x01,
        "cannot read command",
        &mut bwriter
    );
    trace!("command: {command}");
    let _reserved = execute_or_pass_error!(
        breader.read_u8().await,
        0x01,
        "cannot read reserved",
        &mut bwriter
    );
    let address_type = execute_or_pass_error!(
        breader.read_u8().await,
        0x01,
        "cannot read address type",
        &mut bwriter
    );
    trace!("address type: {address_type}");
    let rhost = match address_type {
        0x01 => {
            // IPv4
            let mut addr = [0; 4];
            execute_or_pass_error!(
                breader.read_exact(&mut addr).await,
                0x01,
                "cannot read address",
                &mut bwriter
            );
            std::net::Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            // Domain name
            let len = breader.read_u8().await?;
            let mut addr = vec![0; len as usize];
            execute_or_pass_error!(
                breader.read_exact(&mut addr).await,
                0x01,
                "cannot read domain",
                &mut bwriter
            );
            String::from_utf8(addr)?
        }
        0x04 => {
            // IPv6
            let mut addr = [0; 16];
            execute_or_pass_error!(
                breader.read_exact(&mut addr).await,
                0x01,
                "cannot read address",
                &mut bwriter
            );
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => {
            debug!("invalid address type {address_type}");
            bwriter
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            bwriter.flush().await?;
            return Err(Error::SocksRequest);
        }
    };
    let rport = execute_or_pass_error!(
        breader.read_u16().await,
        0x01,
        "cannot read port",
        &mut bwriter
    );
    debug!("got request {command} for {rhost}:{rport}");
    match command {
        0x01 => {
            // CONNECT
            handle_connect(breader, bwriter, &rhost, rport, handler_resources).await
        }
        0x02 => {
            // BIND
            // We don't support this because I can't ask the remote host to bind
            warn!("BIND is not supported");
            bwriter
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            bwriter.flush().await?;
            Err(Error::SocksRequest)
        }
        0x03 => {
            // UDP ASSOCIATE
            handle_associate(
                breader,
                bwriter,
                &rhost,
                rport,
                local_addr,
                handler_resources,
            )
            .await
        }
        _ => {
            warn!("invalid command {command}");
            bwriter
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            bwriter.flush().await?;
            Err(Error::SocksRequest)
        }
    }
}

async fn handle_connect<R, W>(
    reader: R,
    mut writer: W,
    rhost: &str,
    rport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Establish a connection to the remote host
    let channel = execute_or_pass_error!(
        request_tcp_channel(&handler_resources.stream_command_tx, rhost.into(), rport).await,
        0x01,
        "cannot get channel",
        &mut writer
    );
    // Send back a successful response
    writer
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;
    writer.flush().await?;
    let (remote_rx, remote_tx) = tokio::io::split(channel);
    pipe_streams(reader, writer, remote_rx, remote_tx).await?;
    Ok(())
}

async fn handle_associate<R, W>(
    mut reader: R,
    mut writer: W,
    rhost: &str,
    rport: u16,
    local_addr: &str,
    handler_resources: &HandlerResources,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let socket = execute_or_pass_error!(
        UdpSocket::bind((local_addr, 0)).await,
        0x01,
        "cannot get udp socket",
        &mut writer
    );
    let sock_local_addr = execute_or_pass_error!(
        socket.local_addr(),
        0x01,
        "cannot get local address",
        &mut writer
    );
    let local_port = sock_local_addr.port().to_be_bytes();
    let local_ip = sock_local_addr.ip();
    let relay_task = tokio::spawn(udp_relay(
        rhost.to_string(),
        rport,
        handler_resources.clone(),
        socket,
    ));
    // Send back a successful response
    match local_ip {
        IpAddr::V4(ip) => {
            writer
                .write_all(&[
                    0x05,
                    0x00,
                    0x00,
                    0x01,
                    ip.octets()[0],
                    ip.octets()[1],
                    ip.octets()[2],
                    ip.octets()[3],
                    local_port[0],
                    local_port[1],
                ])
                .await?;
        }
        IpAddr::V6(ip) => {
            writer
                .write_all(&[
                    0x05,
                    0x00,
                    0x00,
                    0x04,
                    ip.octets()[0],
                    ip.octets()[1],
                    ip.octets()[2],
                    ip.octets()[3],
                    ip.octets()[4],
                    ip.octets()[5],
                    ip.octets()[6],
                    ip.octets()[7],
                    ip.octets()[8],
                    ip.octets()[9],
                    ip.octets()[10],
                    ip.octets()[11],
                    ip.octets()[12],
                    ip.octets()[13],
                    ip.octets()[14],
                    ip.octets()[15],
                    local_port[0],
                    local_port[1],
                ])
                .await?;
        }
    }
    // My crude way to detect when the client closes the connection
    reader.read(&mut [0; 1]).await.ok();
    relay_task.abort();
    Ok(())
}

/// UDP task spawned by the TCP connection
#[allow(clippy::similar_names)]
async fn udp_relay(
    _rhost: String,
    _rport: u16,
    handler_resources: HandlerResources,
    socket: UdpSocket,
) -> Result<(), Error> {
    let socket = Arc::new(socket);
    loop {
        let mut buf = [0; 65536];
        let Some((dst, dport, data, len, src, sport)) = handle_udp_relay_header(&socket, &mut buf).await? else {
            continue
        };
        let mut udp_client_id_map = handler_resources.udp_client_id_map.write().await;
        let client_id = u32::next_available_key(&*udp_client_id_map);
        udp_client_id_map.insert(
            client_id,
            ClientIdMapEntry::new((src, sport).into(), socket.clone(), true),
        );
        drop(udp_client_id_map);
        let datagram_frame = DatagramFrame {
            host: dst.into(),
            port: dport,
            sid: client_id,
            data: data[..len].to_vec(),
        };
        handler_resources.datagram_tx.send(datagram_frame).await?;
    }
}

/// Parse a UDP relay request
async fn handle_udp_relay_header<'buf>(
    socket: &UdpSocket,
    buf: &'buf mut [u8],
) -> Result<Option<(String, u16, &'buf [u8], usize, IpAddr, u16)>, Error> {
    let (len, addr) = socket.recv_from(buf).await?;
    // let _reserved = &buf[..2];
    let frag = buf[2];
    if frag != 0 {
        warn!("Fragmented UDP packets are not implemented");
        return Ok(None);
    }
    let atyp = buf[3];
    let (dst, port, processed) = match atyp {
        0x01 => {
            // IPv4
            let dst = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = (u16::from(buf[8]) << 8) | u16::from(buf[9]);
            (dst, port, 10)
        }
        0x03 => {
            // Domain name
            let len = buf[4] as usize;
            let dst = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            let port = (u16::from(buf[5 + len]) << 8) | u16::from(buf[6 + len]);
            (dst, port, 7 + len)
        }
        0x04 => {
            // IPv6
            let dst = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                (u16::from(buf[4]) << 8) | u16::from(buf[5]),
                (u16::from(buf[6]) << 8) | u16::from(buf[7]),
                (u16::from(buf[8]) << 8) | u16::from(buf[9]),
                (u16::from(buf[10]) << 8) | u16::from(buf[11]),
                (u16::from(buf[12]) << 8) | u16::from(buf[13]),
                (u16::from(buf[14]) << 8) | u16::from(buf[15]),
                (u16::from(buf[16]) << 8) | u16::from(buf[17]),
                (u16::from(buf[18]) << 8) | u16::from(buf[19]),
            );
            let port = (u16::from(buf[20]) << 8) | u16::from(buf[21]);
            (dst, port, 22)
        }
        _ => {
            warn!("Dropping datagram with invalid address type {atyp}");
            return Ok(None);
        }
    };
    Ok(Some((
        dst,
        port,
        &buf[processed..len],
        len - processed,
        addr.ip(),
        addr.port(),
    )))
}

/// Send a UDP relay response
pub(crate) async fn send_udp_relay_response(
    socket: &UdpSocket,
    target: &SocketAddr,
    data: &[u8],
) -> std::io::Result<()> {
    // Write the header
    let (target_addr, target_atyp) = match target.ip() {
        IpAddr::V4(ip) => (ip.octets().to_vec(), 0x01),
        IpAddr::V6(ip) => (ip.octets().to_vec(), 0x04),
    };
    let mut content = vec![0, 0, 0, target_atyp];
    content.extend_from_slice(&target_addr);
    content.extend_from_slice(&target.port().to_be_bytes());
    content.extend_from_slice(data);
    socket.send_to(&content, target).await?;
    Ok(())
}
