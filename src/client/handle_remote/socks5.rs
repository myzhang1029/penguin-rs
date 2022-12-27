//! SOCKS 5 server.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::net::IpAddr;
use std::sync::Arc;

use super::tcp::channel_tcp_handshake;
use super::udp::channel_udp_handshake;
use super::Command;
use super::{request_channel, Error};
use crate::mux::pipe_streams;
use tokio::net::UdpSocket;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::mpsc,
};
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
                return Err(e.into());
            }
        }
    };
}

/// Handle a SOCKS5 connection.
/// Based on socksv5's example.
/// We need to be able to request additional channels, so we need `command_tx`
#[tracing::instrument(skip_all, level = "debug")]
pub(crate) async fn handle_socks_connection<R, W>(
    command_tx: mpsc::Sender<Command>,
    reader: R,
    mut writer: W,
    local_addr: String,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut breader = BufReader::new(reader);
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
        writer.write_all(&[0x05, 0xFF]).await?;
        return Err(Error::OtherAuth);
    }
    // Send back NO AUTHENTICATION REQUIRED
    writer.write_all(&[0x05, 0x00]).await?;
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
        &mut writer
    );
    let _reserved = execute_or_pass_error!(
        breader.read_u8().await,
        0x01,
        "cannot read reserved",
        &mut writer
    );
    let address_type = execute_or_pass_error!(
        breader.read_u8().await,
        0x01,
        "cannot read address type",
        &mut writer
    );
    let rhost = match address_type {
        0x01 => {
            // IPv4
            let mut addr = [0; 4];
            execute_or_pass_error!(
                breader.read_exact(&mut addr).await,
                0x01,
                "cannot read address",
                &mut writer
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
                &mut writer
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
                &mut writer
            );
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => {
            debug!("invalid address type {address_type}");
            writer
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            return Err(Error::SocksRequest);
        }
    };
    let rport = execute_or_pass_error!(
        breader.read_u16().await,
        0x01,
        "cannot read port",
        &mut writer
    );
    debug!("got request {command} for {rhost}:{rport}");
    match command {
        0x01 => {
            // CONNECT
            handle_connect(&command_tx, breader, writer, rhost, rport).await
        }
        0x02 => {
            // BIND
            // We don't support this because I can't ask the remote host to bind
            warn!("BIND is not supported");
            writer
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            Err(Error::SocksRequest)
        }
        0x03 => {
            // UDP ASSOCIATE
            handle_associate(&command_tx, breader, writer, rhost, rport, local_addr).await
        }
        _ => {
            warn!("invalid command {command}");
            writer
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            Err(Error::SocksRequest)
        }
    }
}

async fn handle_connect<R, W>(
    command_tx: &mpsc::Sender<Command>,
    reader: R,
    mut writer: W,
    rhost: String,
    rport: u16,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Establish a connection to the remote host
    let channel = execute_or_pass_error!(
        request_channel(command_tx).await,
        0x01,
        "cannot get channel",
        &mut writer
    );
    let (mut remote_rx, mut remote_tx) = tokio::io::split(channel);
    execute_or_pass_error!(
        channel_tcp_handshake(&mut remote_rx, &mut remote_tx, &rhost, rport).await,
        0x01,
        "cannot handshate on the channel",
        &mut writer
    );
    // Send back a successful response
    writer
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;
    pipe_streams(reader, writer, remote_rx, remote_tx).await?;
    Ok(())
}

async fn handle_associate<R, W>(
    command_tx: &mpsc::Sender<Command>,
    mut reader: R,
    mut writer: W,
    rhost: String,
    rport: u16,
    local_addr: String,
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
    let relay_task = tokio::spawn(udp_relay(rhost, rport, command_tx.clone(), socket));
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

async fn udp_relay(
    rhost: String,
    rport: u16,
    command_tx: mpsc::Sender<Command>,
    socket: UdpSocket,
) -> Result<(), Error> {
    let dest_is_specified =
        rhost != "0.0.0.0" && rhost != "0000:0000:0000:0000:0000:0000:0000:0000" && rport != 0;
    let arc_socket = Arc::new(socket);
    if dest_is_specified {
        let channel = request_channel(&command_tx).await?;
        let (mut channel_rx, mut channel_tx) = tokio::io::split(channel);
        channel_udp_handshake(&mut channel_rx, &mut channel_tx, &rhost, rport).await?;
        loop {
            let mut buf = [0; 65536];
            let (dst, dport, data, len, src, sport) =
                match handle_udp_relay_header(arc_socket.clone(), &mut buf).await? {
                    Some(x) => x,
                    None => continue,
                };
            if dst != rhost || dport != rport {
                warn!("Dropping datagram to invalid destination {dst}:{dport}");
                continue;
            }
            debug!("relaying UDP datagram from {src}:{sport} to {dst}:{dport}");
            channel_tx.write_u32(len as u32).await?;
            channel_tx.write_all(data).await?;
            trace!("sent to channel ({len} bytes)");
            channel_tx.flush().await?;
            let len = channel_rx.read_u32().await? as usize;
            channel_rx.read_exact(&mut buf[..len]).await?;
            trace!("received from channel ({len} bytes)");
            // Write the header
            let (target_addr, target_atyp) = match src {
                IpAddr::V4(ip) => (ip.octets().to_vec(), 0x01),
                IpAddr::V6(ip) => (ip.octets().to_vec(), 0x04),
            };
            let mut content = vec![0, 0, 0, target_atyp];
            content.extend_from_slice(&target_addr);
            content.extend_from_slice(&sport.to_be_bytes());
            content.extend_from_slice(&buf[..len]);
            arc_socket.send_to(&content, (src, sport)).await?;
        }
    } else {
        // Fallback mode: establish a new connection for each packet
        loop {
            let mut buf = [0; 65536];
            let (dst, dport, data, len, src, sport) =
                match handle_udp_relay_header(arc_socket.clone(), &mut buf).await? {
                    Some(x) => x,
                    None => continue,
                };
            let channel = request_channel(&command_tx).await?;
            let (mut channel_rx, mut channel_tx) = tokio::io::split(channel);
            channel_udp_handshake(&mut channel_rx, &mut channel_tx, &dst, dport).await?;
            handle_udp_relay_response(
                &mut channel_rx,
                &mut channel_tx,
                arc_socket.clone(),
                len,
                src,
                sport,
                data,
            )
            .await?;
        }
    }
}

/// Parse a UDP relay request
async fn handle_udp_relay_header(
    socket: Arc<UdpSocket>,
    buf: &mut [u8],
) -> Result<Option<(String, u16, &[u8], usize, IpAddr, u16)>, Error> {
    // XXX: Note that we block on reading from the channel. This means that
    // only one client can use the channel at a time.
    let (len, addr) = socket.recv_from(buf).await?;
    let _reserved = &buf[..2];
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
            let port = ((buf[8] as u16) << 8) | (buf[9] as u16);
            (dst, port, 10)
        }
        0x03 => {
            // Domain name
            let len = buf[4] as usize;
            let dst = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            let port = ((buf[5 + len] as u16) << 8) | (buf[6 + len] as u16);
            (dst, port, 7 + len)
        }
        0x04 => {
            // IPv6
            let dst = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                ((buf[4] as u16) << 8) | (buf[5] as u16),
                ((buf[6] as u16) << 8) | (buf[7] as u16),
                ((buf[8] as u16) << 8) | (buf[9] as u16),
                ((buf[10] as u16) << 8) | (buf[11] as u16),
                ((buf[12] as u16) << 8) | (buf[13] as u16),
                ((buf[14] as u16) << 8) | (buf[15] as u16),
                ((buf[16] as u16) << 8) | (buf[17] as u16),
                ((buf[18] as u16) << 8) | (buf[19] as u16),
            );
            let port = ((buf[20] as u16) << 8) | (buf[21] as u16);
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
async fn handle_udp_relay_response<R, W>(
    mut channel_rx: R,
    mut channel_tx: W,
    socket: Arc<UdpSocket>,
    len: usize,
    src: IpAddr,
    sport: u16,
    data: &[u8],
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    channel_tx.write_u32(len as u32).await?;
    channel_tx.write_all(data).await?;
    channel_tx.flush().await?;
    let len = channel_rx.read_u32().await? as usize;
    let mut buf = vec![0; len];
    channel_rx.read_exact(&mut buf).await?;
    // Write the header
    let (target_addr, target_atyp) = match src {
        IpAddr::V4(ip) => (ip.octets().to_vec(), 0x01),
        IpAddr::V6(ip) => (ip.octets().to_vec(), 0x04),
    };
    let mut content = vec![0, 0, 0, target_atyp];
    content.extend_from_slice(&target_addr);
    content.extend_from_slice(&sport.to_be_bytes());
    content.extend_from_slice(&buf);
    socket.send_to(&content, (src, sport)).await?;
    Ok(())
}
