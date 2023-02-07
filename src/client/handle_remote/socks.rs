//! SOCKS 5 server.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::tcp::{open_tcp_listener, request_tcp_channel};
use super::{pipe_streams, Error, HandlerResources};
use crate::client::{ClientIdMapEntry, StreamCommand};
use crate::Dupe;
use bytes::{Buf, Bytes, BytesMut};
use penguin_mux::{DatagramFrame, IntKey};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufWriter};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

macro_rules! v5_reply {
    ($rep:expr) => {
        &[0x05, $rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    };
}

macro_rules! v4_reply {
    ($rep:expr) => {
        &[0x00, $rep, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    };
}

/// Execute an expression, and if it returns an error, write an error response to the client and return the error.
///
/// $ex: The expression to execute
/// $err: The error code to send to the client (RFC 1928)
/// $edesc: The error description to log
/// $writer: The writer to write the error response to
macro_rules! exec_or_ret_err_v5 {
    ($ex:expr, $edesc:literal, $writer:expr) => {
        match $ex {
            Ok(v) => v,
            Err(e) => {
                info!("{}: {}", $edesc, e);
                $writer.write_all(v5_reply!(0x01)).await?;
                $writer.flush().await?;
                return Err(e.into());
            }
        }
    };
}
macro_rules! exec_or_ret_err_v4 {
    ($ex:expr, $edesc:literal, $writer:expr) => {
        match $ex {
            Ok(v) => v,
            Err(e) => {
                info!("{}: {}", $edesc, e);
                $writer.write_all(v4_reply!(0x5b)).await?;
                $writer.flush().await?;
                return Err(e.into());
            }
        }
    };
}

#[tracing::instrument(skip(handler_resources), level = "debug")]
#[inline]
pub(super) async fn handle_socks(
    lhost: &'static str,
    lport: u16,
    handler_resources: &HandlerResources,
) -> Result<(), Error> {
    let listener = open_tcp_listener(lhost, lport).await?;
    loop {
        let (tcp_stream, _) = listener.accept().await?;
        let (tcp_rx, tcp_tx) = tokio::io::split(tcp_stream);
        let handler_resources = handler_resources.dupe();
        // TODO: handle errors: a failed stream request failed should propagate
        tokio::spawn(async move {
            handle_socks_connection(tcp_rx, tcp_tx, lhost, &handler_resources).await
        });
    }
}

/// Handle a SOCKS5 connection.
/// Based on socksv5's example.
/// We need to be able to request additional channels, so we need `command_tx`
#[tracing::instrument(skip_all, level = "trace")]
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
    let bwriter = BufWriter::new(writer);
    let version = breader.read_u8().await?;
    match version {
        4 => {
            // SOCKS4
            handle_socks4_connection(breader, bwriter, handler_resources).await
        }
        5 => {
            // SOCKS5
            handle_socks5_connection(breader, bwriter, local_addr, handler_resources).await
        }
        version => {
            info!("client is not SOCKSv4 or SOCKSv5");
            Err(Error::SocksVersion(version))
        }
    }
}

async fn handle_socks4_connection<R, W>(
    mut breader: R,
    mut bwriter: W,
    handler_resources: &HandlerResources,
) -> Result<(), Error>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let command = exec_or_ret_err_v4!(breader.read_u8().await, "cannot read command", &mut bwriter);
    let rport = exec_or_ret_err_v4!(breader.read_u16().await, "cannot read port", &mut bwriter);
    let ip = exec_or_ret_err_v4!(breader.read_u32().await, "cannot read ip", &mut bwriter);
    let mut user_id = Vec::new();
    exec_or_ret_err_v4!(
        breader.read_until(0, &mut user_id).await,
        "cannot read user id",
        &mut bwriter
    );
    let rhost = if ip >> 24 == 0 {
        let mut domain = Vec::new();
        exec_or_ret_err_v4!(
            breader.read_until(0, &mut domain).await,
            "cannot read domain",
            &mut bwriter
        );
        // Remove the null byte
        domain.pop();
        String::from_utf8(domain)?
    } else {
        Ipv4Addr::from(ip).to_string()
    };
    debug!("SOCKSv4 request for {}:{} from {:?}", rhost, rport, user_id);
    if command == 0x01 {
        // CONNECT
        let stream_command_tx_permit = handler_resources
            .stream_command_tx
            .reserve()
            .await
            .map_err(|_| Error::RequestStream)?;
        handle_connect(
            breader,
            bwriter,
            &rhost,
            rport,
            stream_command_tx_permit,
            false,
        )
        .await
    } else {
        warn!("invalid or unsupported SOCKSv4 command {command}");
        bwriter.write_all(v4_reply!(0x5b)).await?;
        bwriter.flush().await?;
        Err(Error::SocksRequest)
    }
}

async fn handle_socks5_connection<R, W>(
    mut breader: R,
    mut bwriter: W,
    local_addr: &str,
    handler_resources: &HandlerResources,
) -> Result<(), Error>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Complete the handshake
    let num_methods = breader.read_u8().await?;
    let mut methods = vec![0; usize::from(num_methods)];
    breader.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        info!("client does not support NOAUTH");
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
        info!("client is not SOCKSv5");
        return Err(Error::SocksVersion(version));
    }
    let command = exec_or_ret_err_v5!(breader.read_u8().await, "cannot read command", &mut bwriter);
    trace!("command: {command}");
    let _reserved = exec_or_ret_err_v5!(
        breader.read_u8().await,
        "cannot read reserved",
        &mut bwriter
    );
    let address_type = exec_or_ret_err_v5!(
        breader.read_u8().await,
        "cannot read address type",
        &mut bwriter
    );
    trace!("address type: {address_type}");
    let rhost = match address_type {
        0x01 => {
            // IPv4
            let mut addr = [0; 4];
            exec_or_ret_err_v5!(
                breader.read_exact(&mut addr).await,
                "cannot read address",
                &mut bwriter
            );
            std::net::Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            // Domain name
            let len = breader.read_u8().await?;
            let mut addr = vec![0; usize::from(len)];
            exec_or_ret_err_v5!(
                breader.read_exact(&mut addr).await,
                "cannot read domain",
                &mut bwriter
            );
            String::from_utf8(addr)?
        }
        0x04 => {
            // IPv6
            let mut addr = [0; 16];
            exec_or_ret_err_v5!(
                breader.read_exact(&mut addr).await,
                "cannot read address",
                &mut bwriter
            );
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => {
            info!("invalid address type {address_type}");
            bwriter.write_all(v5_reply!(0x08)).await?;
            bwriter.flush().await?;
            return Err(Error::SocksRequest);
        }
    };
    let rport = exec_or_ret_err_v5!(breader.read_u16().await, "cannot read port", &mut bwriter);
    debug!("SOCKSv5 {command} for {rhost}:{rport}");
    match command {
        0x01 => {
            // CONNECT
            let stream_command_tx_permit = handler_resources
                .stream_command_tx
                .reserve()
                .await
                .map_err(|_| Error::RequestStream)?;
            handle_connect(
                breader,
                bwriter,
                &rhost,
                rport,
                stream_command_tx_permit,
                true,
            )
            .await
        }
        0x02 => {
            // BIND
            // We don't support this because I can't ask the remote host to bind
            warn!("BIND is not supported");
            bwriter.write_all(v5_reply!(0x07)).await?;
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
            bwriter.write_all(v5_reply!(0x07)).await?;
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
    stream_command_tx_permit: mpsc::Permit<'_, StreamCommand>,
    version_is_5: bool,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Establish a connection to the remote host
    let channel_request = request_tcp_channel(stream_command_tx_permit, rhost.into(), rport).await;
    let channel = if version_is_5 {
        let channel = exec_or_ret_err_v5!(channel_request, "cannot get channel", &mut writer);
        // Send back a successful response
        writer.write_all(v5_reply!(0x00)).await?;
        channel
    } else {
        let channel = exec_or_ret_err_v4!(channel_request, "cannot get channel", &mut writer);
        // Send back a successful response
        writer.write_all(v4_reply!(0x5a)).await?;
        channel
    };
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
    let socket = exec_or_ret_err_v5!(
        UdpSocket::bind((local_addr, 0)).await,
        "cannot get udp socket",
        &mut writer
    );
    let sock_local_addr =
        exec_or_ret_err_v5!(socket.local_addr(), "cannot get local address", &mut writer);
    let local_port = sock_local_addr.port().to_be_bytes();
    let local_ip = sock_local_addr.ip();
    let relay_task = tokio::spawn(udp_relay(
        rhost.to_string(),
        rport,
        handler_resources.dupe(),
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
    writer.flush().await?;
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
        let Some((dst, dport, data, src, sport)) = handle_udp_relay_header(&socket).await? else {
            continue
        };
        let mut udp_client_id_map = handler_resources.udp_client_id_map.write().await;
        let client_id = u32::next_available_key(&*udp_client_id_map);
        udp_client_id_map.insert(
            client_id,
            ClientIdMapEntry::new((src, sport).into(), socket.dupe(), true),
        );
        drop(udp_client_id_map);
        let datagram_frame = DatagramFrame {
            host: dst.into(),
            port: dport,
            sid: client_id,
            data,
        };
        handler_resources
            .datagram_tx
            .send(datagram_frame)
            .await
            .map_err(|_| Error::SendDatagram)?;
    }
}

/// Parse a UDP relay request
async fn handle_udp_relay_header(
    socket: &UdpSocket,
) -> Result<Option<(String, u16, Bytes, IpAddr, u16)>, Error> {
    let mut buf = BytesMut::zeroed(65536);
    let (len, addr) = socket.recv_from(&mut buf).await?;
    buf.truncate(len);
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
            let len = usize::from(buf[4]);
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
    buf.advance(processed);
    Ok(Some((dst, port, buf.freeze(), addr.ip(), addr.port())))
}

/// Send a UDP relay response
pub async fn send_udp_relay_response(
    socket: &UdpSocket,
    target: &SocketAddr,
    data: &[u8],
) -> std::io::Result<usize> {
    // Write the header
    let mut content = vec![0; 3];
    match target.ip() {
        IpAddr::V4(ip) => {
            content.extend(ip.octets());
            content.extend([0x01]);
        }
        IpAddr::V6(ip) => {
            content.extend(ip.octets());
            content.extend([0x04]);
        }
    }
    content.extend(&target.port().to_be_bytes());
    content.extend(data);
    socket.send_to(&content, target).await
}
