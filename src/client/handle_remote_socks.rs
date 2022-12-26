//! SOCKS 5 server.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::handle_remote::{request_channel, Error};
use super::handle_remote_tcp::channel_tcp_handshake;
use crate::mux::pipe_streams;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::mpsc,
};
use tracing::debug;

use super::Command;

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
#[tracing::instrument(skip_all, level = "trace")]
pub(crate) async fn handle_socks_connection<R, W>(
    mut command_tx: mpsc::Sender<Command>,
    reader: R,
    mut writer: W,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut breader = BufReader::new(reader);
    // Complete the handshake
    let version = breader.read_u8().await?;
    if version != 5 {
        debug!("Client is not SOCKSv5");
        return Err(Error::Socksv4);
    }
    let nmethods = breader.read_u8().await?;
    let mut methods = vec![0; nmethods as usize];
    breader.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        debug!("Client does not support NOAUTH");
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
        debug!("Client is not SOCKSv5");
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
            debug!("Invalid address type {address_type}");
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
    debug!("Got request for {rhost}:{rport}");
    match command {
        0x01 => {
            // CONNECT
            // Establish a connection to the remote host
            let channel = execute_or_pass_error!(
                request_channel(&mut command_tx).await,
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
            pipe_streams(breader, writer, remote_rx, remote_tx).await?;
            Ok(())
        }
        // TODO: UDP ASSOCIATE and BIND
        _ => {
            debug!("Invalid command {command}");
            writer
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            Err(Error::SocksRequest)
        }
    }
}
