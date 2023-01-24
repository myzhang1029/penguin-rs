//! Run a remote connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
//!
//! These are persistent tasks that run for the lifetime of the client.
//! Whenever a new connection is made, it tries to create a new channel
//! from the main loop and then spawns a new task to handle the connection.

pub(super) mod socks5;
mod tcp;
mod udp;

use super::StreamCommand;
use crate::client::HandlerResources;
use crate::mux::DatagramFrame;
use crate::parse_remote::{LocalSpec, RemoteSpec};
use crate::parse_remote::{Protocol, Remote};
use socks5::handle_socks_connection;
use tcp::{handle_tcp, handle_tcp_stdio};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info};
use udp::{handle_udp, handle_udp_stdio};

/// Do something or continue
macro_rules! complete_or_continue {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => {
                warn!("Remote error: {err}");
                continue;
            }
        }
    };
}

/// Do something or continue if the error is retryable
macro_rules! complete_or_continue_if_retryable {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => {
                if err.retryable() {
                    warn!("Remote error: {err}");
                    continue;
                }
                error!("Giving up");
                return Err(err.into());
            }
        }
    };
}

pub(super) use {complete_or_continue, complete_or_continue_if_retryable};

/// Errors
#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    #[error("cannot receive stream from the main loop")]
    ReceiveStream(#[from] oneshot::error::RecvError),
    #[error("main loop cannot send stream")]
    SendStream(#[from] mpsc::error::SendError<StreamCommand>),
    #[error("main loop cannot send datagram")]
    SendDatagram(#[from] mpsc::error::SendError<DatagramFrame>),
    #[error("remote host longer than 255 octets")]
    RHostTooLong(#[from] std::num::TryFromIntError),

    // These are for the socks server
    #[error("only supports SOCKSv5")]
    Socksv4,
    #[error("invalid domain name: {0}")]
    DomainName(#[from] std::string::FromUtf8Error),
    #[error("only supports NOAUTH")]
    OtherAuth,
    #[error("cannot read socks request")]
    SocksRequest,
}

/// Construct a TCP remote based on the description. These are simple because
/// a new channel can be created for each new connection and they do not need
/// to persist afther the connection.
/// This should be spawned as tasks and they will remain as long as `client`
/// is alive. Individual connection tasks are spawned as connections appear.
#[tracing::instrument(skip(handler_resources), level = "debug")]
pub(super) async fn handle_remote(
    remote: &'static Remote,
    handler_resources: HandlerResources,
) -> Result<(), Error> {
    debug!("opening remote {remote}");
    match (&remote.local_addr, &remote.remote_addr, remote.protocol) {
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Inet((rhost, rport)), Protocol::Tcp) => {
            handle_tcp(lhost, *lport, rhost, *rport, &handler_resources).await
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Inet((rhost, rport)), Protocol::Udp) => {
            handle_udp(lhost, *lport, rhost, *rport, &handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Inet((rhost, rport)), Protocol::Tcp) => {
            handle_tcp_stdio(rhost, *rport, &handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Inet((rhost, rport)), Protocol::Udp) => {
            handle_udp_stdio(rhost, *rport, &handler_resources).await
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Socks, _) => {
            // The parser guarantees that the protocol is TCP
            let listener = TcpListener::bind((lhost.as_str(), *lport)).await?;
            let local_addr = listener
                .local_addr()
                .map_or(format!("{lhost}:{lport}"), |a| a.to_string());
            info!("Listening on {local_addr}");
            loop {
                let (tcp_stream, _) = listener.accept().await?;
                let (tcp_rx, tcp_tx) = tokio::io::split(tcp_stream);
                let handler_resources = handler_resources.clone();
                tokio::spawn(async move {
                    handle_socks_connection(tcp_rx, tcp_tx, lhost, &handler_resources).await
                });
            }
        }
        (LocalSpec::Stdio, RemoteSpec::Socks, _) => {
            // The parser guarantees that the protocol is TCP
            Ok(handle_socks_connection(
                tokio::io::stdin(),
                tokio::io::stdout(),
                "localhost",
                &handler_resources,
            )
            .await?)
        }
    }
}
