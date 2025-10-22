//! Run a remote connection.
//!
//! These are persistent tasks that run for the lifetime of the client.
//! They should try to handle connections as long as the client is alive,
//! and if they fail, the entire client will fail.
//! Whenever a new connection is made, it tries to create a new channel
//! from the main loop and then spawns a new task to handle the connection.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

pub(super) mod socks;
mod tcp;
#[cfg(feature = "tproxy")]
mod tproxy;
mod udp;

use self::socks::{handle_socks, handle_socks_stdio};
use self::tcp::{handle_tcp, handle_tcp_stdio};
use self::udp::{handle_udp, handle_udp_stdio};
use crate::client::HandlerResources;
use crate::parse_remote::{LocalSpec, RemoteSpec};
use crate::parse_remote::{Protocol, Remote};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tproxy::{handle_tproxy_tcp, handle_tproxy_udp};
use tracing::debug;

/// Handler errors
/// These are all fatal errors that will cause the client to exit.
#[derive(Debug, Error)]
pub enum FatalError {
    /// Happens when IO errors occur on client sockets, which are unlikely
    /// to be recoverable.
    // Not marked as #[from] so that we don't casually cast all IO errors
    #[error(transparent)]
    ClientIo(io::Error),
    /// Happens when the main loop exits and is thus unable to receive
    /// datagrams on the channel.
    #[error("Cannot request stream from the main loop")]
    RequestStream,
    /// Happens when the main loop exits and is thus unable to receive
    /// datagrams on the channel.
    #[error("Cannot send datagram to the main loop")]
    SendDatagram,
    /// Happens when the main loop receives an unretryable error
    /// while waiting for a stream to be established.
    #[error("Main loop exited without sending stream")]
    MainLoopExitWithoutSendingStream,
    /// Happens when the user is trying to open a "tproxy" remote
    /// but the feature is not enabled.
    #[error("Transparent Proxy not enabled")]
    TproxyNotEnabled,
}

/// Construct a TCP remote based on the description. These are simple because
/// a new channel can be created for each new connection and they do not need
/// to persist after the connection.
/// This should be spawned as tasks and they will remain as long as `client`
/// is alive. Individual connection tasks are spawned as connections appear.
#[tracing::instrument(skip_all, fields(remote = %remote), level = "debug")]
pub(super) async fn handle_remote(
    remote: &'static Remote,
    handler_resources: &'static HandlerResources,
) -> Result<(), FatalError> {
    debug!("opening remote");
    match (&remote.local_addr, &remote.remote_addr, remote.protocol) {
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Inet((rhost, rport)), Protocol::Tcp) => {
            handle_tcp(lhost, *lport, rhost, *rport, handler_resources).await
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Inet((rhost, rport)), Protocol::Udp) => {
            handle_udp(lhost, *lport, rhost, *rport, handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Inet((rhost, rport)), Protocol::Tcp) => {
            handle_tcp_stdio(rhost, *rport, handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Inet((rhost, rport)), Protocol::Udp) => {
            handle_udp_stdio(rhost, *rport, handler_resources).await
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Socks, _) => {
            // The parser guarantees that the protocol is TCP
            handle_socks(lhost, *lport, handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Socks, _) => {
            // The parser guarantees that the protocol is TCP
            handle_socks_stdio(handler_resources).await
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Tproxy, Protocol::Tcp) => {
            handle_tproxy_tcp(lhost, *lport, handler_resources).await
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Tproxy, Protocol::Udp) => {
            handle_tproxy_udp(lhost, *lport, handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Tproxy, _) => {
            unreachable!("`clap` should have rejected this combination (this is a bug)")
        }
    }
}

/// Merged `stdin` and `stdout` into a single stream
#[derive(Debug)]
pub struct Stdio {
    stdin: tokio::io::Stdin,
    stdout: tokio::io::Stdout,
}

impl Stdio {
    pub fn new() -> Self {
        Self {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
        }
    }
}

impl AsyncRead for Stdio {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stdio {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stdout).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_shutdown(cx)
    }
}

#[cfg(not(feature = "tproxy"))]
mod tproxy {
    use super::{FatalError, HandlerResources};
    pub(super) async fn handle_tproxy_tcp(
        _lhost: &str,
        _lport: u16,
        _handler_resources: &HandlerResources,
    ) -> Result<(), FatalError> {
        Err(FatalError::TproxyNotEnabled)
    }
    pub(super) async fn handle_tproxy_udp(
        _lhost: &str,
        _lport: u16,
        _handler_resources: &HandlerResources,
    ) -> Result<(), FatalError> {
        Err(FatalError::TproxyNotEnabled)
    }
}
