//! Run a remote connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
//!
//! These are persistent tasks that run for the lifetime of the client.
//! They should try to handle connections as long as the client is alive,
//! and if they fail, the entire client will fail.
//! Whenever a new connection is made, it tries to create a new channel
//! from the main loop and then spawns a new task to handle the connection.

pub(super) mod socks;
mod tcp;
#[cfg(target_os = "linux")]
mod tproxy;
#[cfg(not(target_os = "linux"))]
mod tproxy_stub;
mod udp;

use crate::client::HandlerResources;
use crate::parse_remote::{LocalSpec, RemoteSpec};
use crate::parse_remote::{Protocol, Remote};
use socks::{handle_socks, handle_socks_stdio};
use tcp::{handle_tcp, handle_tcp_stdio};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tproxy::{handle_tproxy_tcp, handle_tproxy_udp};
#[cfg(not(target_os = "linux"))]
use tproxy_stub as tproxy;
use tracing::{debug, error};
use udp::{handle_udp, handle_udp_stdio};

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
                return Err(FatalError::ClientIo(err));
            }
        }
    };
}

pub(super) use complete_or_continue_if_retryable;

/// Handler errors
/// These are all fatal errors that will cause the client to exit.
#[derive(Debug, Error)]
pub enum FatalError {
    /// Happens when IO errors occur on client sockets, which are unlikely
    /// to be recoverable.
    // Not marked as #[from] so that we don't casually cast all IO errors
    #[error(transparent)]
    ClientIo(std::io::Error),
    /// Happens when the main loop exits and is thus unable to receive
    /// datagrams on the channel.
    #[error("Cannot request stream from the main loop")]
    RequestStream,
    /// Happens when the main loop exits and is thus unable to receive
    /// datagrams on the channel.
    #[error("Cannot send datagram to the main loop")]
    SendDatagram,
    /// Happens when the main loop receives an unretryable error
    /// while waiting for a straem to be established.
    #[error("Main loop exited without sending stream")]
    MainLoopExitWithoutSendingStream,
    /// Happens when the user is trying to open a "tproxy" remote
    /// on a non-Linux system.
    #[error("Transparent Proxy only works on Linux")]
    TproxyNotLinux,
}

/// Construct a TCP remote based on the description. These are simple because
/// a new channel can be created for each new connection and they do not need
/// to persist after the connection.
/// This should be spawned as tasks and they will remain as long as `client`
/// is alive. Individual connection tasks are spawned as connections appear.
#[tracing::instrument(skip(handler_resources), level = "debug")]
pub(super) async fn handle_remote(
    remote: &'static Remote,
    handler_resources: HandlerResources,
) -> Result<(), FatalError> {
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
            handle_socks(lhost, *lport, &handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Socks, _) => {
            // The parser guarantees that the protocol is TCP
            handle_socks_stdio(&handler_resources).await
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Tproxy, Protocol::Tcp) => {
            handle_tproxy_tcp(lhost, *lport, &handler_resources).await
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Tproxy, Protocol::Udp) => {
            handle_tproxy_udp(lhost, *lport, &handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Tproxy, _) => {
            unreachable!("`clap` should have rejected this combination (this is a bug)")
        }
    }
}

/// Merged `stdin` and `stdout` into a single stream
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
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
        buf: &mut tokio::io::ReadBuf,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdin).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stdio {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stdout).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_shutdown(cx)
    }
}
