//! Run a remote connection.
//!
//! These are persistent tasks that run for the lifetime of the client.
//! They should try to handle connections as long as the client is alive,
//! and if they fail, the entire client will fail.
//! Whenever a new connection is made, it tries to create a new channel
//! from the main loop and then spawns a new task to handle the connection.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod common;
#[cfg(feature = "http-proxy")]
mod http;
pub(super) mod socks;
mod tcp;
#[cfg(feature = "tproxy")]
mod tproxy;
mod udp;

use self::common::open_tcp_listener;
use self::http::{handle_http, handle_http_stdio};
use self::socks::{handle_socks, handle_socks_stdio};
use self::tcp::{handle_tcp, handle_tcp_stdio};
use self::udp::{handle_udp, handle_udp_stdio};
use crate::arg::{LocalSpec, Protocol, Remote, RemoteSpec};
use crate::client::HandlerResources;
use std::io;
use thiserror::Error;
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
    #[error("cannot request stream from the main loop")]
    RequestStream,
    /// Happens when the main loop exits and is thus unable to receive
    /// datagrams on the channel.
    #[error("cannot send datagram to the main loop")]
    SendDatagram,
    /// Happens when the main loop receives an unretryable error
    /// while waiting for a stream to be established.
    #[error("main loop exited without sending stream")]
    MainLoopExitWithoutSendingStream,
    /// Happens when the user is trying to open a remote with features
    /// turned off at compile time.
    #[error("feature `{0}` is not enabled")]
    NotEnabled(&'static str),
    /// Happens when the user is trying to open a remote with features
    /// unavailable on the current platform.
    #[error("feature `{0}` is not available on this platform")]
    NotAvailable(&'static str),
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
        // Remote `Inet`
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Inet((rhost, rport)), Protocol::Tcp) => {
            // Failing to open the listener is a fatal error and should be propagated.
            let listener = open_tcp_listener(lhost, *lport)
                .await
                .map_err(FatalError::ClientIo)?;
            handle_tcp(listener, rhost, *rport, handler_resources).await
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Inet((rhost, rport)), Protocol::Udp) => {
            handle_udp(lhost, *lport, rhost, *rport, handler_resources).await
        }
        (LocalSpec::DomainSocket(path), RemoteSpec::Inet((rhost, rport)), _) => {
            // The parser guarantees that the protocol is TCP
            #[cfg(unix)]
            let listener = tokio::net::UnixListener::bind(path).map_err(FatalError::ClientIo)?;
            #[cfg(not(unix))]
            let listener = return Err(FatalError::NotAvailable("unix domain sockets"));
            handle_tcp(listener, rhost, *rport, handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Inet((rhost, rport)), Protocol::Tcp) => {
            handle_tcp_stdio(rhost, *rport, handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Inet((rhost, rport)), Protocol::Udp) => {
            handle_udp_stdio(rhost, *rport, handler_resources).await
        }
        // Remote `Socks`
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Socks, _) => {
            // The parser guarantees that the protocol is TCP
            let listener = open_tcp_listener(lhost, *lport)
                .await
                .map_err(FatalError::ClientIo)?;
            handle_socks(listener, lhost, handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Socks, _) => {
            // The parser guarantees that the protocol is TCP
            handle_socks_stdio(handler_resources).await
        }
        (LocalSpec::DomainSocket(path), RemoteSpec::Socks, _) => {
            // The parser guarantees that the protocol is TCP
            #[cfg(unix)]
            let listener = tokio::net::UnixListener::bind(path).map_err(FatalError::ClientIo)?;
            #[cfg(not(unix))]
            let listener = return Err(FatalError::NotAvailable("unix domain sockets"));
            handle_socks(listener, "localhost", handler_resources).await
        }
        // Remote `Http`
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Http, _) => {
            // The parser guarantees that the protocol is TCP
            let listener = open_tcp_listener(lhost, *lport)
                .await
                .map_err(FatalError::ClientIo)?;
            handle_http(listener, handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Http, _) => {
            // The parser guarantees that the protocol is TCP
            handle_http_stdio(handler_resources).await
        }
        (LocalSpec::DomainSocket(path), RemoteSpec::Http, _) => {
            // The parser guarantees that the protocol is TCP
            #[cfg(unix)]
            let listener = tokio::net::UnixListener::bind(path).map_err(FatalError::ClientIo)?;
            #[cfg(not(unix))]
            let listener = return Err(FatalError::NotAvailable("unix domain sockets"));
            handle_http(listener, handler_resources).await
        }
        // Remote `Tproxy`
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Tproxy, Protocol::Tcp) => {
            handle_tproxy_tcp(lhost, *lport, handler_resources).await
        }
        (LocalSpec::Inet((lhost, lport)), RemoteSpec::Tproxy, Protocol::Udp) => {
            handle_tproxy_udp(lhost, *lport, handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Tproxy, _) => {
            unreachable!("`clap` should have rejected this combination (this is a bug)")
        }
        (LocalSpec::DomainSocket(_), RemoteSpec::Tproxy, _) => {
            todo!("unix domain sockets TPROXY is not yet implemented")
        }
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
        Err(FatalError::NotEnabled("tproxy"))
    }
    pub(super) async fn handle_tproxy_udp(
        _lhost: &str,
        _lport: u16,
        _handler_resources: &HandlerResources,
    ) -> Result<(), FatalError> {
        Err(FatalError::NotEnabled("tproxy"))
    }
}

#[cfg(not(feature = "http-proxy"))]
mod http {
    use super::{FatalError, HandlerResources};
    pub(super) async fn handle_http(
        _lhost: &str,
        _lport: u16,
        _handler_resources: &HandlerResources,
    ) -> Result<(), FatalError> {
        Err(FatalError::NotEnabled("http-proxy"))
    }
    pub(super) async fn handle_http_uds(
        _path: &Path,
        _handler_resources: &'static HandlerResources,
    ) -> Result<(), super::FatalError> {
        Err(FatalError::NotEnabled("http-proxy"))
    }
    pub(super) async fn handle_http_stdio(
        _handler_resources: &HandlerResources,
    ) -> Result<(), FatalError> {
        Err(FatalError::NotEnabled("http-proxy"))
    }
}
