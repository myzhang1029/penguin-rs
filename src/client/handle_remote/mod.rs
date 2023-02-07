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
mod udp;

use crate::client::HandlerResources;
use crate::parse_remote::{LocalSpec, RemoteSpec};
use crate::parse_remote::{Protocol, Remote};
use socks::{handle_socks, handle_socks_stdio};
use tcp::{handle_tcp, handle_tcp_stdio};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error};
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
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Cannot request stream from the main loop")]
    RequestStream,
    #[error("Cannot send datagram to the main loop")]
    SendDatagram,
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
            handle_socks(lhost, *lport, &handler_resources).await
        }
        (LocalSpec::Stdio, RemoteSpec::Socks, _) => {
            // The parser guarantees that the protocol is TCP
            handle_socks_stdio(&handler_resources).await
        }
    }
}

/// Read/write to and from (i.e. bidirectionally forward) a pair of streams
#[tracing::instrument(skip_all, level = "debug")]
pub async fn pipe_streams<R1, W1, R2, W2>(
    mut reader1: R1,
    mut writer1: W1,
    mut reader2: R2,
    mut writer2: W2,
) -> std::io::Result<(u64, u64)>
where
    R1: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let pipe1 = async {
        let result = tokio::io::copy(&mut reader1, &mut writer2).await;
        writer2.shutdown().await.ok();
        result
    };
    let pipe2 = async {
        let result = tokio::io::copy(&mut reader2, &mut writer1).await;
        writer1.shutdown().await.ok();
        result
    };

    tokio::try_join!(pipe1, pipe2)
}
