//! Run a remote connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::mux::{pipe_streams, DuplexStream};
use crate::parse_remote::Remote;
use crate::parse_remote::{LocalSpec, Protocol, RemoteSpec};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info};

use super::Command;

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("socks5 proxy failed: {0}")]
    Socks(#[from] async_socks5::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    #[error("cannot receive stream from the main loop")]
    ReceiveStream(#[from] oneshot::error::RecvError),
    #[error("main loop cannot send stream")]
    SendStream(#[from] mpsc::error::SendError<Command>),
}

/// Construct a remote based on the description.
#[tracing::instrument(skip(command_tx))]
pub async fn handle_remote(remote: Remote, command_tx: mpsc::Sender<Command>) -> Result<(), Error> {
    debug!("Opening remote {remote}");
    match remote.local_addr {
        LocalSpec::Inet((lhost, lport)) => {
            let listener = TcpListener::bind((lhost, lport)).await?;
            info!("Listening on port {lport}");
            loop {
                let (tcp_stream, _) = listener.accept().await?;
                let (tx, rx) = oneshot::channel();
                command_tx.send(tx).await?;
                let stream = rx.await?;
                let (tcp_rx, tcp_tx) = tokio::io::split(tcp_stream);
                let rspec = remote.remote_addr.clone();
                tokio::spawn(async move {
                    handle_connection(stream, rspec, remote.protocol, tcp_rx, tcp_tx).await
                });
            }
        }
        LocalSpec::Stdio => {
            let (tx, rx) = oneshot::channel();
            command_tx.send(tx).await?;
            let stream = rx.await?;
            let rspec = remote.remote_addr.clone();
            handle_connection(
                stream,
                rspec,
                remote.protocol,
                tokio::io::stdin(),
                tokio::io::stdout(),
            )
            .await
        }
    }
}

/// Handle a connection.
#[tracing::instrument(skip(stream, local_rx, local_tx))]
async fn handle_connection<R, T>(
    mut stream: DuplexStream,
    rspec: RemoteSpec,
    proto: Protocol,
    mut local_rx: R,
    mut local_tx: T,
) -> Result<(), Error>
where
    R: AsyncReadExt + Unpin + Send + 'static,
    T: AsyncWriteExt + Unpin + Send + 'static,
{
    // I could have used a giant match here, but I think this is more readable.
    if rspec == RemoteSpec::Socks {
        assert!(proto == Protocol::Tcp, "should be unreachable");
        debug!("Forwarding local to the internal socks5 proxy");
        let (mut rx, mut tx) = tokio::io::split(stream);
        pipe_streams(&mut local_rx, &mut local_tx, &mut rx, &mut tx).await?;
        debug!("SOCKS connection closed");
        Ok(())
    } else if proto == Protocol::Tcp {
        // We want to ask the socks5 proxy to connect to another port.
        let (rhost, rport) = match rspec {
            RemoteSpec::Inet((rhost, rport)) => (rhost, rport),
            RemoteSpec::Socks => unreachable!("already matched this case above"),
        };
        debug!("Forwarding local to the remote socks5 proxy");
        async_socks5::connect(&mut stream, (rhost, rport), None).await?;
        let (mut socksified_rx, mut socksified_tx) = tokio::io::split(stream);
        pipe_streams(
            &mut local_rx,
            &mut local_tx,
            &mut socksified_rx,
            &mut socksified_tx,
        )
        .await?;
        debug!("SOCKS connection closed");
        Ok(())
    } else {
        todo!()
    }
}
