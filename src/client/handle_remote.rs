//! Run a remote connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::parse_remote::Remote;
use super::parse_remote::{LocalSpec, Protocol, RemoteSpec};
use async_socks5::SocksListener;
use log::info;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_stream_multiplexor::DuplexStream;

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("socks5 proxy failed: {0}")]
    Socks(#[from] async_socks5::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Task(#[from] tokio::task::JoinError),
}

/// Construct a remote based on the description.
pub async fn handle_remote(remote: Remote, stream: DuplexStream) -> Result<(), Error> {
    info!("Connected to remote {}", remote);
    // I could have used a giant match here, but I think this is more readable.
    if remote.remote_addr == RemoteSpec::Socks {
        assert!(remote.protocol == Protocol::Tcp, "should be unreachable");
        // Simple case: we want to forward to our socks5 proxy.
        match remote.local_addr {
            LocalSpec::Inet((lhost, lport)) => connect_tcp(stream, lhost, lport).await,
            LocalSpec::Stdio => connect_stdio(stream).await,
        }
    } else if remote.protocol == Protocol::Tcp {
        // We want to ask the socks5 proxy to connect to another port.
        let (rhost, rport) = match remote.remote_addr {
            RemoteSpec::Inet((rhost, rport)) => (rhost, rport),
            RemoteSpec::Socks => unreachable!("already matched this case above"),
        };
        let (socksified, _) = SocksListener::bind(stream, (rhost, rport), None)
            .await?
            .accept()
            .await?;
        match remote.local_addr {
            LocalSpec::Inet((lhost, lport)) => connect_tcp(socksified, lhost, lport).await,
            LocalSpec::Stdio => connect_stdio(socksified).await,
        }
    } else {
        todo!()
    }
}

/// Connect a stream to a local TCP socket.
async fn connect_tcp<Stream>(mut stream: Stream, host: String, port: u16) -> Result<(), Error>
where
    Stream: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let tcp_listener = TcpListener::bind((host, port)).await?;
    loop {
        let (mut tcp_stream, _) = tcp_listener.accept().await?;
        tokio::io::copy_bidirectional(&mut tcp_stream, &mut stream).await?;
    }
}

/// Connect a stream to stdio.
async fn connect_stdio(stream: DuplexStream) -> Result<(), Error> {
    let (mut rx, mut tx) = tokio::io::split(stream);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let send_task = tokio::spawn(async move { tokio::io::copy(&mut rx, &mut stdout).await });
    tokio::io::copy(&mut stdin, &mut tx).await?;
    send_task.await??;
    Ok(())
}
