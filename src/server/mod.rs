//! Penguin server.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod forwarder;
mod service;
mod websocket;

use std::net::SocketAddr;

use self::service::State;
use crate::arg::ServerArgs;
use crate::tls::{make_tls_identity, reload_tls_identity};
use crate::Dupe;
use hyper::upgrade::Upgraded;
use hyper_util::rt::tokio::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, trace};

type WebSocket = WebSocketStream<TokioIo<Upgraded>>;

/// Server Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid listening host: {0}")]
    InvalidHost(#[from] std::net::AddrParseError),
    #[error(transparent)]
    Tls(#[from] crate::tls::Error),
    #[error("Cannot register signal handler: {0}")]
    Signal(std::io::Error),
    #[error("HTTP server I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    #[cfg(feature = "nativetls")]
    NativeTls(#[from] tokio_native_tls::native_tls::Error),
}

#[tracing::instrument(level = "trace")]
pub async fn server_main(args: &'static ServerArgs) -> Result<(), Error> {
    let state = State::new(
        args.backend.as_ref(),
        args.ws_psk.as_ref(),
        &args.not_found_resp,
        args.obfs,
    );
    let sockaddrs = arg_to_sockaddrs(args)?;
    let mut listening_tasks = JoinSet::new();
    if let Some(tls_key) = &args.tls_key {
        // `expect`: `clap` ensures that both `--tls-cert` and `--tls-key` are
        // specified if either is specified.
        let tls_cert = args
            .tls_cert
            .as_ref()
            .expect("`tls_cert` is `None` (this is a bug)");
        trace!("Enabling TLS");
        let tls_config = make_tls_identity(tls_cert, tls_key, args.tls_ca.as_deref()).await?;
        #[cfg(unix)]
        {
            let mut sigusr1 =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
                    .map_err(Error::Signal)?;
            let tls_config = tls_config.dupe();
            // This `Future` does not fail, so we can ignore the `Result`.
            tokio::spawn(async move {
                while sigusr1.recv().await == Some(()) {
                    info!("Reloading TLS certificate");
                    if let Err(err) =
                        reload_tls_identity(&tls_config, tls_cert, tls_key, args.tls_ca.as_deref())
                            .await
                    {
                        error!("Cannot reload TLS certificate: {err}");
                    }
                }
            });
        }
        for sockaddr in sockaddrs {
            let listener = create_listener(sockaddr).await?;
            let state = state.dupe();
            let tls_config = tls_config.dupe();
            listening_tasks.spawn(async move {
                loop {
                    let (stream, peer) = match listener.accept().await {
                        Ok((stream, peer)) => (stream, peer),
                        Err(err) => {
                            error!("Accept error: {err}");
                            continue;
                        }
                    };
                    debug!("accepted connection from {peer} with TLS");
                    #[cfg(feature = "__rustls")]
                    let stream = tokio_rustls::TlsAcceptor::from(tls_config.load_full())
                        .accept(stream)
                        .await;
                    #[cfg(feature = "nativetls")]
                    let stream = tls_config.load().accept(stream).await;
                    match stream {
                        Ok(stream) => {
                            tokio::spawn(serve_connection(stream, state.dupe()));
                        }
                        Err(err) => {
                            error!("TLS handshake error: {err}");
                        }
                    }
                }
            });
        }
    } else {
        for sockaddr in sockaddrs {
            let listener = create_listener(sockaddr).await?;
            let state = state.dupe();
            listening_tasks.spawn(async move {
                loop {
                    let (stream, peer) = match listener.accept().await {
                        Ok((stream, peer)) => (stream, peer),
                        Err(err) => {
                            error!("Accept error: {err}");
                            continue;
                        }
                    };
                    debug!("accepted connection from {peer}");
                    tokio::spawn(serve_connection(stream, state.dupe()));
                }
            });
        }
    }
    while let Some(res) = listening_tasks.join_next().await {
        if let Err(err) = res {
            assert!(!err.is_panic(), "Panic in a listener: {err}");
            error!("Listener finished with error: {err}");
        }
    }
    Ok(())
}

/// Create a list of `SocketAddr`s from the command-line arguments on which to listen.
fn arg_to_sockaddrs(arg: &ServerArgs) -> Result<Vec<SocketAddr>, Error> {
    // `expect`: `clap` ensures that `--port` has at least one element.
    let last_port = arg.port.last().expect("`port` is empty (this is a bug)");
    // Fill the rest of `port` with the last element.
    let ports = arg.port.iter().chain(std::iter::repeat(last_port));
    // Fills the rest of `port` with the last element.
    arg.host
        .iter()
        .zip(ports)
        .map(|(host, port)| {
            let host = crate::parse_remote::remove_brackets(host);
            let sockaddr: SocketAddr = (host.parse::<std::net::IpAddr>()?, *port).into();
            Ok(sockaddr)
        })
        .collect()
}

/// Create a listener.
async fn create_listener(sockaddr: SocketAddr) -> Result<TcpListener, Error> {
    let listener = TcpListener::bind(sockaddr).await?;
    info!("Listening on ws://{sockaddr}/ws");
    Ok(listener)
}

/// Serves a single connection from a client.
async fn serve_connection<S>(stream: S, state: State<'static>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let hyper_io = TokioIo::new(stream);
    let conn = auto::Builder::new(TokioExecutor::new());
    let conn = conn.serve_connection_with_upgrades(hyper_io, state);
    let conn = assert_send(conn);
    conn.await.unwrap_or_else(|err| error!("Error: {err}"));
}

/// Workaround at https://github.com/rust-lang/rust/issues/102211#issuecomment-1367900125
fn assert_send<'u, R>(
    fut: impl 'u + Send + std::future::Future<Output = R>,
) -> impl 'u + Send + std::future::Future<Output = R> {
    fut
}
