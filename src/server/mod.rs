//! Penguin server.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

#[cfg(feature = "acme")]
pub mod acme;
mod forwarder;
mod service;
mod websocket;

use self::service::State;
use crate::arg::ServerArgs;
#[cfg(unix)]
use crate::tls::reload_tls_identity;
use crate::tls::{make_tls_identity, TlsIdentity, TlsIdentityInner};
use hyper::upgrade::Upgraded;
use hyper_util::rt::tokio::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use penguin_mux::Dupe;
use std::net::SocketAddr;
use std::sync::Arc;
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
    #[cfg(unix)]
    #[error("Cannot register signal handler: {0}")]
    Signal(std::io::Error),
    #[error("HTTP server I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    #[cfg(feature = "nativetls")]
    NativeTls(#[from] tokio_native_tls::native_tls::Error),
    #[cfg(feature = "acme")]
    #[error(transparent)]
    Acme(#[from] acme::Error),
}

/// Check if TLS is enabled.
/// If so, create a TlsIdentity and start relevant tasks
async fn check_start_tls(args: &'static ServerArgs) -> Result<Option<TlsIdentity>, Error> {
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
        register_signal_handler(tls_config.dupe(), tls_cert, tls_key, args.tls_ca.as_deref())?;
        return Ok(Some(tls_config));
    }
    // `clap` ensures that tls-key or tls-domain are mutually exclusive.
    #[cfg(feature = "acme")]
    if !args.tls_domain.is_empty() {
        trace!("Enabling TLS using ACME");
        let acme_client = acme::Client::populate_or_get(args).await?;
        let tls_config = acme_client.get_tls_config_spawn_renewal();
        return Ok(Some(tls_config));
    }
    trace!("TLS is not enabled");
    Ok(None)
}

#[tracing::instrument(level = "trace")]
pub async fn server_main(args: &'static ServerArgs) -> Result<(), Error> {
    let state = State::new(
        args.backend.as_ref(),
        args.ws_psk.as_ref(),
        &args.not_found_resp,
        args.obfs,
        args.timeout,
        args.timeout,
    );
    let sockaddrs = arg_to_sockaddrs(args)?;
    let mut listening_tasks = JoinSet::new();
    if let Some(tls_config) = check_start_tls(args).await? {
        for sockaddr in sockaddrs {
            let listener = TcpListener::bind(sockaddr).await?;
            let actual_addr = listener.local_addr()?;
            info!("Listening on wss://{actual_addr}/ws");
            listening_tasks.spawn(run_listener(
                listener,
                Some(tls_config.dupe()),
                state.dupe(),
            ));
        }
    } else {
        for sockaddr in sockaddrs {
            let listener = TcpListener::bind(sockaddr).await?;
            let actual_addr = listener.local_addr()?;
            info!("Listening on ws://{actual_addr}/ws");
            listening_tasks.spawn(run_listener(listener, None, state.dupe()));
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

/// Run a signal handler task to reload the TLS certificate.
#[cfg(unix)]
#[inline]
fn register_signal_handler(
    tls_config: crate::tls::TlsIdentity,
    tls_cert: &'static str,
    tls_key: &'static str,
    tls_ca: Option<&'static str>,
) -> Result<(), Error> {
    let mut sigusr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        .map_err(Error::Signal)?;
    // This `Future` does not fail, so we can ignore the `Result`.
    tokio::spawn(async move {
        while sigusr1.recv().await.is_some() {
            info!("Reloading TLS certificate");
            if let Err(err) = reload_tls_identity(&tls_config, tls_cert, tls_key, tls_ca).await {
                error!("Cannot reload TLS certificate: {err}");
            }
        }
    });
    Ok(())
}

/// Create a list of `SocketAddr`s from the command-line arguments on which to listen.
fn arg_to_sockaddrs(arg: &ServerArgs) -> Result<Vec<SocketAddr>, Error> {
    // `expect`: `clap` ensures that `--port` has at least one element.
    let last_port = arg.port.last().expect("`port` is empty (this is a bug)");
    assert!(!arg.host.is_empty(), "`host` is empty (this is a bug)");
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

/// Runs a listener.
#[tracing::instrument(skip_all, level = "debug", fields(tls = %tls_config.is_some()))]
async fn run_listener(
    listener: TcpListener,
    tls_config: Option<crate::tls::TlsIdentity>,
    state: State<'static>,
) {
    loop {
        let new_state = state.dupe();
        let (stream, peer) = match listener.accept().await {
            Ok((stream, peer)) => (stream, peer),
            Err(err) => {
                error!("Accept error: {err}");
                continue;
            }
        };
        debug!("accepted connection from {peer}");
        if let Some(tls_config) = &tls_config {
            tokio::spawn(serve_connection_tls(
                stream,
                new_state,
                tls_config.load_full(),
            ));
        } else {
            tokio::spawn(serve_connection(stream, new_state));
        }
    }
}

/// Serves a single connection from a client with TLS, ignoring errors.
async fn serve_connection_tls<S>(
    stream: S,
    state: State<'static>,
    tls_config: Arc<TlsIdentityInner>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let tls_timeout = state.tls_timeout;
    #[cfg(feature = "__rustls")]
    let stream_future = tokio_rustls::TlsAcceptor::from(tls_config).accept(stream);
    #[cfg(feature = "nativetls")]
    let stream_future = tls_config.accept(stream);

    let stream = state.tls_timeout.timeout(stream_future).await;

    match stream {
        Ok(Ok(stream)) => {
            serve_connection(stream, state).await;
        }
        Ok(Err(err)) => {
            error!("TLS handshake error: {err}");
        }
        Err(_) => {
            error!("TLS handshake timed out after {tls_timeout}");
        }
    }
}

/// Serves a single connection from a client, ignoring errors.
#[tracing::instrument(skip_all, level = "debug")]
async fn serve_connection<S>(stream: S, state: State<'static>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let http_timeout = state.http_timeout;
    let hyper_io = TokioIo::new(stream);
    let exec = auto::Builder::new(TokioExecutor::new());
    let conn = exec.serve_connection_with_upgrades(hyper_io, state);
    let conn = assert_send(conn);
    // This works because `ws_handler` spawns another task once the handshake is
    // complete, and that task is unaffected by this timeout.
    // This timeout only limits how much time we wait for the ws handshake to complete.
    // TODO: fully test its interaction with the backend handler as well.
    match http_timeout.timeout(conn).await {
        Err(_) => error!("HTTP connection timed out after {http_timeout}"),
        Ok(Err(err)) => error!("HTTP connection error: {err}"),
        Ok(Ok(())) => {}
    }
}

/// Workaround at https://github.com/rust-lang/rust/issues/102211#issuecomment-1367900125
fn assert_send<'u, R>(
    fut: impl 'u + Send + std::future::Future<Output = R>,
) -> impl 'u + Send + std::future::Future<Output = R> {
    fut
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_server_args(host: Vec<String>, port: Vec<u16>) -> ServerArgs {
        ServerArgs {
            host,
            port,
            ..Default::default()
        }
    }

    /// Test `arg_to_sockaddrs` with no hosts and no ports.
    #[test]
    #[should_panic(expected = "`port` is empty (this is a bug)")]
    fn test_arg_to_sockaddrs_empty() {
        crate::tests::setup_logging();
        let args = get_server_args(vec![], vec![]);
        let _ = arg_to_sockaddrs(&args).unwrap();
    }

    /// Test `arg_to_sockaddrs` with no hosts and one port.
    #[test]
    #[should_panic(expected = "`host` is empty (this is a bug)")]
    fn test_arg_to_sockaddrs_empty_host() {
        crate::tests::setup_logging();
        let args = get_server_args(vec![], vec![1234]);
        let _ = arg_to_sockaddrs(&args).unwrap();
    }

    /// Test `arg_to_sockaddrs` with one host and no ports.
    #[test]
    #[should_panic(expected = "`port` is empty (this is a bug)")]
    fn test_arg_to_sockaddrs_empty_port() {
        crate::tests::setup_logging();
        let args = get_server_args(vec!["::".to_string()], vec![]);
        let _ = arg_to_sockaddrs(&args).unwrap();
    }

    /// Test `arg_to_sockaddrs` with a single host and a single port.
    #[test]
    fn test_arg_to_sockaddrs_single_v4() {
        crate::tests::setup_logging();
        let args = get_server_args(vec!["127.0.0.1".to_string()], vec![9999]);
        let sockaddrs = arg_to_sockaddrs(&args).unwrap();
        assert_eq!(sockaddrs.len(), 1);
        assert_eq!(
            sockaddrs[0].ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(sockaddrs[0].port(), 9999);
    }

    /// Test `arg_to_sockaddrs` with a single host and a single port.
    #[test]
    fn test_arg_to_sockaddrs_single_v6() {
        crate::tests::setup_logging();
        let args = get_server_args(vec!["[::1]".to_string()], vec![1532]);
        let sockaddrs = arg_to_sockaddrs(&args).unwrap();
        assert_eq!(sockaddrs.len(), 1);
        assert_eq!(
            sockaddrs[0].ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(sockaddrs[0].port(), 1532);
    }

    /// Test `arg_to_sockaddrs` with several hosts and one port.
    #[test]
    fn test_arg_to_sockaddrs_multi_v4() {
        crate::tests::setup_logging();
        let args = get_server_args(
            vec![
                "127.0.0.1".to_string(),
                "0.0.0.0".to_string(),
                "[::]".to_string(),
                "::1".to_string(),
            ],
            vec![1233],
        );
        let sockaddrs = arg_to_sockaddrs(&args).unwrap();
        assert_eq!(sockaddrs.len(), 4);
        assert_eq!(
            sockaddrs[0].ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(sockaddrs[0].port(), 1233);
        assert_eq!(
            sockaddrs[1].ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
        );
        assert_eq!(sockaddrs[1].port(), 1233);
        assert_eq!(
            sockaddrs[2].ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
        );
        assert_eq!(sockaddrs[2].port(), 1233);
        assert_eq!(
            sockaddrs[3].ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(sockaddrs[3].port(), 1233);
    }
}
