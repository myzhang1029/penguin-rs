//! Penguin server.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod forwarder;
mod service;
mod websocket;

use self::service::{MakeStateService, State};
use crate::arg::ServerArgs;
use crate::tls::{make_tls_identity, reload_tls_identity, TlsAcceptor};
use crate::Dupe;
use hyper::server::conn::AddrIncoming;
use hyper::upgrade::Upgraded;
use hyper::Server;
use thiserror::Error;
use tokio_tungstenite::WebSocketStream;
use tracing::{error, info, trace};

type WebSocket = WebSocketStream<Upgraded>;

/// Server Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid listening host: {0}")]
    InvalidHost(#[from] std::net::AddrParseError),
    #[error(transparent)]
    Tls(#[from] crate::tls::Error),
    #[error("Cannot register signal handler: {0}")]
    Signal(std::io::Error),
    #[error("HTTP server error: {0}")]
    Hyper(#[from] hyper::Error),
}

#[tracing::instrument(level = "trace")]
pub async fn server_main(args: &'static ServerArgs) -> Result<(), Error> {
    let host = crate::parse_remote::remove_brackets(&args.host);
    let sockaddr = (host.parse::<std::net::IpAddr>()?, args.port).into();
    let incoming = AddrIncoming::bind(&sockaddr)?;

    let state = State::new(
        args.backend.as_ref(),
        args.ws_psk.as_ref(),
        &args.not_found_resp,
        args.obfs,
    );

    if let Some(tls_key) = &args.tls_key {
        // `expect`: `clap` ensures that both `--tls-cert` and `--tls-key` are
        // specified if either is specified.
        let tls_cert = args
            .tls_cert
            .as_ref()
            .expect("`tls_cert` is `None` (this is a bug)");
        trace!("Enabling TLS");
        info!("Listening on wss://{sockaddr}/ws");
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
        Server::builder(TlsAcceptor::new(tls_config, incoming))
            .serve(MakeStateService(state))
            .await?;
    } else {
        info!("Listening on ws://{sockaddr}/ws");
        Server::builder(incoming)
            .serve(MakeStateService(state))
            .await?;
    }
    Ok(())
}
