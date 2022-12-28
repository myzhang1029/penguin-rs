//! Penguin server.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod forwarder;
mod websocket;

use std::sync::Arc;

use crate::arg::{BackendUrl, ServerArgs};
use crate::proto_version::PROTOCOL_VERSION;
use axum::extract::WebSocketUpgrade;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use http::{HeaderMap, HeaderValue};
use hyper::{client::HttpConnector, Body as HyperBody, Client as HyperClient};
use rustls::ServerConfig;
use thiserror::Error;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::{debug, error, info, trace, warn};
use websocket::handle_websocket;

/// Server Errors
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid listening host
    #[error("invalid listening host: {0}")]
    InvalidHost(#[from] std::net::AddrParseError),
    /// Private key not supported
    #[error("private key not supported")]
    PrivateKeyNotSupported,
    /// Client certificate store is empty
    #[error("client certificate store is empty")]
    EmptyClientCertStore,
    /// General TLS error
    #[error("rustls error: {0}")]
    Tls(#[from] rustls::Error),
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Hyper error
    #[error("HTTP server error: {0}")]
    Hyper(#[from] hyper::Error),
}

/// Required state
#[derive(Clone, Debug)]
pub struct ServerState {
    /// Backend URL
    pub backend: Option<BackendUrl>,
    /// Websocket PSK
    pub ws_psk: Option<HeaderValue>,
    /// 404 response
    pub not_found_resp: String,
    /// Hyper client
    pub client: HyperClient<HttpConnector, HyperBody>,
}

#[tracing::instrument(level = "trace")]
pub async fn server_main(args: ServerArgs) -> Result<(), Error> {
    let host = if args.host.starts_with('[') && args.host.ends_with(']') {
        // Remove brackets from IPv6 addresses
        &args.host[1..args.host.len() - 1]
    } else {
        &args.host
    };
    let sockaddr = (host.parse::<std::net::IpAddr>()?, args.port).into();

    let state = ServerState {
        backend: args.backend,
        ws_psk: args.ws_psk,
        not_found_resp: args.not_found_resp,
        client: HyperClient::new(),
    };

    let mut app: Router<()> = Router::new()
        .route("/ws", get(ws_or_404_handler))
        .fallback(backend_or_404_handler)
        .with_state(state);
    if !args.obfs {
        app = app.route("/version", get(|| async { env!("CARGO_PKG_VERSION") }));
        app = app.route("/health", get(|| async { "OK" }));
    }
    let app = app.layer(
        TraceLayer::new_for_http()
            .make_span_with(DefaultMakeSpan::default().include_headers(false)),
    );

    if let Some(tls_key) = &args.tls_key {
        trace!("Enabling TLS");
        info!("Listening on wss://{}:{}/ws", args.host, args.port);
        let config = make_rustls_server_config(
            args.tls_cert.as_deref().unwrap(),
            tls_key,
            args.tls_ca.as_deref(),
        )
        .await?;
        let config = RustlsConfig::from_config(Arc::new(config));

        #[cfg(unix)]
        tokio::spawn(reload_cert_on_signal(
            config.clone(),
            args.tls_cert.unwrap(),
            tls_key.clone(),
            args.tls_ca.clone(),
        ));
        axum_server::bind_rustls(sockaddr, config)
            .serve(app.into_make_service())
            .await?;
    } else {
        info!("Listening on ws://{}:{}/ws", args.host, args.port);
        axum::Server::bind(&sockaddr)
            .serve(app.into_make_service())
            .await?;
    }
    Ok(())
}

/// `axum` example: `rustls_reload.rs`
#[cfg(unix)]
async fn reload_cert_on_signal(
    config: RustlsConfig,
    cert_path: String,
    key_path: String,
    client_ca_path: Option<String>,
) -> Result<(), Error> {
    let mut sigusr1 =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    loop {
        sigusr1.recv().await;
        info!("Reloading TLS certificate");
        let server_config =
            make_rustls_server_config(&cert_path, &key_path, client_ca_path.as_deref()).await?;
        config.reload_from_config(Arc::new(server_config));
    }
}

async fn make_rustls_server_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<ServerConfig, Error> {
    use rustls_pemfile::Item;
    // Load certificate chain
    let certs = tokio::fs::read(cert_path).await?;
    let certs = rustls_pemfile::certs(&mut certs.as_ref())?;
    let certs = certs.into_iter().map(rustls::Certificate).collect();
    // Load private key
    let key = tokio::fs::read(key_path).await?;
    let key = match rustls_pemfile::read_one(&mut key.as_ref())? {
        Some(Item::RSAKey(key)) | Some(Item::PKCS8Key(key)) | Some(Item::ECKey(key)) => key,
        _ => return Err(Error::PrivateKeyNotSupported),
    };
    let key = rustls::PrivateKey(key);
    // Build config
    let config = ServerConfig::builder().with_safe_defaults();
    let mut config = if let Some(client_ca_path) = client_ca_path {
        let mut store = rustls::RootCertStore::empty();
        let client_ca = tokio::fs::read(client_ca_path).await?;
        let client_ca = rustls_pemfile::certs(&mut client_ca.as_ref())?;
        let (new, _) = store.add_parsable_certificates(&client_ca);
        if new == 0 {
            return Err(Error::EmptyClientCertStore);
        }
        config.with_client_cert_verifier(rustls::server::AllowAnyAuthenticatedClient::new(store))
    } else {
        config.with_no_client_auth()
    }
    .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Reverse proxy and 404
async fn backend_or_404_handler(
    State(state): State<ServerState>,
    mut req: Request<Body>,
) -> Response {
    if let Some(backend) = &state.backend {
        let path = req.uri().path();
        let path_query = req
            .uri()
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or(path);

        let uri = Uri::builder()
            // `unwrap()` should not panic because `BackendUrl` is validated
            // by clap.
            .scheme(backend.scheme.clone())
            .authority(backend.authority.clone())
            .path_and_query(format!("{}{}", backend.path.path(), path_query))
            .build()
            .unwrap();
        *req.uri_mut() = uri;
        return state.client.request(req).await.unwrap().into_response();
    }
    not_found_handler(State(state)).await
}

/// 404 handler
async fn not_found_handler(State(state): State<ServerState>) -> Response {
    (StatusCode::NOT_FOUND, state.not_found_resp).into_response()
}

/// Check the PSK and protocol version and upgrade to a websocket if the PSK matches (if required).
pub async fn ws_or_404_handler(
    State(state): State<ServerState>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
) -> Response {
    if let Some(predefined_psk) = &state.ws_psk {
        let supplied_psk = headers.get("x-penguin-psk");
        if supplied_psk.is_none() || supplied_psk.unwrap() != predefined_psk {
            warn!("Invalid PSK");
            return not_found_handler(State(state)).await;
        }
    }
    let proto = headers.get("sec-websocket-protocol");
    if proto.is_none() || proto.unwrap() != PROTOCOL_VERSION {
        warn!("Invalid protocol version");
        return not_found_handler(State(state)).await;
    }
    debug!("Upgrading to websocket");
    ws.on_upgrade(handle_websocket)
}
