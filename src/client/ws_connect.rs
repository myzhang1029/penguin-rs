//! `WebSocket` connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::arg::ServerUrl;
use crate::mux::DEFAULT_WS_CONFIG;
use crate::proto_version::PROTOCOL_VERSION;
use crate::tls::make_rustls_client_config;
use http::header::HeaderValue;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, warn};
use tungstenite::{client::IntoClientRequest, handshake::client::Request};

/// Error type for `WebSocket` connection.
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid URL
    #[error("tungstenite error: {0}")]
    Tungstenite(#[from] tungstenite::error::Error),
    /// TLS error
    #[error(transparent)]
    Tls(#[from] crate::tls::Error),
}

/// Perform a `WebSocket` handshake.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(level = "debug", skip(extra_headers))]
pub async fn handshake(
    url: &ServerUrl,
    ws_psk: Option<&HeaderValue>,
    override_hostname: Option<&HeaderValue>,
    extra_headers: &[crate::arg::Header],
    tls_ca: Option<&str>,
    tls_key: Option<&str>,
    tls_cert: Option<&str>,
    tls_insecure: bool,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Error> {
    // We already sanitized https URLs to wss
    let is_tls = url.scheme().unwrap().as_str() == "wss";

    // Use a request to allow additional headers
    let mut req: Request = url.0.clone().into_client_request()?;
    let req_headers = req.headers_mut();
    // Add protocol version
    req_headers.insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(PROTOCOL_VERSION),
    );
    // Add PSK
    if let Some(ws_psk) = ws_psk {
        req_headers.insert("x-penguin-psk", ws_psk.clone());
    }
    // Add potentially custom hostname
    if let Some(hostname) = override_hostname {
        req_headers.insert("host", hostname.clone());
    }
    // Now add custom headers
    for header in extra_headers {
        req_headers.insert(header.name.clone(), header.value.clone());
    }

    let connector = if is_tls {
        let config = make_rustls_client_config(tls_cert, tls_key, tls_ca, tls_insecure).await?;
        Connector::Rustls(config.into())
    } else {
        // No TLS
        warn!("Using insecure WebSocket connection");
        Connector::Plain
    };
    let (ws_stream, _response) =
        connect_async_tls_with_config(req, Some(DEFAULT_WS_CONFIG), Some(connector)).await?;
    // We don't need to check the response now...
    debug!("WebSocket handshake succeeded");
    Ok(ws_stream)
}
