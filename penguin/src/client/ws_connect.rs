//! `WebSocket` connection.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::arg::ClientArgs;
use crate::tls::{MaybeTlsStream, tls_connect};
use http::header::HeaderValue;
use penguin_mux::{Dupe, PROTOCOL_VERSION};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, handshake::client::Request};
use tokio_tungstenite::{WebSocketStream, client_async};
use tracing::{debug, warn};

/// Perform a `WebSocket` handshake.
#[tracing::instrument(skip_all, fields(server = %args.server.0), level = "debug")]
async fn handshake_inner(
    args: &ClientArgs,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, super::Error> {
    // We already sanitized https URLs to wss
    let is_tls = args
        .server
        .scheme()
        .expect("URL scheme should be present (this is a bug)")
        .as_str()
        == "wss";

    // Get the host and port from the URL
    // Both are guaranteed to exist by the `ClientArgs` parser
    let host = args
        .server
        .0
        .host()
        .expect("URL host should be present (this is a bug)");
    // `Tcp*` functions expect IPv6 addresses to not be wrapped in square brackets
    let host = crate::parse_remote::remove_brackets(host);
    let port = args
        .server
        .0
        .port_u16()
        .expect("URL port should be present (this is a bug)");
    // Server name for SNI
    // To be overridden later if a custom hostname is provided
    let mut domain = host;

    // Use a request to allow additional headers
    let mut req: Request = args.server.0.dupe().into_client_request()?;
    let req_headers = req.headers_mut();
    // Add protocol version
    req_headers.insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(PROTOCOL_VERSION),
    );
    // Add PSK
    if let Some(ref ws_psk) = args.ws_psk {
        req_headers.insert("x-penguin-psk", ws_psk.dupe());
    }
    // Add potentially custom hostname
    if let Some(ref hostname) = args.hostname {
        req_headers.insert("host", hostname.dupe());
        domain = hostname.to_str()?;
    }
    // Now add custom headers
    for header in &args.header {
        req_headers.insert(&header.name, header.value.dupe());
    }
    let stream = if is_tls {
        MaybeTlsStream::Tls(
            tls_connect(
                host,
                port,
                domain,
                args.tls_cert.as_deref(),
                args.tls_key.as_deref(),
                args.tls_ca.as_deref(),
                args.tls_skip_verify,
            )
            .await?,
        )
    } else {
        // No TLS
        warn!("Using insecure WebSocket connection");
        MaybeTlsStream::Plain(
            TcpStream::connect((host, port))
                .await
                .map_err(super::Error::TcpConnect)?,
        )
    };
    let (ws_stream, _response) = client_async(req, stream).await?;
    debug!("WebSocket handshake succeeded");
    Ok(ws_stream)
}

/// Perform a `WebSocket` handshake with timeout and cancellation support
pub async fn handshake(
    args: &ClientArgs,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, super::Error> {
    tokio::select! {
        result = handshake_inner(args) => result,
        () = args.handshake_timeout.sleep() => Err(super::Error::HandshakeTimeout),
        Ok(()) = tokio::signal::ctrl_c() => Err(super::Error::HandshakeCancelled),
    }
}
