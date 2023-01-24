//! Penguin server.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod forwarder;
mod websocket;

use std::sync::Arc;

use crate::arg::{BackendUrl, ServerArgs};
use crate::config;
use crate::proto_version::PROTOCOL_VERSION;
use crate::tls::make_rustls_server_config;
use axum::async_trait;
use axum::extract::FromRequest;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::engine::general_purpose::STANDARD as B64_STANDARD_ENGINE;
use base64::Engine;
use http::header::SEC_WEBSOCKET_VERSION;
use http::HeaderValue;
use http::Method;
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper::{client::HttpConnector, Body as HyperBody, Client as HyperClient};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use sha1::{Digest, Sha1};
use thiserror::Error;
use tokio_tungstenite::WebSocketStream;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::{debug, error, info, trace, warn};
use tungstenite::protocol::Role;
use websocket::handle_websocket;

static UPGRADE: HeaderValue = HeaderValue::from_static("upgrade");
static WEBSOCKET: HeaderValue = HeaderValue::from_static("websocket");
static WANTED_PROTOCOL: HeaderValue = HeaderValue::from_static(PROTOCOL_VERSION);
static WEBSOCKET_VERSION: HeaderValue = HeaderValue::from_static("13");

type WebSocket = WebSocketStream<Upgraded>;

/// Server Errors
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid listening host
    #[error("invalid listening host: {0}")]
    InvalidHost(#[from] std::net::AddrParseError),
    /// TLS error
    #[error(transparent)]
    Tls(#[from] crate::tls::Error),
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Hyper error
    #[error("HTTP server error: {0}")]
    Hyper(#[from] hyper::Error),
}

/// Required state
#[derive(Clone, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct ServerState<'a> {
    /// Backend URL
    pub backend: Option<&'a BackendUrl>,
    /// Websocket PSK
    pub ws_psk: Option<&'a HeaderValue>,
    /// 404 response
    pub not_found_resp: &'a str,
    /// Hyper client
    pub client: Arc<HyperClient<HttpsConnector<HttpConnector>, HyperBody>>,
}

#[tracing::instrument(level = "trace")]
pub async fn server_main(args: &'static ServerArgs) -> Result<(), Error> {
    let host = crate::parse_remote::remove_brackets(&args.host);
    let sockaddr = (host.parse::<std::net::IpAddr>()?, args.port).into();

    #[cfg(feature = "rustls-native-roots")]
    let client_https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    #[cfg(all(feature = "rustls-native-roots", not(feature = "rustls-native-roots")))]
    let client_https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    let state = ServerState {
        backend: args.backend.as_ref(),
        ws_psk: args.ws_psk.as_ref(),
        not_found_resp: &args.not_found_resp,
        client: Arc::new(HyperClient::builder().build(client_https)),
    };

    let mut app: Router<()> = Router::new()
        .route("/ws", get(ws_handler))
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
        // `unwrap()` is safe because `clap` ensures that both `--tls-cert` and `--tls-key` are
        // specified if either is specified.
        let tls_cert = args.tls_cert.as_ref().unwrap();
        trace!("Enabling TLS");
        info!("Listening on wss://{sockaddr}/ws");
        let config = make_rustls_server_config(tls_cert, tls_key, args.tls_ca.as_deref()).await?;
        let config = RustlsConfig::from_config(Arc::new(config));

        #[cfg(unix)]
        tokio::spawn(reload_cert_on_signal(
            config.clone(),
            tls_cert,
            tls_key,
            args.tls_ca.as_deref(),
        ));
        axum_server::bind_rustls(sockaddr, config)
            .serve(app.into_make_service())
            .await?;
    } else {
        info!("Listening on ws://{sockaddr}/ws");
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
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<(), Error> {
    let mut sigusr1 =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    loop {
        sigusr1.recv().await;
        info!("Reloading TLS certificate");
        let server_config = make_rustls_server_config(cert_path, key_path, client_ca_path).await?;
        config.reload_from_config(Arc::new(server_config));
    }
}

/// Reverse proxy and 404
async fn backend_or_404_handler(
    State(state): State<ServerState<'static>>,
    mut req: Request<Body>,
) -> Response {
    if let Some(backend) = state.backend {
        let path = req.uri().path();
        let path_query = req
            .uri()
            .path_and_query()
            .map_or(path, http::uri::PathAndQuery::as_str);

        let uri = Uri::builder()
            // `unwrap()` should not panic because `BackendUrl` is validated
            // by clap.
            .scheme(backend.scheme.to_owned())
            .authority(backend.authority.to_owned())
            .path_and_query(format!("{}{path_query}", backend.path.path()))
            .build()
            .unwrap();
        *req.uri_mut() = uri;
        // This may not be the best way to do this, but to avoid panicking if
        // we have a HTTP/2 request, but `backend` does not support h2, let's
        // downgrade to HTTP/1.1 and let them upgrade if they want to.
        *req.version_mut() = http::version::Version::default();
        // XXX: I don't really know what I am `unwrap`ping, but I think it's
        // the best I can do in this situation.
        return state.client.request(req).await.unwrap().into_response();
    }
    not_found_handler(State(state)).await
}

/// 404 handler
#[allow(clippy::unused_async)]
async fn not_found_handler(State(state): State<ServerState<'static>>) -> Response {
    (StatusCode::NOT_FOUND, state.not_found_resp).into_response()
}

/// Check the PSK and protocol version and upgrade to a WebSocket if the PSK matches (if required).
pub async fn ws_handler(ws: StealthWebSocketUpgrade) -> Response {
    debug!("Upgrading to WebSocket");
    ws.on_upgrade(handle_websocket).await
}

/// A variant of `WebSocketUpgrade` that does not leak information
/// about the presence of a WebSocket endpoint if the upgrade fails.
pub struct StealthWebSocketUpgrade {
    sec_websocket_accept: HeaderValue,
    on_upgrade: OnUpgrade,
}

impl StealthWebSocketUpgrade {
    /// Upgrade to a WebSocket.
    pub async fn on_upgrade<F, Fut, T>(self, callback: F) -> Response
    where
        F: FnOnce(WebSocket) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send,
    {
        let on_upgrade = self.on_upgrade;

        tokio::spawn(async move {
            match on_upgrade.await {
                Ok(upgraded) => {
                    let ws = WebSocketStream::from_raw_socket(
                        upgraded,
                        Role::Server,
                        Some(config::DEFAULT_WS_CONFIG),
                    )
                    .await;
                    callback(ws).await;
                }
                Err(err) => {
                    error!("Failed to upgrade to WebSocket: {err}");
                }
            };
        });

        // Shouldn't panic
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", &UPGRADE)
            .header("upgrade", &WEBSOCKET)
            .header("sec-websocket-protocol", &WANTED_PROTOCOL)
            .header("sec-websocket-accept", self.sec_websocket_accept)
            .body(axum::body::boxed(axum::body::Empty::new()))
            .expect("Failed to build response")
    }
}

macro_rules! header_matches {
    ($given:expr, $wanted:expr) => {
        $given
            .map(|v| v.as_bytes())
            .map(|v| v.eq_ignore_ascii_case($wanted.as_bytes()))
            .unwrap_or_else(|| {
                warn!("Header {:?} does not match {:?}", $given, $wanted);
                false
            })
    };
}

#[async_trait]
impl FromRequest<ServerState<'static>, Body> for StealthWebSocketUpgrade {
    type Rejection = Response;

    async fn from_request(
        mut req: Request<Body>,
        state: &ServerState<'static>,
    ) -> Result<Self, Self::Rejection> {
        let on_upgrade = req.extensions_mut().remove::<OnUpgrade>();
        let headers = req.headers();
        let connection = headers.get("connection");
        let upgrade = headers.get("upgrade");
        let sec_websocket_key = headers.get("sec-websocket-key");
        let sec_websocket_protocol = headers.get("sec-websocket-protocol");
        let sec_websocket_version = headers.get(SEC_WEBSOCKET_VERSION);
        let x_penguin_psk = headers.get("x-penguin-psk");

        // `clone` should be cheap
        if req.method() != Method::GET {
            warn!("Invalid WebSocket request: not a GET request");
            return Err(backend_or_404_handler(State(state.to_owned()), req).await);
        }
        if state.ws_psk.is_some() && x_penguin_psk != state.ws_psk {
            warn!("Invalid WebSocket request: invalid PSK {x_penguin_psk:?}");
            return Err(backend_or_404_handler(State(state.to_owned()), req).await);
        }
        if sec_websocket_key.is_none() {
            warn!("Invalid WebSocket request: no sec-websocket-key header");
            return Err(backend_or_404_handler(State(state.to_owned()), req).await);
        }
        if !header_matches!(connection, UPGRADE)
            || !header_matches!(upgrade, WEBSOCKET)
            || !header_matches!(sec_websocket_version, WEBSOCKET_VERSION)
            || !header_matches!(sec_websocket_protocol, WANTED_PROTOCOL)
        {
            return Err(backend_or_404_handler(State(state.to_owned()), req).await);
        }
        if on_upgrade.is_none() {
            error!("Empty `on_upgrade`");
            return Err(backend_or_404_handler(State(state.to_owned()), req).await);
        }
        // We can `unwrap()` here because we checked that the header is present
        let sec_websocket_accept = make_sec_websocket_accept(sec_websocket_key.unwrap());
        Ok(Self {
            on_upgrade: on_upgrade.unwrap(),
            sec_websocket_accept,
        })
    }
}

fn make_sec_websocket_accept(key: &HeaderValue) -> HeaderValue {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let accept = B64_STANDARD_ENGINE.encode(hasher.finalize().as_slice());
    // Shouldn't panic
    accept.parse().expect("Broken header value")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_sec_websocket_accept() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        let actual = make_sec_websocket_accept(&key.parse().unwrap());
        assert_eq!(actual, expected);
        let key = "7S3qp57psT3kwWF29CFJNg==";
        let expected = "4s9bDvNVhoia18oejmdBEUJci9s=";
        let actual = make_sec_websocket_accept(&key.parse().unwrap());
        assert_eq!(actual, expected);
    }

    #[cfg(feature = "tests-real-internet")]
    #[tokio::test]
    async fn test_stealth_websocket_upgrade_from_request_parts() {
        use once_cell::sync::Lazy;
        use std::str::FromStr;
        #[cfg(feature = "rustls-native-roots")]
        let client_https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        #[cfg(all(feature = "rustls-native-roots", not(feature = "rustls-native-roots")))]
        let client_https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        static BACKEND: Lazy<BackendUrl> =
            Lazy::new(|| BackendUrl::from_str("http://example.com").unwrap());
        let state = ServerState {
            ws_psk: None,
            backend: Some(&BACKEND),
            not_found_resp: "not found in the test",
            client: Arc::new(HyperClient::builder().build(client_https)),
        };
        let req = Request::builder()
            .method(Method::GET)
            .header("connection", "UpGrAdE")
            .header("upgrade", "WEBSOCKET")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-protocol", &WANTED_PROTOCOL)
            .body(Body::empty())
            .unwrap();
        let upgrade = StealthWebSocketUpgrade::from_request(req, &state).await;
        assert!(upgrade.is_err());
        // Can't really test the rest because we need to have a `OnUpgrade`.
    }
}
