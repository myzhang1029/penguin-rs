//! Hyper services for the server.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::websocket::handle_websocket;
use crate::arg::BackendUrl;
use crate::server::io_with_timeout;
use crate::tls::{HyperConnector, MaybeTlsStream};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STANDARD_ENGINE;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, Uri, header};
use http_body_util::{BodyExt, Full as FullBody};
use hyper::body::Incoming;
use hyper::service::Service;
use hyper::upgrade::OnUpgrade;
use hyper_util::client::legacy::{Client as HyperClient, Error as HyperClientError};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::upgrade::{Parts, downcast};
use penguin_mux::{Dupe, PROTOCOL_VERSION, timing::OptionalDuration};
use sha1::{Digest, Sha1};
use std::pin::Pin;
use std::sync::OnceLock;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use tracing::{debug, error, warn};

static UPGRADE: HeaderValue = HeaderValue::from_static("upgrade");
static WEBSOCKET: HeaderValue = HeaderValue::from_static("websocket");
static WANTED_PROTOCOL: HeaderValue = HeaderValue::from_static(PROTOCOL_VERSION);
static WEBSOCKET_VERSION: HeaderValue = HeaderValue::from_static("13");

macro_rules! header_matches {
    ($given:expr, $wanted:expr) => {
        $given
            .map(|v| v.as_bytes().eq_ignore_ascii_case($wanted.as_bytes()))
            .unwrap_or_else(|| {
                warn!("Header {:?} does not match {:?}", $given, $wanted);
                false
            })
    };
}

fn make_sec_websocket_accept(key: &HeaderValue) -> HeaderValue {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let accept = B64_STANDARD_ENGINE.encode(hasher.finalize());
    // `expect`: Base64-encoded string should be valid UTF-8
    accept.parse().expect("Broken header value (this is a bug)")
}

/// Possible errors when processing requests.
/// Any of these actually should never happen.
#[derive(Debug, Error)]
pub(super) enum Error {
    #[error(transparent)]
    Http(#[from] http::Error),
    #[error(transparent)]
    Client(#[from] HyperClientError),
    #[error(transparent)]
    Body(#[from] hyper::Error),
}

/// Wrapper enum for hyper body types
#[derive(Debug)]
pub enum IncomingOrFullBody {
    /// `hyper::body::Incoming` body
    Incoming(Incoming),
    /// Full body in memory
    Full(FullBody<Bytes>),
}

impl IncomingOrFullBody {
    /// Create a new `Full` body from bytes
    fn new_full(bytes: Bytes) -> Self {
        Self::Full(FullBody::new(bytes))
    }
}

impl hyper::body::Body for IncomingOrFullBody {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Incoming(body) => Pin::new(body).poll_frame(cx),
            Self::Full(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|res| res.map(|res| res.map_err(|e| match e {}))),
        }
    }
}

/// Required state for each request.
#[derive(Clone, Debug)]
pub(super) struct State {
    /// Backend URL
    backend: Option<&'static BackendUrl>,
    /// Websocket PSK
    ws_psk: Option<&'static HeaderValue>,
    /// 404 response
    not_found_resp: &'static str,
    /// Whether to obfuscate
    obfs: bool,
    /// Whether we accept reverse binding
    reverse: bool,
    /// Backend client
    client: HyperClient<HyperConnector, IncomingOrFullBody>,
    /// Whether the backend supports HTTP/2
    /// This setting will be probed on the first HTTP/2 request.
    http2_support: &'static OnceLock<bool>,
    /// TLS handshake timeout
    pub tls_timeout: OptionalDuration,
    /// HTTP timeout
    pub http_timeout: OptionalDuration,
}

impl Dupe for State {
    fn dupe(&self) -> Self {
        Self {
            backend: self.backend,
            ws_psk: self.ws_psk,
            not_found_resp: self.not_found_resp,
            obfs: self.obfs,
            reverse: self.reverse,
            // `hyper` client is designed to be cheaply cloned.
            client: self.client.clone(),
            http2_support: self.http2_support,
            tls_timeout: self.tls_timeout,
            http_timeout: self.http_timeout,
        }
    }
}

impl State {
    /// Create a new `State`
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        backend: Option<&'static BackendUrl>,
        http2_support: &'static OnceLock<bool>,
        ws_psk: Option<&'static HeaderValue>,
        not_found_resp: &'static str,
        obfs: bool,
        reverse: bool,
        tls_timeout: OptionalDuration,
        http_timeout: OptionalDuration,
    ) -> std::io::Result<Self> {
        let client =
            HyperClient::builder(TokioExecutor::new()).build(crate::tls::make_hyper_connector()?);
        Ok(Self {
            backend,
            ws_psk,
            not_found_resp,
            obfs,
            reverse,
            client,
            http2_support,
            tls_timeout,
            http_timeout,
        })
    }
}

impl State {
    /// Convert the request to our types and execute
    async fn exec_request_inner(
        &self,
        mut req: Request<IncomingOrFullBody>,
        force_http1: bool,
    ) -> Result<Response<IncomingOrFullBody>, Error> {
        if force_http1 {
            // Downgrade to HTTP/1.1
            *req.version_mut() = http::Version::default();
        }
        let resp = self.client.request(req).await?;
        Ok(resp.map(IncomingOrFullBody::Incoming))
    }

    /// Helper for sending a request to the backend
    async fn exec_request(
        &self,
        req: Request<IncomingOrFullBody>,
    ) -> Result<Response<IncomingOrFullBody>, Error> {
        let is_http2 = req.version() == http::Version::HTTP_2;
        match (self.http2_support.get(), is_http2) {
            // HTTP/1.1 request or known HTTP/2 support: just send it
            (_, false) | (Some(true), true) => self.exec_request_inner(req, false).await,
            // Known no HTTP/2 support: downgrade to HTTP/1.1
            (Some(false), true) => self.exec_request_inner(req, true).await,
            (None, true) => {
                // First HTTP/2 request: probe if the backend supports HTTP/2
                // Duplicate the body so that we can retry if needed
                let (parts, body) = req.into_parts();
                let body = body.collect().await?.to_bytes();
                let saved_parts = parts.clone();
                let saved_body = body.dupe();
                let old_req = Request::from_parts(parts, IncomingOrFullBody::new_full(body.dupe()));
                let resp = self.exec_request_inner(old_req, false).await;
                match resp {
                    Ok(resp) => {
                        // Backend supports HTTP/2
                        // Ignore the error because we do allow concurrent sets
                        self.http2_support.set(true).ok();
                        Ok(resp)
                    }
                    Err(err) => {
                        // Pass the error if it is not related to HTTP/2
                        let Error::Client(client_err) = &err else {
                            return Err(err);
                        };
                        let Some(info) = client_err.connect_info() else {
                            return Err(err);
                        };
                        if info.is_negotiated_h2() {
                            // Server did negotiate HTTP/2, so the error is not related to HTTP/2 support
                            return Err(err);
                        }
                        // No HTTP/2 support, retry with HTTP/1.1
                        debug!(
                            "backend does not support HTTP/2, permanently downgrading to HTTP/1.1: {err}"
                        );
                        // Ignore the error because we do allow concurrent sets
                        self.http2_support.set(false).ok();
                        let saved_req = Request::from_parts(
                            saved_parts,
                            IncomingOrFullBody::new_full(saved_body),
                        );
                        self.exec_request_inner(saved_req, true).await
                    }
                }
            }
        }
    }

    /// Reverse proxy and 404
    async fn backend_or_404_handler(
        self,
        mut req: Request<IncomingOrFullBody>,
    ) -> Result<Response<IncomingOrFullBody>, Error> {
        if let Some(BackendUrl {
            scheme,
            authority,
            path: backend_path,
        }) = self.backend
        {
            let req_path = req.uri().path();
            let req_path_query = req
                .uri()
                .path_and_query()
                .map_or(req_path, http::uri::PathAndQuery::as_str);

            // Remove repeated forward slashes
            let base_path = backend_path.path();
            let new_path = if base_path.ends_with('/') && req_path_query.starts_with('/') {
                format!("{}{}", base_path, &req_path_query[1..])
            } else {
                format!("{base_path}{req_path_query}")
            };

            let uri = Uri::builder()
                // `expect`: `BackendUrl` is validated by clap.
                .scheme(scheme.dupe())
                .authority(authority.dupe())
                .path_and_query(new_path)
                .build()?;
            *req.uri_mut() = uri;
            self.exec_request(req).await.or_else(|e| {
                error!("Failed to proxy request to backend: {e}");
                self.not_found_handler()
            })
        } else {
            self.not_found_handler()
        }
    }

    /// 404 handler
    fn not_found_handler(self) -> Result<Response<IncomingOrFullBody>, Error> {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(IncomingOrFullBody::new_full(Bytes::from_static(
                self.not_found_resp.as_bytes(),
            )))?)
    }

    /// Check the PSK and protocol version and upgrade to a WebSocket if the PSK matches (if required).
    async fn ws_handler(
        self,
        mut req: Request<IncomingOrFullBody>,
        reverse: bool,
    ) -> Result<Response<IncomingOrFullBody>, Error> {
        let on_upgrade = req.extensions_mut().remove::<OnUpgrade>();
        let headers = req.headers();
        let connection = headers.get(header::CONNECTION);
        let upgrade = headers.get(header::UPGRADE);
        let sec_websocket_key = headers.get(header::SEC_WEBSOCKET_KEY);
        let sec_websocket_protocol = headers.get(header::SEC_WEBSOCKET_PROTOCOL);
        let sec_websocket_version = headers.get(header::SEC_WEBSOCKET_VERSION);
        let x_penguin_psk = headers.get("x-penguin-psk");

        if req.method() != Method::GET {
            warn!("Invalid WebSocket request: not a GET request");
            return self.backend_or_404_handler(req).await;
        }
        if self.ws_psk.is_some() && x_penguin_psk != self.ws_psk {
            warn!("Invalid WebSocket request: invalid PSK {x_penguin_psk:?}");
            return self.backend_or_404_handler(req).await;
        }
        let Some(sec_websocket_key) = sec_websocket_key else {
            warn!("Invalid WebSocket request: no `sec-websocket-key` header");
            return self.backend_or_404_handler(req).await;
        };
        if !header_matches!(connection, UPGRADE)
            || !header_matches!(upgrade, WEBSOCKET)
            || !header_matches!(sec_websocket_version, WEBSOCKET_VERSION)
            || !header_matches!(sec_websocket_protocol, WANTED_PROTOCOL)
        {
            return self.backend_or_404_handler(req).await;
        }
        let Some(on_upgrade) = on_upgrade else {
            error!("Empty `on_upgrade`");
            return self.backend_or_404_handler(req).await;
        };

        // Now we know it's a valid WebSocket request, so we can upgrade to a WebSocket.
        debug!("Upgrading to WebSocket");

        let sec_websocket_accept = make_sec_websocket_accept(sec_websocket_key);

        tokio::spawn(async move {
            match on_upgrade.await {
                Ok(upgraded) => {
                    // It is not a TLS connection, so we try to downcast to a plain `TcpStream`
                    let parts = downcast::<
                        TokioIo<io_with_timeout::IoWithTimeout<MaybeTlsStream<TcpStream>>>,
                    >(upgraded)
                    .expect("`Upgrade` is not the expected type (this is a bug)");
                    let Parts { io, read_buf, .. } = parts;
                    let inner_conn = io.into_inner().into_inner();
                    let ws = WebSocketStream::from_partially_read(
                        inner_conn,
                        read_buf.to_vec(),
                        Role::Server,
                        None,
                    )
                    .await;
                    handle_websocket(ws, reverse).await;
                }
                Err(err) => {
                    error!("Failed to upgrade to WebSocket: {err}");
                }
            }
        });

        Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::CONNECTION, &UPGRADE)
            .header(header::UPGRADE, &WEBSOCKET)
            .header(header::SEC_WEBSOCKET_PROTOCOL, &WANTED_PROTOCOL)
            .header(header::SEC_WEBSOCKET_ACCEPT, sec_websocket_accept)
            .body(IncomingOrFullBody::new_full(Bytes::new()))?)
    }
}

impl Service<Request<IncomingOrFullBody>> for State {
    type Response = Response<IncomingOrFullBody>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Hyper service handler
    fn call(&self, req: Request<IncomingOrFullBody>) -> Self::Future {
        // Only allow `/health` and `/version` if not obfuscating
        if req.uri().path() == "/health" && !self.obfs {
            return Box::pin(async {
                Ok(Response::new(IncomingOrFullBody::new_full(
                    Bytes::from_static(b"OK"),
                )))
            });
        }
        if req.uri().path() == "/version" && !self.obfs {
            return Box::pin(async {
                Ok(Response::new(IncomingOrFullBody::new_full(
                    Bytes::from_static(env!("CARGO_PKG_VERSION").as_bytes()),
                )))
            });
        }
        // If `/ws`, handle WebSocket
        if req.uri().path() == "/ws" {
            return Box::pin(self.dupe().ws_handler(req, self.reverse));
        }
        // Else, proxy to backend or return 404
        Box::pin(self.dupe().backend_or_404_handler(req))
    }
}

impl Service<Request<hyper::body::Incoming>> for State {
    type Response = <Self as Service<Request<IncomingOrFullBody>>>::Response;
    type Error = Error;
    type Future = <Self as Service<Request<IncomingOrFullBody>>>::Future;
    fn call(&self, req: Request<hyper::body::Incoming>) -> Self::Future {
        let req = req.map(IncomingOrFullBody::Incoming);
        Self::call(self, req)
    }
}

impl Service<Request<http_body_util::Empty<Bytes>>> for State {
    type Response = <Self as Service<Request<IncomingOrFullBody>>>::Response;
    type Error = Error;
    type Future = <Self as Service<Request<IncomingOrFullBody>>>::Future;
    fn call(&self, req: Request<http_body_util::Empty<Bytes>>) -> Self::Future {
        let req = req.map(|_| IncomingOrFullBody::new_full(Bytes::new()));
        Self::call(self, req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::LazyLock;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    type EmptyBody = http_body_util::Empty<Bytes>;

    /// A simple HTTP handler for testing
    async fn http_return_status(req: Request<Incoming>) -> Result<Response<Incoming>, Infallible> {
        let resp = Response::builder()
            .status(
                req.uri()
                    .path()
                    .trim_start_matches('/')
                    .parse::<u16>()
                    .unwrap_or(200),
            )
            .body(req.into_body())
            .unwrap();
        Ok(resp)
    }

    /// Start the test server
    async fn start_test_server() -> (JoinHandle<()>, SocketAddr) {
        let listener = TcpListener::bind(("::1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let task = tokio::task::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let io = TokioIo::new(stream);
                tokio::task::spawn(async move {
                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service_fn(http_return_status))
                        .await
                    {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                });
            }
        });
        (task, addr)
    }

    #[test]
    fn test_make_sec_websocket_accept() {
        crate::tests::setup_logging();
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        let actual = make_sec_websocket_accept(&key.parse().unwrap());
        assert_eq!(actual, expected);
        let key = "7S3qp57psT3kwWF29CFJNg==";
        let expected = "4s9bDvNVhoia18oejmdBEUJci9s=";
        let actual = make_sec_websocket_accept(&key.parse().unwrap());
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_obfs_or_not() {
        static TEST_OBFS_OR_NOT_BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
        TEST_OBFS_OR_NOT_BACKEND_SUPPORTS_HTTP2.set(false).unwrap();
        crate::tests::setup_logging();
        // Test `/health` without obfuscation
        let state = State::new(
            None,
            &TEST_OBFS_OR_NOT_BACKEND_SUPPORTS_HTTP2,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/health")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "OK");
        // Test `/health` with obfuscation
        let state = State::new(
            None,
            &TEST_OBFS_OR_NOT_BACKEND_SUPPORTS_HTTP2,
            None,
            "not found in the test",
            true,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/health")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "not found in the test");
        // Test `/version` without obfuscation
        let state = State::new(
            None,
            &TEST_OBFS_OR_NOT_BACKEND_SUPPORTS_HTTP2,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/version")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, env!("CARGO_PKG_VERSION"));
        // Test `/version` with obfuscation
        let state = State::new(
            None,
            &TEST_OBFS_OR_NOT_BACKEND_SUPPORTS_HTTP2,
            None,
            "not found in the test",
            true,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/version")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "not found in the test");
    }

    #[tokio::test]
    async fn test_backend_status() {
        static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
        static BACKEND: OnceLock<BackendUrl> = OnceLock::new();
        crate::tests::setup_logging();
        let (server_task, server_addr) = start_test_server().await;
        BACKEND
            .set(BackendUrl::from_str(&format!("http://{}", server_addr)).unwrap())
            .unwrap();
        // Test that the backend is actually working
        let state = State::new(
            Some(BACKEND.get().unwrap()),
            &BACKEND_SUPPORTS_HTTP2,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/200")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let state = State::new(
            Some(BACKEND.get().unwrap()),
            &BACKEND_SUPPORTS_HTTP2,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/418")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
        server_task.abort();
    }

    #[tokio::test]
    async fn test_backend_http1_from_http2_client() {
        static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
        static BACKEND: OnceLock<BackendUrl> = OnceLock::new();
        crate::tests::setup_logging();
        let (server_task, server_addr) = start_test_server().await;
        BACKEND
            .set(BackendUrl::from_str(&format!("http://{}", server_addr)).unwrap())
            .unwrap();
        let state = State::new(
            Some(BACKEND.get().unwrap()),
            &BACKEND_SUPPORTS_HTTP2,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let req = Request::builder()
            .version(http::Version::HTTP_11)
            .method(Method::GET)
            .uri("http://example.com/200")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // No probing should happen here
        assert!(BACKEND_SUPPORTS_HTTP2.get().is_none());
        let req = Request::builder()
            .version(http::Version::HTTP_2)
            .method(Method::GET)
            .uri("http://example.com/200")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Probing should have happened here
        assert_eq!(BACKEND_SUPPORTS_HTTP2.get(), Some(&false));
        // Now create a new state. Both version requests should still work
        let state = State::new(
            Some(BACKEND.get().unwrap()),
            &BACKEND_SUPPORTS_HTTP2,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let req = Request::builder()
            .version(http::Version::HTTP_2)
            .method(Method::GET)
            .uri("http://example.com/404")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/418")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
        server_task.abort();
    }

    #[cfg(any(feature = "tests-real-internet4", feature = "tests-real-internet6"))]
    #[tokio::test]
    async fn test_backend_tls() {
        static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
        static BACKEND: LazyLock<BackendUrl> =
            LazyLock::new(|| BackendUrl::from_str("https://www.google.com").unwrap());
        crate::tests::setup_logging();
        // Test that the backend is actually working
        let state = State::new(
            Some(&BACKEND),
            &BACKEND_SUPPORTS_HTTP2,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        // Google does support HTTP/2. We try that here, but let's not expect it to always work
        let req = Request::builder()
            .version(http::Version::HTTP_2)
            .method(Method::GET)
            .uri("http://example.com")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let state = State::new(
            Some(&BACKEND),
            &BACKEND_SUPPORTS_HTTP2,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        assert!(BACKEND_SUPPORTS_HTTP2.get().is_some());
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/teapot")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    }

    #[tokio::test]
    async fn test_stealth_websocket_upgrade_method() {
        static TEST_STEALTH_WEBSOCKET_UPGRADE_METHOD: OnceLock<bool> = OnceLock::new();
        TEST_STEALTH_WEBSOCKET_UPGRADE_METHOD.set(false).unwrap();
        crate::tests::setup_logging();
        // Test non-GET request
        let state = State::new(
            None,
            &TEST_STEALTH_WEBSOCKET_UPGRADE_METHOD,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .header("connection", "UpGrAdE")
            .header("upgrade", "WEBSOCKET")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-protocol", &WANTED_PROTOCOL)
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(EmptyBody::new())
            .unwrap();
        let result = state.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::NOT_FOUND);
        let body_bytes = result.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "not found in the test");
    }

    #[tokio::test]
    async fn test_stealth_websocket_upgrade_missing_key_header() {
        static TEST_STEALTH_WEBSOCKET_UPGRADE_MISSING_KEY_HEADER: OnceLock<bool> = OnceLock::new();
        TEST_STEALTH_WEBSOCKET_UPGRADE_MISSING_KEY_HEADER
            .set(false)
            .unwrap();
        crate::tests::setup_logging();
        // Test missing upgrade header
        let state = State::new(
            None,
            &TEST_STEALTH_WEBSOCKET_UPGRADE_MISSING_KEY_HEADER,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .header("connection", "UpGrAdE")
            .header("upgrade", "WEBSOCKET")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-protocol", &WANTED_PROTOCOL)
            .body(EmptyBody::new())
            .unwrap();
        let result = state.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::NOT_FOUND);
        let body_bytes = result.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "not found in the test");
    }

    #[tokio::test]
    async fn test_stealth_websocket_upgrade_wrong_psk() {
        static TEST_STEALTH_WEBSOCKET_UPGRADE_WRONG_PSK: OnceLock<bool> = OnceLock::new();
        TEST_STEALTH_WEBSOCKET_UPGRADE_WRONG_PSK.set(false).unwrap();
        // Test wrong PSK
        static PSK: HeaderValue = HeaderValue::from_static("correct PSK");
        crate::tests::setup_logging();
        let state = State::new(
            None,
            &TEST_STEALTH_WEBSOCKET_UPGRADE_WRONG_PSK,
            Some(&PSK),
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .header("connection", "UpGrAdE")
            .header("upgrade", "WEBSOCKET")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-protocol", &WANTED_PROTOCOL)
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("x-penguin-psk", "wrong PSK")
            .body(EmptyBody::new())
            .unwrap();
        let result = state.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::NOT_FOUND);
        let body_bytes = result.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "not found in the test");
    }

    #[tokio::test]
    async fn test_stealth_websocket_upgrade_correct_psk() {
        static TEST_STEALTH_WEBSOCKET_UPGRADE_CORRECT_PSK: OnceLock<bool> = OnceLock::new();
        TEST_STEALTH_WEBSOCKET_UPGRADE_CORRECT_PSK
            .set(false)
            .unwrap();
        // Test correct PSK
        static PSK: HeaderValue = HeaderValue::from_static("correct PSK");
        crate::tests::setup_logging();
        let state = State::new(
            None,
            &TEST_STEALTH_WEBSOCKET_UPGRADE_CORRECT_PSK,
            Some(&PSK),
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        )
        .unwrap();
        let on_upgrade = hyper::upgrade::on(http::Request::new(EmptyBody::new()));
        let req = Request::builder()
            .uri("wss://example.com/ws")
            .method(Method::GET)
            .header("connection", "UpGrAdE")
            .header("upgrade", "WEBSOCKET")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-protocol", &WANTED_PROTOCOL)
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("x-penguin-psk", &PSK)
            .extension(on_upgrade)
            .body(EmptyBody::new())
            .unwrap();
        let result = state.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::SWITCHING_PROTOCOLS);
    }
}
