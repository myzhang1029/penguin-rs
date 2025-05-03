//! Hyper services for the server.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::websocket::handle_websocket;
use crate::arg::BackendUrl;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STANDARD_ENGINE;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, Uri, header};
use http_body_util::{BodyExt, Full as FullBody};
use hyper::service::Service;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use penguin_mux::{Dupe, PROTOCOL_VERSION, timing::OptionalDuration};
use sha1::{Digest, Sha1};
use std::pin::Pin;
use thiserror::Error;
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
    let accept = B64_STANDARD_ENGINE.encode(hasher.finalize().as_slice());
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
    Reqwest(#[from] reqwest::Error),
}

/// Required state for each request.
#[derive(Clone, Debug)]
pub(super) struct State<'a> {
    /// Backend URL
    backend: Option<&'a BackendUrl>,
    /// Websocket PSK
    ws_psk: Option<&'a HeaderValue>,
    /// 404 response
    not_found_resp: &'a str,
    /// Whether to obfuscate
    obfs: bool,
    /// Whether we accept reverse binding
    reverse: bool,
    /// Reqwest client
    client: reqwest::Client,
    /// TLS handshake timeout
    pub tls_timeout: OptionalDuration,
    /// HTTP timeout
    pub http_timeout: OptionalDuration,
}

impl Dupe for State<'_> {
    fn dupe(&self) -> Self {
        Self {
            backend: self.backend,
            ws_psk: self.ws_psk,
            not_found_resp: self.not_found_resp,
            obfs: self.obfs,
            reverse: self.reverse,
            client: self.client.dupe(),
            tls_timeout: self.tls_timeout,
            http_timeout: self.http_timeout,
        }
    }
}

impl<'a> State<'a> {
    /// Create a new `State`
    pub fn new(
        backend: Option<&'a BackendUrl>,
        ws_psk: Option<&'a HeaderValue>,
        not_found_resp: &'a str,
        obfs: bool,
        reverse: bool,
        tls_timeout: OptionalDuration,
        http_timeout: OptionalDuration,
    ) -> Self {
        Self {
            backend,
            ws_psk,
            not_found_resp,
            obfs,
            reverse,
            client: reqwest::Client::new(),
            tls_timeout,
            http_timeout,
        }
    }
}

impl State<'static> {
    /// Helper for sending a request to the backend
    /// XXX: Should we use `reqwest`, or should we construct something new with `tower`?
    async fn exec_request<B>(&self, req: Request<B>) -> Result<Response<FullBody<Bytes>>, Error>
    where
        B: hyper::body::Body,
        <B as hyper::body::Body>::Error: std::fmt::Debug,
    {
        let (parts, body) = req.into_parts();
        let method = parts.method;
        let headers = parts.headers;
        let body = body.collect().await.unwrap().to_bytes();
        let req = self
            .client
            .request(method, parts.uri.to_string())
            .body(body)
            .headers(headers)
            .build()?;
        let resp = self.client.execute(req).await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.bytes().await?;
        let mut http_resp = Response::new(FullBody::new(body));
        *http_resp.status_mut() = status;
        *http_resp.headers_mut() = headers;
        Ok(http_resp)
    }

    /// Reverse proxy and 404
    async fn backend_or_404_handler<B>(
        self,
        mut req: Request<B>,
    ) -> Result<Response<FullBody<Bytes>>, Error>
    where
        B: hyper::body::Body,
        <B as hyper::body::Body>::Error: std::fmt::Debug,
    {
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
            // This is no longer relevant since we're using reqwest instead of hyper.
            // Kept here for reference.
            // This may not be the best way to do this, but to avoid panicking if
            // we have a HTTP/2 request, but `backend` does not support h2, let's
            // downgrade to HTTP/1.1 and let them upgrade if they want to.
            // *req.version_mut() = http::version::Version::default();
            self.exec_request(req).await.or_else(|e| {
                error!("Failed to proxy request to backend: {e}");
                self.not_found_handler()
            })
        } else {
            self.not_found_handler()
        }
    }

    /// 404 handler
    fn not_found_handler(self) -> Result<Response<FullBody<Bytes>>, Error> {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(FullBody::new(Bytes::from_static(
                self.not_found_resp.as_bytes(),
            )))?)
    }

    /// Check the PSK and protocol version and upgrade to a WebSocket if the PSK matches (if required).
    async fn ws_handler<B>(
        self,
        mut req: Request<B>,
        reverse: bool,
    ) -> Result<Response<FullBody<Bytes>>, Error>
    where
        B: hyper::body::Body,
        <B as hyper::body::Body>::Error: std::fmt::Debug,
    {
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
                    let ws = WebSocketStream::from_raw_socket(
                        TokioIo::new(upgraded),
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
            .body(FullBody::new(Bytes::new()))?)
    }
}

impl<B> Service<Request<B>> for State<'static>
where
    B: hyper::body::Body + Send + 'static,
    <B as hyper::body::Body>::Error: std::fmt::Debug,
    <B as hyper::body::Body>::Data: Send,
{
    type Response = Response<FullBody<Bytes>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Hyper service handler
    fn call(&self, req: Request<B>) -> Self::Future {
        // Only allow `/health` and `/version` if not obfuscating
        if req.uri().path() == "/health" && !self.obfs {
            return Box::pin(async { Ok(Response::new(FullBody::new(Bytes::from_static(b"OK")))) });
        }
        if req.uri().path() == "/version" && !self.obfs {
            return Box::pin(async {
                Ok(Response::new(FullBody::new(Bytes::from_static(
                    env!("CARGO_PKG_VERSION").as_bytes(),
                ))))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::sync::LazyLock;

    type EmptyBody = http_body_util::Empty<Bytes>;

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
        crate::tests::setup_logging();
        // Test `/health` without obfuscation
        let state = State::new(
            None,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        );
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
            None,
            "not found in the test",
            true,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        );
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
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        );
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
            None,
            "not found in the test",
            true,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/health")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "not found in the test");
    }

    #[cfg(any(feature = "tests-real-internet4", feature = "tests-real-internet6"))]
    #[tokio::test]
    async fn test_backend() {
        static BACKEND: LazyLock<BackendUrl> =
            LazyLock::new(|| BackendUrl::from_str("http://httpbin.io").unwrap());
        crate::tests::setup_logging();
        // Test that the backend is actually working
        let state = State::new(
            Some(&BACKEND),
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/status/200")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let state = State::new(
            Some(&BACKEND),
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/status/418")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    }

    #[cfg(any(feature = "tests-real-internet4", feature = "tests-real-internet6"))]
    #[tokio::test]
    async fn test_backend_tls() {
        // Check that this test makes sense: remove TLS deps of `reqwest`
        static BACKEND: LazyLock<BackendUrl> =
            LazyLock::new(|| BackendUrl::from_str("https://www.google.com").unwrap());
        crate::tests::setup_logging();
        // Test that the backend is actually working
        let state = State::new(
            Some(&BACKEND),
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com")
            .body(EmptyBody::new())
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let state = State::new(
            Some(&BACKEND),
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        );
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
        crate::tests::setup_logging();
        // Test non-GET request
        let state = State::new(
            None,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        );
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
        crate::tests::setup_logging();
        // Test missing upgrade header
        let state = State::new(
            None,
            None,
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        );
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
        // Test wrong PSK
        static PSK: HeaderValue = HeaderValue::from_static("correct PSK");
        crate::tests::setup_logging();
        let state = State::new(
            None,
            Some(&PSK),
            "not found in the test",
            false,
            false,
            OptionalDuration::NONE,
            OptionalDuration::NONE,
        );
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
}
