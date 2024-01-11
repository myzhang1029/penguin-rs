//! Hyper services for the server.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
// TODO: revisit expect

use super::websocket::handle_websocket;
use crate::arg::BackendUrl;
use crate::proto_version::PROTOCOL_VERSION;
use crate::Dupe;
use base64::engine::general_purpose::STANDARD as B64_STANDARD_ENGINE;
use base64::Engine;
use bytes::Bytes;
use http::{header, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full as FullBody};
use hyper::service::Service;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use sha1::{Digest, Sha1};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;
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

/// Required state for each request.
#[derive(Clone, Debug)]
pub(super) struct State<'a> {
    /// Backend URL
    pub backend: Option<&'a BackendUrl>,
    /// Websocket PSK
    pub ws_psk: Option<&'a HeaderValue>,
    /// 404 response
    pub not_found_resp: &'a str,
    /// Whether to obfuscate
    pub obfs: bool,
    /// Reqwest client
    pub client: reqwest::Client,
}

impl<'a> Dupe for State<'a> {
    fn dupe(&self) -> Self {
        Self {
            backend: self.backend,
            ws_psk: self.ws_psk,
            not_found_resp: self.not_found_resp,
            obfs: self.obfs,
            client: self.client.dupe(),
        }
    }
}
impl State<'static> {
    /// Create a new `State`
    pub fn new(
        backend: Option<&'static BackendUrl>,
        ws_psk: Option<&'static HeaderValue>,
        not_found_resp: &'static str,
        obfs: bool,
    ) -> Self {
        Self {
            backend,
            ws_psk,
            not_found_resp,
            obfs,
            client: reqwest::Client::new(),
        }
    }

    /// Reverse proxy and 404
    async fn backend_or_404_handler<B>(
        self,
        req: Request<B>,
    ) -> Result<Response<FullBody<Bytes>>, Infallible>
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

            let uri = Uri::builder()
                // `expect`: `BackendUrl` is validated by clap.
                .scheme(scheme.dupe())
                .authority(authority.dupe())
                .path_and_query(format!("{}{req_path_query}", backend_path.path()))
                .build()
                .expect("Failed to build URI for backend (this is a bug)")
                .to_string();
            // XXX: This bridge between hyper and reqwest is very ugly. They are actually the same
            // type, so I have no idea why reqwest doesn't just use http::Request and http::Response.
            // This is no longer relevant since we're using reqwest instead of hyper.
            // Kept here for reference.
            // This may not be the best way to do this, but to avoid panicking if
            // we have a HTTP/2 request, but `backend` does not support h2, let's
            // downgrade to HTTP/1.1 and let them upgrade if they want to.
            // *req.version_mut() = http::version::Version::default();
            let (parts, body) = req.into_parts();
            let method = parts
                .method
                .as_str()
                .as_bytes()
                .try_into()
                .expect("Failed to convert hyper method to reqwest method (this is a bug)");
            let headers = parts.headers;
            let mut new_headers = reqwest::header::HeaderMap::with_capacity(headers.len());
            for (name, value) in headers.iter() {
                new_headers.insert(
                    reqwest::header::HeaderName::try_from(name.as_str())
                        .expect("Failed to convert header (this is a bug)"),
                    value
                        .as_bytes()
                        .try_into()
                        .expect("Failed to convert header (this is a bug)"),
                );
            }
            let body = body.collect().await.unwrap().to_bytes();
            let req = self
                .client
                .request(method, uri)
                .body(body)
                .headers(new_headers)
                .build()
                .expect("Failed to build request (this is a bug)");
            match self.client.execute(req).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let mut resp_builder = Response::builder().status(status);
                    {
                        let headers = resp.headers();
                        for (name, value) in headers.iter() {
                            resp_builder = resp_builder.header(
                                name.as_str(),
                                value
                                    .to_str()
                                    .expect("Failed to convert header (this is a bug)"),
                            );
                        }
                    }
                    let body = resp
                        .bytes()
                        .await
                        .expect("Failed to read response body (this is a bug)");
                    let resp = resp_builder
                        .body(FullBody::new(body))
                        .expect("Failed to build response (this is a bug)");
                    Ok(resp)
                }
                Err(e) => {
                    error!("Failed to proxy request to backend: {}", e);
                    self.not_found_handler()
                }
            }
        } else {
            self.not_found_handler()
        }
    }

    /// 404 handler
    fn not_found_handler(self) -> Result<Response<FullBody<Bytes>>, Infallible> {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(FullBody::new(self.not_found_resp.into()))
            .expect("Failed to build 404 response (this is a bug)"))
    }

    /// Check the PSK and protocol version and upgrade to a WebSocket if the PSK matches (if required).
    pub async fn ws_handler<B>(
        self,
        mut req: Request<B>,
    ) -> Result<Response<FullBody<Bytes>>, Infallible>
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
                    handle_websocket(ws).await;
                }
                Err(err) => {
                    error!("Failed to upgrade to WebSocket: {err}");
                }
            };
        });

        // Shouldn't panic
        Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::CONNECTION, &UPGRADE)
            .header(header::UPGRADE, &WEBSOCKET)
            .header(header::SEC_WEBSOCKET_PROTOCOL, &WANTED_PROTOCOL)
            .header(header::SEC_WEBSOCKET_ACCEPT, sec_websocket_accept)
            .body(FullBody::new(Bytes::new()))
            .expect("Failed to build WebSocket response (this is a bug)"))
    }
}

impl<B> Service<Request<B>> for State<'static>
where
    B: hyper::body::Body + Send + 'static,
    <B as hyper::body::Body>::Error: std::fmt::Debug,
    <B as hyper::body::Body>::Data: Send,
{
    type Response = Response<FullBody<Bytes>>;
    type Error = Infallible;
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
            return Box::pin(self.dupe().ws_handler(req));
        }
        // Else, proxy to backend or return 404
        Box::pin(self.dupe().backend_or_404_handler(req))
    }
}

/// The corresponding `MakeService` for `State`.
#[derive(Clone, Debug)]
pub(super) struct MakeStateService(pub State<'static>);

impl Dupe for MakeStateService {
    fn dupe(&self) -> Self {
        Self(self.0.dupe())
    }
}

impl<T> Service<T> for MakeStateService {
    type Response = State<'static>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, _: T) -> Self::Future {
        let cloned_self = self.dupe();
        Box::pin(async { Ok(cloned_self.0) })
    }
}

#[cfg(test)]
mod test {
    use http_body_util::BodyExt;

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

    #[tokio::test]
    async fn test_obfs_or_not() {
        // Test `/health` without obfuscation
        let state = State::new(None, None, "not found in the test", false);
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/health")
            .body(FullBody::new(Bytes::new()))
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "OK");
        // Test `/health` with obfuscation
        let state = State::new(None, None, "not found in the test", true);
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/health")
            .body(FullBody::new(Bytes::new()))
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "not found in the test");
        // Test `/version` without obfuscation
        let state = State::new(None, None, "not found in the test", false);
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/version")
            .body(FullBody::new(Bytes::new()))
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, env!("CARGO_PKG_VERSION"));
        // Test `/version` with obfuscation
        let state = State::new(None, None, "not found in the test", true);
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/health")
            .body(FullBody::new(Bytes::new()))
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "not found in the test");
    }

    #[cfg(any(feature = "tests-real-internet4", feature = "tests-real-internet6"))]
    #[tokio::test]
    async fn test_backend() {
        use once_cell::sync::Lazy;
        use std::str::FromStr;
        static BACKEND: Lazy<BackendUrl> =
            Lazy::new(|| BackendUrl::from_str("http://httpbin.org").unwrap());
        // Test that the backend is actually working
        let state = State::new(Some(&BACKEND), None, "not found in the test", false);
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/status/200")
            .body(FullBody::new(Bytes::new()))
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let state = State::new(Some(&BACKEND), None, "not found in the test", false);
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/status/418")
            .body(FullBody::new(Bytes::new()))
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    }

    #[cfg(any(feature = "tests-real-internet4", feature = "tests-real-internet6"))]
    #[tokio::test]
    async fn test_backend_tls() {
        // Check that this test makes sense: remove TLS deps of `reqwest`
        use once_cell::sync::Lazy;
        use std::str::FromStr;
        static BACKEND: Lazy<BackendUrl> =
            Lazy::new(|| BackendUrl::from_str("https://httpbin.org").unwrap());
        // Test that the backend is actually working
        let state = State::new(Some(&BACKEND), None, "not found in the test", false);
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/status/200")
            .body(FullBody::new(Bytes::new()))
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let state = State::new(Some(&BACKEND), None, "not found in the test", false);
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/status/418")
            .body(FullBody::new(Bytes::new()))
            .unwrap();
        let resp = state.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    }

    #[tokio::test]
    async fn test_stealth_websocket_upgrade_from_request_parts() {
        // Test missing upgrade header
        let state = State::new(None, None, "not found in the test", false);
        let req = Request::builder()
            .method(Method::GET)
            .header("connection", "UpGrAdE")
            .header("upgrade", "WEBSOCKET")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-protocol", &WANTED_PROTOCOL)
            .body(FullBody::new(Bytes::new()))
            .unwrap();
        let result = state.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::NOT_FOUND);
        let body_bytes = result.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "not found in the test");
        // Test wrong PSK
        static PSK: HeaderValue = HeaderValue::from_static("correct PSK");
        let state = State::new(None, Some(&PSK), "not found in the test", false);
        let req = Request::builder()
            .method(Method::GET)
            .header("connection", "UpGrAdE")
            .header("upgrade", "WEBSOCKET")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-protocol", &WANTED_PROTOCOL)
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("x-penguin-psk", "wrong PSK")
            .body(FullBody::new(Bytes::new()))
            .unwrap();
        let result = state.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::NOT_FOUND);
        let body_bytes = result.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "not found in the test");
    }
}
