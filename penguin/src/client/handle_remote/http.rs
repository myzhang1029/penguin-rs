//! Support for HTTP proxy servers
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::{convert::Infallible, net::SocketAddr};

use super::{
    FatalError,
    tcp::{open_tcp_listener, request_tcp_channel},
};
use crate::{client::HandlerResources, http::IncomingOrFullBody};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, uri::Scheme};
use hyper::client::conn::http1;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use tokio::io::{self as tio, AsyncRead, AsyncWrite};
use tracing::{debug, trace, warn};

fn make_static_body(status: StatusCode, content: &'static [u8]) -> Response<IncomingOrFullBody> {
    Response::builder()
        .status(status)
        .body(IncomingOrFullBody::new_full(Bytes::from_static(content)))
        // expect: this is hard codede as a valid response
        .expect("Failed to build response (this is a bug)")
}

async fn do_proxy_request(
    mut req: Request<Incoming>,
    client_addr: Option<SocketAddr>,
    our_addr: Option<&str>,
    handler_resources: &HandlerResources,
) -> Result<Response<IncomingOrFullBody>, Infallible> {
    // This fails only if main has exited
    let Ok(stream_command_tx_permit) = handler_resources.stream_command_tx.reserve().await else {
        return Ok(make_static_body(
            StatusCode::SERVICE_UNAVAILABLE,
            b"Proxy server is shutting down",
        ));
    };

    add_proxy_headers(req.headers_mut(), client_addr, our_addr);
    let Some(target) = req.uri().authority() else {
        return Ok(make_static_body(
            StatusCode::BAD_REQUEST,
            b"Malformed CONNECT request",
        ));
    };
    // Needs an owned copy so that the upgrade task can access it
    let host = Bytes::copy_from_slice(target.host().as_bytes());
    let port = target.port_u16().unwrap_or_else(|| {
        if req.uri().scheme() == Some(&Scheme::HTTPS) {
            443
        } else {
            80
        }
    });

    let Ok(mux_stream) = request_tcp_channel(stream_command_tx_permit, host, port).await else {
        return Ok(make_static_body(
            StatusCode::INTERNAL_SERVER_ERROR,
            b"Failed to establish connection",
        ));
    };
    if Method::CONNECT == req.method() {
        debug!("CONNECT for {target}");
        tokio::spawn(async move {
            let Ok(upgraded) = hyper::upgrade::on(req).await else {
                warn!("Could not upgrade connection in the CONNECT request");
                return;
            };
            if let Err(e) = mux_stream
                .into_copy_bidirectional(TokioIo::new(upgraded))
                .await
            {
                warn!("Error while proxying CONNECT request: {e}");
            }
        });
        Ok(make_static_body(StatusCode::OK, b""))
    } else {
        let method = req.method().clone();
        debug!("{method} request for {target}");
        let hyper_io = TokioIo::new(mux_stream);
        let Ok((mut client, conn)) = http1::handshake(hyper_io).await else {
            warn!("HTTP handshake failed for {target}");
            return Ok(make_static_body(
                StatusCode::BAD_GATEWAY,
                b"Failed to establish connection",
            ));
        };
        trace!("HTTP handshake successful for {target}");

        tokio::spawn(async move {
            if let Err(e) = dbg!(conn).await {
                warn!("HTTP connection error: {e}");
            }
        });
        client
            .send_request(req)
            .await
            .map(|res| res.map(IncomingOrFullBody::Incoming))
            .or_else(|e| {
                warn!("Error while sending {method} request: {e}");
                Ok(make_static_body(
                    StatusCode::BAD_GATEWAY,
                    b"Failed to proxy request to target",
                ))
            })
    }
}

fn add_proxy_headers(
    headers: &mut HeaderMap,
    client_addr: Option<SocketAddr>,
    our_ip: Option<&str>,
) {
    let Some(our_ip) = our_ip else {
        return;
    };
    let Some(client_addr) = client_addr else {
        return;
    };
    let client_ip = client_addr.ip().to_string();
    let x_forwarded_for = if headers.contains_key("x-forwarded-for") {
        let mut values: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .flat_map(|hdr| hdr.to_str().unwrap_or("").split(','))
            .map(str::trim)
            .collect();
        values.push(our_ip);
        values.join(", ")
    } else {
        format!("{client_ip}, {our_ip}")
    };
    if let Ok(value) = HeaderValue::from_str(&client_ip) {
        headers.append("x-real-ip", value);
    }
    if let Ok(value) = HeaderValue::from_str(&x_forwarded_for) {
        headers.append("x-forwarded-for", value);
    }
    headers.append("x-forwarded-proto", HeaderValue::from_static("http"));
}

async fn http_proxy_on_stream<S>(
    stream: S,
    client_addr: Option<SocketAddr>,
    our_addr: Option<&'static str>,
    handler_resources: &'static HandlerResources,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let hyper_io = TokioIo::new(stream);
    let exec = auto::Builder::new(TokioExecutor::new());
    let service =
        service_fn(move |req| do_proxy_request(req, client_addr, our_addr, handler_resources));
    exec.serve_connection_with_upgrades(hyper_io, service).await
}

#[tracing::instrument(skip(handler_resources), level = "debug")]
pub(super) async fn handle_http(
    lhost: &'static str,
    lport: u16,
    handler_resources: &'static HandlerResources,
) -> Result<(), super::FatalError> {
    // Not being able to open a TCP listener is a fatal error.
    let listener = open_tcp_listener(lhost, lport)
        .await
        .map_err(FatalError::ClientIo)?;
    loop {
        let (stream, peer_addr) = listener.accept().await.map_err(FatalError::ClientIo)?;
        debug!("Accepted HTTP proxy connection from {peer_addr}");
        tokio::spawn(async move {
            if let Err(e) =
                http_proxy_on_stream(stream, Some(peer_addr), Some(lhost), handler_resources).await
            {
                warn!("HTTP proxy forwarded from {peer_addr} failed: {e}");
            }
        });
    }
}

#[tracing::instrument(skip(handler_resources), level = "debug")]
pub(super) async fn handle_http_stdio(
    handler_resources: &'static HandlerResources,
) -> Result<(), super::FatalError> {
    loop {
        let stdio = tio::join(tio::stdin(), tio::stdout());
        if let Err(e) = http_proxy_on_stream(stdio, None, None, handler_resources).await {
            warn!("HTTP proxy forwarded from stdio failed: {e}");
            break Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;

    #[tokio::test]
    async fn test_make_static_body() {
        let content = b"Hello, world!";
        let response = make_static_body(StatusCode::OK, content);
        assert_eq!(response.status(), StatusCode::OK);
        if let IncomingOrFullBody::Full(body) = response.into_body() {
            let bytes: Bytes = body.collect().await.unwrap().to_bytes();
            assert_eq!(bytes, Bytes::from_static(content));
        } else {
            panic!("Expected a full body");
        }
    }
}
