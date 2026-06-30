//! Support for HTTP proxy servers
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::{FatalError, common::request_tcp_channel};
use crate::client::HandlerResources;
use crate::http::{body::IncomingOrFullBody, proxy};
use async_acceptor::{AsyncAcceptable, AsyncAcceptableExt};
use bytes::Bytes;
use futures_util::TryFutureExt;
use http::{Method, Request, Response, StatusCode, uri::Scheme};
use hyper::client::conn::http1;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use std::{convert::Infallible, net::SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
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
    hr: &HandlerResources,
) -> Result<Response<IncomingOrFullBody>, Infallible> {
    // This fails only if main has exited
    let Ok(stream_command_tx_permit) = hr.stream_command_tx.reserve().await else {
        return Ok(make_static_body(
            StatusCode::SERVICE_UNAVAILABLE,
            b"Proxy server is shutting down",
        ));
    };

    proxy::add_headers(req.headers_mut(), client_addr);
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
            if let Err(e) = conn.await {
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

async fn http_proxy_on_stream<S>(
    stream: S,
    client_addr: Option<SocketAddr>,
    hr: &'static HandlerResources,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let hyper_io = TokioIo::new(stream);
    let exec = auto::Builder::new(TokioExecutor::new());
    let service = service_fn(move |req| do_proxy_request(req, client_addr, hr));
    exec.serve_connection_with_upgrades(hyper_io, service).await
}

#[tracing::instrument(skip_all, level = "debug")]
pub(super) async fn handle_http<L: AsyncAcceptable + Send + Sync>(
    listener: L,
    hr: &'static HandlerResources,
) -> Result<(), super::FatalError> {
    loop {
        let (stream, peer_addr) = listener
            .accept_with_sockaddr()
            .await
            .map_err(FatalError::ClientIo)?;
        let peer_addr_for_proxy = if peer_addr.ip().is_unspecified() {
            None
        } else {
            Some(peer_addr)
        };
        debug!("Accepted HTTP proxy connection from {peer_addr}");
        tokio::spawn(
            http_proxy_on_stream(stream, peer_addr_for_proxy, hr).inspect_err(move |e| {
                warn!("HTTP proxy forwarded from {peer_addr} failed: {e}");
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_make_static_body() {
        let content = b"Hello, world!";
        let response = make_static_body(StatusCode::OK, content);
        assert_eq!(response.status(), StatusCode::OK);
        let bytes: Bytes = response.collect().await.unwrap().to_bytes();
        assert_eq!(bytes, Bytes::from_static(content));
    }
}
