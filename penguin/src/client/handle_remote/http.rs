//! Support for HTTP proxy servers
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::{
    FatalError,
    tcp::{open_tcp_listener, request_tcp_channel},
};
use crate::{client::HandlerResources, http::IncomingOrFullBody};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use tokio::io::{self as tio, AsyncRead, AsyncWrite};
use tracing::{debug, warn};

fn make_static_body(status: StatusCode, content: &'static [u8]) -> Response<IncomingOrFullBody> {
    Response::builder()
        .status(status)
        .body(IncomingOrFullBody::new_full(Bytes::from_static(content)))
        // expect: this is hard codede as a valid response
        .expect("Failed to build response (this is a bug)")
}

async fn do_proxy_request(
    req: Request<Incoming>,
    handler_resources: &HandlerResources,
) -> Result<Response<IncomingOrFullBody>, FatalError> {
    // This fails only if main has exited
    let Ok(stream_command_tx_permit) = handler_resources.stream_command_tx.reserve().await else {
        return Ok(make_static_body(
            StatusCode::SERVICE_UNAVAILABLE,
            b"Proxy server is shutting down",
        ));
    };
    let Some(target) = req.uri().authority() else {
        return Ok(make_static_body(
            StatusCode::BAD_REQUEST,
            b"Malformed CONNECT request",
        ));
    };
    // Needs an owned copy so that the upgrade task can access it
    let host = Bytes::copy_from_slice(target.host().as_bytes());
    let port = target.port_u16().unwrap_or(443);

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
        let client = HyperClient::builder(TokioExecutor::new())
            .build(crate::tls::make_hyper_connector().map_err(FatalError::ClientIo)?);
        match client
            .request(req.map(IncomingOrFullBody::Incoming))
            .await
            .map(|res| res.map(IncomingOrFullBody::Incoming))
        {
            Ok(res) => return Ok(res),
            Err(e) => {
                warn!("Error while proxying {method} request: {e}");
                return Ok(make_static_body(
                    StatusCode::BAD_GATEWAY,
                    b"Failed to proxy request to target",
                ));
            }
        }
    }
}

async fn http_proxy_on_stream<S>(
    stream: S,
    handler_resources: &'static HandlerResources,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let hyper_io = TokioIo::new(stream);
    let exec = auto::Builder::new(TokioExecutor::new());
    let service = service_fn(move |req| do_proxy_request(req, handler_resources));
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
            if let Err(e) = http_proxy_on_stream(stream, handler_resources).await {
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
        if let Err(e) = http_proxy_on_stream(stdio, handler_resources).await {
            warn!("HTTP proxy forwarded from stdio failed: {e}");
            break Ok(());
        }
    }
}
