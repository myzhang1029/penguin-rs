//! Hyper-based HTTP(S) client for requests to the backend.
//!
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use http::{uri, Request, Response};
use hyper::body::Incoming;
use tokio::net::TcpStream;

pub async fn request<B>(mut req: Request<B>) -> Result<Response<Incoming>, Error> {
    let uri = req.uri();
    let host = uri.host().expect("host is None (this is a bug)");
    // Insert the `Host` header
    req.headers_mut().insert(
        http::header::HOST,
        http::header::HeaderValue::from_str(host).expect("invalid host (this is a bug)"),
    );
    let port = uri.port_u16().unwrap_or_else(|| match uri.scheme_str() {
        Some("http") => 80,
        Some("https") => 443,
        _ => unreachable!("invalid scheme (this is a bug)"),
    });
    let stream = TcpStream::connect((host, port)).await?;

}
