//! HTTP utilities
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use bytes::Bytes;
use http_body_util::Full as FullBody;
use hyper::body::Incoming;
use std::pin::Pin;

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
    pub fn new_full(bytes: Bytes) -> Self {
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
