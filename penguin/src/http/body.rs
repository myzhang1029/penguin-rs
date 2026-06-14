//! HTTP body types for `hyper`` interaction
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
use bytes::Bytes;
use hyper::body::{Frame, Incoming, SizeHint};
use std::{pin::Pin, task::Poll};

/// Wrapper enum for hyper body types
#[derive(Debug)]
pub enum IncomingOrFullBody {
    /// `hyper::body::Incoming` body
    Incoming(Incoming),
    /// Full body in memory
    Full(Option<Bytes>),
}

impl IncomingOrFullBody {
    /// Create a new `Full` body from bytes
    pub const fn new_full(bytes: Bytes) -> Self {
        Self::Full(Some(bytes))
    }
}

impl hyper::body::Body for IncomingOrFullBody {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Incoming(body) => Pin::new(body).poll_frame(cx),
            Self::Full(body) => Poll::Ready(body.take().map(|d| Ok(Frame::data(d)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Incoming(body) => body.is_end_stream(),
            Self::Full(body) => body.is_none(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Incoming(body) => body.size_hint(),
            Self::Full(body) => SizeHint::with_exact(
                body.as_ref()
                    .map_or(0, |data| u64::try_from(data.len()).unwrap_or(u64::MAX)),
            ),
        }
    }
}
