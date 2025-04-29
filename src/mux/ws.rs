//! Generic WebSocket
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::task::{Context, Poll};

use bytes::Bytes;

/// Types of messages we need
#[derive(Clone, PartialEq, Eq)]
pub enum Message {
    /// Binary message or any payload
    Binary(Bytes),
    /// Ping message. Note that the payload is discarded.
    Ping,
    /// Pong message. Note that the payload is discarded.
    Pong,
    /// Close message. Note that the payload is discarded.
    Close,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Binary(data) => f.debug_struct("Binary").field("len", &data.len()).finish(),
            Self::Ping => f.debug_struct("Ping").finish(),
            Self::Pong => f.debug_struct("Pong").finish(),
            Self::Close => f.debug_struct("Close").finish(),
        }
    }
}

/// A generic WebSocket stream
/// Specialized for our [`Message`] type similar to [`futures_util::Stream`] and [`futures_util::Sink`].
/// See [`futures_util::Stream`] and [`futures_util::Sink`] for more details on the required methods.
pub trait WebSocket: Send + 'static {
    /// The internal type this `WebSocket` uses to represent `WebSocket` protocol messages
    type Message: Into<Message> + From<Message> + Send + Unpin;
    /// The internal type this `WebSocket` uses to represent errors
    type Error: std::error::Error + Into<crate::Error> + Send;
    /// Attempt to prepare the `Sink` to receive a value.
    fn poll_ready_unpin(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>>;
    /// Begin the process of sending a value to the sink.
    fn start_send_unpin(&mut self, item: Message) -> Result<(), crate::Error>;
    /// Flush any remaining output from this sink.
    fn poll_flush_unpin(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>>;
    /// Flush any remaining output and close this sink, if necessary.
    fn poll_close_unpin(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>>;
    /// Attempt to pull out the next value of this stream.
    fn poll_next_unpin(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Message, crate::Error>>>;
}

#[cfg(feature = "tungstenite")]
mod tokio_tungstenite {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures_util::{Sink, Stream};
    use tokio_tungstenite::tungstenite;
    use tracing::error;

    use super::{Message, WebSocket};
    impl From<tungstenite::Message> for Message {
        #[inline]
        fn from(msg: tungstenite::Message) -> Self {
            match msg {
                tungstenite::Message::Binary(data) => Self::Binary(data),
                tungstenite::Message::Text(text) => {
                    error!("Received text message: {text}");
                    Self::Binary(Bytes::from(text))
                }
                tungstenite::Message::Ping(_) => Self::Ping,
                tungstenite::Message::Pong(_) => Self::Pong,
                tungstenite::Message::Close(_) => Self::Close,
                tungstenite::Message::Frame(_) => {
                    unreachable!("`Frame` message should not be received")
                }
            }
        }
    }

    impl From<Message> for tungstenite::Message {
        #[inline]
        fn from(msg: Message) -> Self {
            match msg {
                Message::Binary(data) => Self::Binary(data),
                Message::Ping => Self::Ping(Bytes::new()),
                Message::Pong => Self::Pong(Bytes::new()),
                Message::Close => Self::Close(None),
            }
        }
    }

    impl From<tungstenite::Error> for crate::Error {
        #[inline]
        fn from(e: tungstenite::Error) -> Self {
            Self::WebSocket(Box::new(e))
        }
    }

    impl<RW> WebSocket for tokio_tungstenite::WebSocketStream<RW>
    where
        RW: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        type Message = tungstenite::Message;
        type Error = tungstenite::Error;

        /// Attempt to prepare the `Sink` to receive a value.
        ///
        /// # Errors
        /// It returns the error from the underlying sink.
        #[inline]
        fn poll_ready_unpin(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>> {
            Pin::new(self).poll_ready(cx).map_err(Into::into)
        }

        /// Begin the process of sending a value to the sink.
        /// Specialized for our [`Message`] type. See [`futures_util::Sink::start_send`] for more details.
        ///
        /// # Errors
        /// It returns the error from the underlying sink.
        #[inline]
        fn start_send_unpin(&mut self, item: Message) -> Result<(), crate::Error> {
            let item: Self::Message = item.into();
            Pin::new(self).start_send(item).map_err(Into::into)
        }

        /// Flush any remaining output from this sink.
        /// Specialized for our [`Message`] type. See [`futures_util::Sink::poll_flush`] for more details.
        #[inline]
        fn poll_flush_unpin(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>> {
            Pin::new(self).poll_flush(cx).map_err(Into::into)
        }

        /// Flush any remaining output and close this sink, if necessary.
        /// Specialized for our [`Message`] type. See [`futures_util::Sink::poll_close`] for more details.
        #[inline]
        fn poll_close_unpin(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>> {
            let this = Pin::new(self);
            futures_util::Sink::poll_close(this, cx).map_err(Into::into)
        }

        /// Attempt to pull out the next value of this stream.
        /// Specialized for our [`Message`] type. See [`futures_util::Stream::poll_next`] for more details.
        ///
        /// # Errors
        /// It returns the error from the underlying sink.
        #[inline]
        fn poll_next_unpin(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Message, crate::Error>>> {
            Pin::new(self)
                .poll_next(cx)
                .map(|opt| opt.map(|res| res.map(Into::into).map_err(Into::into)))
        }
    }
}
