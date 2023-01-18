//! Client- and server-side connection multiplexing and processing
//!
//! This is not a general-purpose WebSocket multiplexing library.
//! It is tailored to the needs of `penguin`.
//!
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod client;
mod common_methods;
mod frame;
mod server;
#[cfg(test)]
mod test;

use frame::Frame;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{pin_mut, FutureExt, Sink as FutureSink, Stream as FutureStream, StreamExt};
use rand::Rng;
use std::collections::HashMap;
use std::hash::Hash;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tracing::error;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::Message;

pub use client::{Multiplexor as ClientMultiplexor, MuxStream as ClientMuxStream};
pub use frame::*;
pub use server::{Multiplexor as ServerMultiplexor, MuxStream as ServerMuxStream};
pub use tungstenite::protocol::Role;

pub const DEFAULT_WS_CONFIG: WebSocketConfig = WebSocketConfig {
    max_send_queue: None,
    max_message_size: Some(64 << 20),
    max_frame_size: Some(2 << 23),
    accept_unmasked_frames: false,
};

/// Number of frames to buffer in the channels before blocking
const DATAGRAM_BUFFER_SIZE: usize = 2 << 8;
const STREAM_BUFFER_SIZE: usize = 2 << 8;
const FRAME_BUFFER_SIZE: usize = 2 << 8;
/// Size of the `n` in `duplex(n)`
const DUPLEX_SIZE: usize = 2 << 21;
/// Less than max_frame_size - header size
const READ_BUF_SIZE: usize = 2 << 22;

/// Multiplexor error
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("no available ports")]
    NoAvailablePorts,
    #[error(transparent)]
    Tungstenite(#[from] tungstenite::Error),
    #[error("invalid message: {0}")]
    InvalidMessage(&'static str),
    #[error("invalid frame: {0}")]
    InvalidFrame(#[from] <Vec<u8> as TryFrom<Frame>>::Error),
    #[error(transparent)]
    SendFrameToChannel(#[from] tokio::sync::mpsc::error::SendError<Frame>),
}

#[derive(Debug, Clone)]
pub enum Multiplexor<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Unpin + 'static,
{
    Client(ClientMultiplexor<Sink, Stream>),
    Server(ServerMultiplexor<Sink, Stream>),
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send>
    Multiplexor<SplitSink<WebSocketStream<S>, Message>, SplitStream<WebSocketStream<S>>>
{
    /// Create a new `WebSocketMultiplexor` from a `WebSocketStream`
    pub fn new(
        ws_stream: WebSocketStream<S>,
        role: Role,
        keepalive_interval: Option<std::time::Duration>,
    ) -> Self {
        let ws_config = ws_stream.get_config();
        let max_frame_size = ws_config.max_frame_size.unwrap_or(1 << 22);
        let (sink, stream) = ws_stream.split();
        match role {
            Role::Client => Multiplexor::Client(ClientMultiplexor::new(
                sink,
                stream,
                max_frame_size,
                keepalive_interval,
            )),
            Role::Server => {
                Multiplexor::Server(ServerMultiplexor::new(sink, stream, max_frame_size))
            }
        }
    }
}

impl<Sink, Stream> Multiplexor<Sink, Stream>
where
    Stream: FutureStream<Item = tungstenite::Result<Message>> + Send + Unpin + 'static,
    Sink: FutureSink<Message, Error = tungstenite::Error> + Send + Unpin + 'static,
{
    pub fn role(&self) -> Role {
        match self {
            Multiplexor::Client(_) => Role::Client,
            Multiplexor::Server(_) => Role::Server,
        }
    }

    pub fn unwrap_client(self) -> ClientMultiplexor<Sink, Stream> {
        match self {
            Multiplexor::Client(mux) => mux,
            Multiplexor::Server(_) => panic!("not a client multiplexor"),
        }
    }

    pub fn unwrap_server(self) -> ServerMultiplexor<Sink, Stream> {
        match self {
            Multiplexor::Client(_) => panic!("not a server multiplexor"),
            Multiplexor::Server(mux) => mux,
        }
    }

    pub fn as_client(&self) -> Option<&ClientMultiplexor<Sink, Stream>> {
        match self {
            Multiplexor::Client(mux) => Some(mux),
            Multiplexor::Server(_) => None,
        }
    }

    pub fn as_server(&self) -> Option<&ServerMultiplexor<Sink, Stream>> {
        match self {
            Multiplexor::Client(_) => None,
            Multiplexor::Server(mux) => Some(mux),
        }
    }
}

/// Read/write to and from (i.e. bidirectionally forward) a pair of streams
#[tracing::instrument(skip_all, level = "debug")]
pub async fn pipe_streams<R1, W1, R2, W2>(
    mut reader1: R1,
    mut writer1: W1,
    mut reader2: R2,
    mut writer2: W2,
) -> std::io::Result<u64>
where
    R1: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let pipe1 = tokio::io::copy(&mut reader1, &mut writer2).fuse();
    let pipe2 = tokio::io::copy(&mut reader2, &mut writer1).fuse();

    pin_mut!(pipe1, pipe2);

    tokio::select! {
        res = pipe1 => res,
        res = pipe2 => res
    }
}

/// Randomly generate a new number
pub trait IntKey: Eq + Hash + Copy {
    fn next_available_key<V>(map: &HashMap<Self, V>) -> Self;
}

macro_rules! impl_int_key {
    ($($t:ty),*) => {
        $(
            impl IntKey for $t {
                fn next_available_key<V>(map: &HashMap<Self, V>) -> Self {
                    let mut i = 0;
                    while map.contains_key(&i) {
                        i = rand::thread_rng().gen_range(1..<$t>::MAX);
                    }
                    i
                }
            }
        )*
    };
}

impl_int_key!(u8, u16, u32, u64, u128, usize);
