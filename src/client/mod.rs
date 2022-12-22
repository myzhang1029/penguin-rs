//! Penguin client.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod parse_remote;
mod ws_connect;

use std::str::FromStr;

use crate::arg::ClientArgs;
use crate::mux::{Multiplexor, WebSocket};
use log::{debug, info};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to parse remote
    #[error("failed to parse remote: {0}")]
    ParseRemote(#[from] parse_remote::Error),
    /// Failed to connect WebSocket
    #[error("failed to connect WebSocket: {0}")]
    Connect(#[from] ws_connect::Error),
    /// WebSocket IO error
    #[error("WebSocket IO error: {0}")]
    WebSocketIO(#[from] std::io::Error),
}

pub async fn client_main(args: ClientArgs) -> Result<(), Error> {
    debug!("Client args: {:?}", args);
    let mut ws_stream = WebSocket::new(ws_connect::handshake(&args).await?);
    // Allow one channel for each remote, plus one for keep alive
    let num_channels = args.remote.len();
    // Send the number of channels, excluding the keep alive channel
    ws_stream.write_u16(num_channels as u16).await?;
    ws_stream.flush().await?;
    info!("Connected to server, asking for {} channels", num_channels);
    let mux = Multiplexor::new(ws_stream);

    // Leave the first channel for keep alive, regardless of whether keep alive is enabled
    for (idx, remote) in (2..).zip(args.remote.iter()) {
        let remote = parse_remote::Remote::from_str(remote)?;
        let mut chan = mux.connect(idx).await?;
        // Just doing random stuff here to test the multiplexor
        tokio::spawn(async move {
            info!("Connected to remote {}", remote);
            chan.write_u16(idx).await.unwrap();
            let content = chan.read_u16().await.unwrap();
            println!("Got content: {content}");
        });
    }
    // Keep alive channel
    if args.keepalive != 0 {
        let mut keepalive_chan = mux.connect(1).await?;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(args.keepalive)).await;
            keepalive_chan.write_u16(0).await.unwrap();
        }
    } else {
        loop {
            // Just keep the main thread alive
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
}
