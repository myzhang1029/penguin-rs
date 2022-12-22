//! Penguin client.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod mux;
mod parse_remote;
mod ws_connect;

use std::str::FromStr;

use crate::arg::ClientArgs;
use log::debug;
use mux::{ClientMultiplexor, ClientWebSocket};

pub async fn client_main(args: ClientArgs) -> i32 {
    debug!("Client args: {:?}", args);
    let ws_stream = match ws_connect::handshake(&args).await {
        Ok(ws_stream) => ws_stream,
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            return 1;
        }
    };
    let mux = ClientMultiplexor::new(ClientWebSocket::new(ws_stream));
    for (idx, remote) in (0..).zip(args.remote.iter()) {
        match parse_remote::Remote::from_str(remote) {
            Ok(remote) => {
                mux.connect(idx).await;
            }
            Err(err) => {
                eprintln!("Failed to parse remote: {}", err);
                return 1;
            }
        }
    }
    0
}
