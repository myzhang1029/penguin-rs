//! Module tests.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::*;
use tokio::io::duplex;

#[tokio::test]
#[tracing::instrument]
async fn connect_listen_succeeds() {
    let (client, server) = duplex(10);
    let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;

    let client_mux = Multiplexor::new(client, Role::Client, None);
    let server_mux = Multiplexor::new(server, Role::Server, None);

    tokio::spawn(async move {
        server_mux
            .unwrap_server()
            .new_stream_channel()
            .await
            .unwrap();
    });

    let _ = client_mux
        .unwrap_client()
        .new_stream_channel(vec![], 0)
        .await
        .unwrap();
}
