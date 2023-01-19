//! Module tests.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::*;
use tokio::io::{duplex, AsyncWriteExt};
use tracing::{debug, info};
use tracing_subscriber::prelude::*;

fn setup_log() {
    let fmt_layer = tracing_subscriber::fmt::Layer::default()
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_timer(tracing_subscriber::fmt::time::time())
        .with_writer(std::io::stderr);
    let level_layer = tracing_subscriber::filter::LevelFilter::DEBUG;
    tracing_subscriber::registry()
        .with(level_layer)
        .with(fmt_layer)
        .init();
    info!("Starting test");
}

#[tokio::test]
async fn connect_succeeds() {
    setup_log();

    let (client, server) = duplex(10);
    let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;

    let client_mux = Multiplexor::new(client, Role::Client, None);
    let server_mux = Multiplexor::new(server, Role::Server, None);

    let server_task = tokio::spawn(async move {
        let stream = server_mux.server_new_stream_channel().await.unwrap();
        info!(
            "sport = {}, dport = {}, dest = {:?}:{}",
            stream.our_port, stream.their_port, stream.dest_host, stream.dest_port
        );
    });

    let stream = client_mux
        .client_new_stream_channel(vec![], 0)
        .await
        .unwrap();
    info!("sport = {}, dport = {}", stream.our_port, stream.their_port);
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
async fn dropped_connection_rsts() {
    setup_log();

    let (client, server) = duplex(10);
    let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;

    let client_mux = Multiplexor::new(client, Role::Client, None);
    let server_mux = Multiplexor::new(server, Role::Server, None);

    let server_task = tokio::spawn(async move {
        server_mux.server_new_stream_channel().await.unwrap();
    });

    let mut stream = client_mux
        .client_new_stream_channel(vec![], 0)
        .await
        .unwrap();
    info!("sport = {}, dport = {}", stream.our_port, stream.their_port);
    stream.write_all(b"hello").await.unwrap();
    server_task.await.unwrap();
}
