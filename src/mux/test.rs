//! Module tests.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::*;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

#[tokio::test]
async fn connect_succeeds() {
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
async fn connected_stream_passes_data() {
    let (client, server) = duplex(10);
    let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;

    let client_mux = Multiplexor::new(client, Role::Client, None);
    let server_mux = Multiplexor::new(server, Role::Server, None);

    let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let len = input_bytes.len();
    let input_bytes_clone = input_bytes.to_owned();

    tokio::spawn(async move {
        let mut conn = server_mux.server_new_stream_channel().await.unwrap();
        let mut i = 0;
        while i < input_bytes_clone.len() {
            let res = conn.write_all(&input_bytes_clone[i..i + 1024]).await;
            assert!(res.is_ok());
            i += 1024;
        }
        info!("Done send");
    });

    let mut output_bytes: Vec<u8> = vec![];

    let mut conn = client_mux
        .client_new_stream_channel(vec![], 0)
        .await
        .unwrap();
    while output_bytes.len() < len {
        let mut buf = [0u8; 2048];
        let bytes = conn.read(&mut buf).await.unwrap();
        if bytes == 0 {
            break;
        }
        output_bytes.extend_from_slice(&buf[..bytes]);
        debug!("Read {} bytes", output_bytes.len());
    }

    assert_eq!(input_bytes, output_bytes);
}

#[tokio::test]
async fn test_early_eof_detected() {
    let (client, server) = duplex(10);
    let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;

    let client_mux = Multiplexor::new(client, Role::Client, None);
    let server_mux = Multiplexor::new(server, Role::Server, None);

    let input_bytes: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
    let len = input_bytes.len();
    let input_bytes_clone = input_bytes.to_owned();

    tokio::spawn(async move {
        let mut conn = server_mux.server_new_stream_channel().await.unwrap();
        conn.write_all(&input_bytes_clone).await.unwrap();
        info!("Done send");
    });

    let mut output_bytes: Vec<u8> = vec![];

    let mut conn = client_mux
        .client_new_stream_channel(vec![], 0)
        .await
        .unwrap();
    while output_bytes.len() < len + 2 {
        let mut buf = [0u8; 2048];
        let bytes = conn.read(&mut buf).await.unwrap();
        if bytes == 0 {
            break;
        }
        output_bytes.extend_from_slice(&buf[..bytes]);
        debug!("Read {} bytes", output_bytes.len());
    }

    assert_eq!(input_bytes, output_bytes);
}
