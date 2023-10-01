//! Module tests.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::*;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

// Looks like since `mux` is a separate target (i.e. lib vs bin), we need to
// have a separate `test_setup_log` function here.
#[ctor::ctor]
fn test_setup_log() {
    use tracing_subscriber::{filter, fmt, prelude::*};
    let fmt_layer = fmt::Layer::default()
        .compact()
        .with_thread_ids(true)
        .with_timer(fmt::time::time())
        .with_writer(std::io::stderr);
    tracing_subscriber::registry()
        .with(filter::LevelFilter::INFO)
        .with(fmt_layer)
        .init();
}

#[tokio::test]
async fn connect_succeeds() {
    let (client, server) = crate::ws::mock::get_pair().await;

    let client_mux = Multiplexor::new(client, Role::Client, None, None);
    let server_mux = Multiplexor::new(server, Role::Server, None, None);

    let server_task = tokio::spawn(async move {
        let stream = server_mux.server_new_stream_channel().await.unwrap();
        info!(
            "sport = {}, dport = {}, dest = {:?}:{}",
            stream.our_port, stream.their_port, stream.dest_host, stream.dest_port
        );
    });

    let stream = client_mux.client_new_stream_channel(&[], 0).await.unwrap();
    info!("sport = {}, dport = {}", stream.our_port, stream.their_port);
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
async fn datagram_channel_passes_data() {
    let (client, server) = crate::ws::mock::get_pair().await;

    let client_mux = Multiplexor::new(client, Role::Client, None, None);
    let server_mux = Multiplexor::new(server, Role::Server, None, None);

    let server_task = tokio::spawn(async move {
        for _ in 0..64 {
            let dgram = server_mux.get_datagram().await.unwrap();
            debug!("Server got datagram");
            server_mux.send_datagram(dgram).await.unwrap();
        }
    });

    for _ in 0..64 {
        let payload: Bytes = (0..32768).map(|_| rand::random::<u8>()).collect();
        debug!("Client sending datagram");
        client_mux
            .send_datagram(DatagramFrame {
                host: Bytes::from_static("example.com".as_bytes()),
                port: 53,
                sid: 1,
                data: payload.clone(),
            })
            .await
            .unwrap();
        debug!("Client awaiting datagram");
        let recvd = client_mux.get_datagram().await.unwrap();
        assert_eq!(recvd.host, "example.com".as_bytes());
        assert_eq!(recvd.port, 53);
        assert_eq!(recvd.sid, 1);
        assert_eq!(recvd.data, payload);
    }
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
async fn connected_stream_passes_data() {
    let (client, server) = crate::ws::mock::get_pair().await;

    let client_mux = Multiplexor::new(client, Role::Client, None, None);
    let server_mux = Multiplexor::new(server, Role::Server, None, None);

    let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let len = input_bytes.len();
    let input_bytes_clone = input_bytes.clone();

    let server_task = tokio::spawn(async move {
        let mut conn = server_mux.server_new_stream_channel().await.unwrap();
        let mut i = 0;
        while i < input_bytes_clone.len() {
            conn.write_all(&input_bytes_clone[i..i + 1024])
                .await
                .unwrap();
            i += 1024;
        }
        info!("Done send");
        conn.shutdown().await.unwrap();
    });

    let mut output_bytes: Vec<u8> = vec![];

    let mut conn = client_mux.client_new_stream_channel(&[], 0).await.unwrap();
    while output_bytes.len() < len {
        let mut buf = [0u8; 2048];
        let bytes = conn.read(&mut buf).await.unwrap();
        if bytes == 0 {
            break;
        }
        output_bytes.extend(&buf[..bytes]);
        info!("Read {} bytes", output_bytes.len());
    }

    assert_eq!(input_bytes, output_bytes);
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_early_eof_detected() {
    let (client, server) = crate::ws::mock::get_pair().await;

    let client_mux = Multiplexor::new(client, Role::Client, None, None);
    let server_mux = Multiplexor::new(server, Role::Server, None, None);

    let input_bytes: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
    let len = input_bytes.len();
    let input_bytes_clone = input_bytes.clone();

    let server_task = tokio::spawn(async move {
        let mut conn = server_mux.server_new_stream_channel().await.unwrap();
        conn.write_all(&input_bytes_clone).await.unwrap();
        info!("Done send");
    });

    let mut output_bytes: Vec<u8> = vec![];

    let mut conn = client_mux.client_new_stream_channel(&[], 0).await.unwrap();
    while output_bytes.len() < len + 2 {
        let mut buf = [0u8; 2048];
        let bytes = conn.read(&mut buf).await.unwrap();
        if bytes == 0 {
            break;
        }
        output_bytes.extend(&buf[..bytes]);
        info!("Read {} bytes", output_bytes.len());
    }

    assert_eq!(input_bytes, output_bytes);
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_several_channels() {
    let (client, server) = crate::ws::mock::get_pair().await;

    let client_mux = Multiplexor::new(client, Role::Client, None, None);
    let server_mux = Multiplexor::new(server, Role::Server, None, None);

    let server_task = tokio::spawn(async move {
        let mut conn1 = server_mux.server_new_stream_channel().await.unwrap();
        info!("server conn1 = {:?}", conn1);
        let mut conn2 = server_mux.server_new_stream_channel().await.unwrap();
        info!("server conn2 = {:?}", conn2);
        let mut conn3 = server_mux.server_new_stream_channel().await.unwrap();
        info!("server conn3 = {:?}", conn3);
        let mut buf = [0u8; 32];
        let bytes = conn3.read(&mut buf).await.unwrap();
        assert_eq!(buf[..bytes], b"!"[..]);
        info!("server conn3 read = {:?}", bytes);
        let bytes = conn2.read(&mut buf).await.unwrap();
        assert_eq!(buf[..bytes], b"world"[..]);
        info!("server conn2 read = {:?}", bytes);
        let bytes = conn1.read(&mut buf).await.unwrap();
        assert_eq!(buf[..bytes], b"hello"[..]);
        info!("server conn1 read = {:?}", bytes);
    });
    let mut conn1 = client_mux.client_new_stream_channel(&[], 0).await.unwrap();
    info!("client conn1 = {:?}", conn1);
    let mut conn2 = client_mux.client_new_stream_channel(&[], 0).await.unwrap();
    info!("client conn2 = {:?}", conn2);
    let mut conn3 = client_mux.client_new_stream_channel(&[], 0).await.unwrap();
    info!("client conn3 = {:?}", conn3);
    conn1.write_all(b"hello").await.unwrap();
    conn1.shutdown().await.unwrap();
    info!("client conn1 wrote");
    conn2.write_all(b"world").await.unwrap();
    conn2.shutdown().await.unwrap();
    info!("client conn2 wrote");
    conn3.write_all(b"!").await.unwrap();
    conn3.shutdown().await.unwrap();
    info!("client conn3 wrote");

    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}
