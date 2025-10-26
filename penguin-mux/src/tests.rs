//! Module tests.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

// These tests are not run under loom, as they
// use `tokio::spawn` and thus need an actual `tokio` runtime.

use super::*;
use crate::{
    frame,
    ws::{Message, WebSocket},
};
use std::future::poll_fn;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tungstenite")]
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Used to provide some compatibility for tests written against the
/// `futures_util::Sink` and `Stream` traits.
trait CompatSinkStreamWebSocket: WebSocket {
    async fn send(&mut self, item: Message) -> Result<()> {
        poll_fn(|cx| self.poll_ready_unpin(cx)).await?;
        self.start_send_unpin(item)?;
        poll_fn(|cx| self.poll_flush_unpin(cx)).await
    }

    async fn next(&mut self) -> Option<Result<Message>> {
        poll_fn(|cx| self.poll_next_unpin(cx)).await
    }
}
impl<T: WebSocket> CompatSinkStreamWebSocket for T {}

pub fn setup_logging() {
    #[cfg(feature = "deadlock-detection")]
    crate::deadlock_detection::try_spawn_deadlock_detection();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

#[cfg(feature = "tungstenite")]
async fn get_pair(
    link_mss: Option<usize>,
) -> (
    WebSocketStream<tokio::io::DuplexStream>,
    WebSocketStream<tokio::io::DuplexStream>,
) {
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};
    let (client, server) = tokio::io::duplex(link_mss.unwrap_or(2048));
    let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
    (client, server)
}
#[cfg(not(feature = "tungstenite"))]
use mock::{MockWebSocketStream as WebSocketStream, get_pair};

mod mock {
    use crate::ws::{Message, WebSocket};
    use std::task::{Context, Poll};
    use tokio::sync::mpsc;

    pub struct MockWebSocketStream(
        Option<mpsc::UnboundedSender<Message>>,
        mpsc::UnboundedReceiver<Message>,
    );

    impl WebSocket for MockWebSocketStream {
        fn poll_ready_unpin(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>> {
            if self.0.is_none() {
                Poll::Ready(Err(crate::Error::Closed))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn start_send_unpin(&mut self, item: Message) -> Result<(), crate::Error> {
            let Some(sender) = &self.0 else {
                return Err(crate::Error::Closed);
            };
            sender.send(item).or(Err(crate::Error::Closed))?;
            Ok(())
        }

        fn poll_flush_unpin(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close_unpin(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>> {
            self.0.take();
            Poll::Ready(Ok(()))
        }

        fn poll_next_unpin(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Message, crate::Error>>> {
            self.1.poll_recv(cx).map(|x| x.map(Ok))
        }
    }

    pub async fn get_pair(_link_mss: Option<usize>) -> (MockWebSocketStream, MockWebSocketStream) {
        let (tx1, rx1) = mpsc::unbounded_channel();
        let (tx2, rx2) = mpsc::unbounded_channel();
        let client = MockWebSocketStream(Some(tx1), rx2);
        let server = MockWebSocketStream(Some(tx2), rx1);
        (client, server)
    }
}

#[tokio::test]
#[cfg(not(loom))]
async fn connect_succeeds() {
    setup_logging();
    let (client, server) = get_pair(None).await;

    let client_mux = Multiplexor::new(client, None, None);
    let server_mux = Multiplexor::new(server, None, None);

    let server_task = tokio::spawn(async move {
        let stream = server_mux.accept_stream_channel().await.unwrap();
        info!(
            "flow_id = {:08x}, dest = {:?}:{}",
            stream.flow_id, stream.dest_host, stream.dest_port
        );
    });

    let stream = client_mux.new_stream_channel(&[], 0).await.unwrap();
    info!("flow_id = {:08x}", stream.flow_id);
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn datagram_channel_passes_data_tiny_mtu() {
    setup_logging();
    // 8 bytes is the IPv4 minimum segment size. Let's try that
    let (client, server) = get_pair(Some(8)).await;

    let client_mux = Multiplexor::new(client, None, None);
    let server_mux = Multiplexor::new(server, None, None);

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
            .send_datagram(Datagram {
                flow_id: 1,
                target_host: Bytes::from_static(b"example.com"),
                target_port: 53,
                data: payload.clone(),
            })
            .await
            .unwrap();
        debug!("Client awaiting datagram");
        let recvd = client_mux.get_datagram().await.unwrap();
        assert_eq!(recvd.flow_id, 1);
        assert_eq!(*recvd.target_host, *b"example.com");
        assert_eq!(recvd.target_port, 53);
        assert_eq!(recvd.data, payload);
    }
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn datagram_channel_passes_data() {
    setup_logging();
    let (client, server) = get_pair(None).await;

    let client_mux = Multiplexor::new(client, None, None);
    let server_mux = Multiplexor::new(server, None, None);

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
            .send_datagram(Datagram {
                flow_id: 1,
                target_host: Bytes::from_static(b"example.com"),
                target_port: 53,
                data: payload.clone(),
            })
            .await
            .unwrap();
        debug!("Client awaiting datagram");
        let recvd = client_mux.get_datagram().await.unwrap();
        assert_eq!(*recvd.target_host, *b"example.com");
        assert_eq!(recvd.target_port, 53);
        assert_eq!(recvd.flow_id, 1);
        assert_eq!(recvd.data, payload);
    }
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn test_datagram_reject_long_host() {
    setup_logging();
    let (client, server) = get_pair(None).await;

    let client_mux = Multiplexor::new(client, None, None);
    let server_mux = Multiplexor::new(server, None, None);
    // Make it 256 bytes long
    let long_host = Bytes::from(b"example1".repeat(32));
    let data = Bytes::from_static(b"hello");
    client_mux
        .send_datagram(Datagram {
            flow_id: 1,
            target_host: long_host.clone(),
            target_port: 53,
            data: data.clone(),
        })
        .await
        .unwrap_err();
    // Try one fewer byte
    let long_host2 = long_host.slice(1..);
    client_mux
        .send_datagram(Datagram {
            flow_id: 1,
            target_host: long_host2.clone(),
            target_port: 53,
            data: data.clone(),
        })
        .await
        .unwrap();
    let result = server_mux.get_datagram().await.unwrap();
    assert_eq!(result.target_host, long_host2);
    assert_eq!(result.target_port, 53);
    assert_eq!(result.flow_id, 1);
    assert_eq!(result.data, data);
}

#[tokio::test]
#[cfg(not(loom))]
async fn connected_stream_passes_data_tiny_mtu_rwndminusone() {
    setup_logging();
    let (client, server) = get_pair(Some(8)).await;

    let options = crate::config::Options::new()
        .rwnd(4)
        .default_rwnd_threshold(4 - 1);

    let client_mux = Multiplexor::new(client, Some(options), None);
    let server_mux = Multiplexor::new(server, Some(options), None);

    let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let len = input_bytes.len();
    let input_bytes_clone = input_bytes.clone();

    let server_task = tokio::spawn(async move {
        let mut conn = server_mux.accept_stream_channel().await.unwrap();
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

    let mut conn = client_mux.new_stream_channel(&[], 0).await.unwrap();
    while output_bytes.len() < len {
        let mut buf = [0u8; 2048];
        let bytes = conn.read(&mut buf).await.unwrap();
        if bytes == 0 {
            break;
        }
        output_bytes.extend(&buf[..bytes]);
        debug!("Read {} bytes", output_bytes.len());
    }

    assert_eq!(input_bytes, output_bytes);
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn connected_stream_passes_data_tiny_mtu_with_keepalive() {
    setup_logging();
    let (client, server) = get_pair(Some(1)).await;

    let client_option = crate::config::Options {
        keepalive_interval: crate::timing::OptionalDuration::from_secs(1),
        ..Default::default()
    };
    let client_mux = Multiplexor::new(client, Some(client_option), None);
    let server_mux = Multiplexor::new(server, None, None);

    let input_bytes: Vec<u8> = (0..1024 * 256).map(|_| rand::random::<u8>()).collect();
    let len = input_bytes.len();
    let input_bytes_clone = input_bytes.clone();

    let client_task = tokio::spawn(async move {
        let mut output_bytes: Vec<u8> = vec![];
        let mut conn = client_mux.new_stream_channel(&[], 0).await.unwrap();
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
    });
    let mut conn = server_mux.accept_stream_channel().await.unwrap();
    conn.write_all(&input_bytes_clone).await.unwrap();
    info!("Done send");
    conn.shutdown().await.unwrap();
    debug!("Waiting for client task to finish");
    client_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn connected_stream_passes_data_tiny_mtu() {
    setup_logging();
    let (client, server) = get_pair(Some(8)).await;

    let client_mux = Multiplexor::new(client, None, None);
    let server_mux = Multiplexor::new(server, None, None);

    let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let len = input_bytes.len();
    let input_bytes_clone = input_bytes.clone();

    let server_task = tokio::spawn(async move {
        let mut conn = server_mux.accept_stream_channel().await.unwrap();
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

    let mut conn = client_mux.new_stream_channel(&[], 0).await.unwrap();
    while output_bytes.len() < len {
        let mut buf = [0u8; 2048];
        let bytes = conn.read(&mut buf).await.unwrap();
        if bytes == 0 {
            break;
        }
        output_bytes.extend(&buf[..bytes]);
        debug!("Read {} bytes", output_bytes.len());
    }

    assert_eq!(input_bytes, output_bytes);
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn connected_stream_passes_data() {
    setup_logging();
    let (client, server) = get_pair(None).await;

    let client_mux = Multiplexor::new(client, None, None);
    let server_mux = Multiplexor::new(server, None, None);

    let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let len = input_bytes.len();
    let input_bytes_clone = input_bytes.clone();

    let server_task = tokio::spawn(async move {
        let mut conn = server_mux.accept_stream_channel().await.unwrap();
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

    let mut conn = client_mux.new_stream_channel(&[], 0).await.unwrap();
    while output_bytes.len() < len {
        let mut buf = [0u8; 2048];
        let bytes = conn.read(&mut buf).await.unwrap();
        if bytes == 0 {
            break;
        }
        output_bytes.extend(&buf[..bytes]);
        debug!("Read {} bytes", output_bytes.len());
    }

    assert_eq!(input_bytes, output_bytes);
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn connected_stream_passes_data_one_sided_lots() {
    setup_logging();
    let (client, server) = get_pair(None).await;

    let client_mux = Multiplexor::new(client, None, None);
    let server_mux = Multiplexor::new(server, None, None);

    let input_bytes: Vec<u8> = (0..(32 * 0x20000)).map(|_| rand::random::<u8>()).collect();
    let len = input_bytes.len();
    let input_bytes_clone = input_bytes.clone();

    let server_task = tokio::spawn(async move {
        let mut conn = server_mux.accept_stream_channel().await.unwrap();
        let mut i = 0;
        while i < input_bytes_clone.len() {
            conn.write_all(&input_bytes_clone[i..i + 32]).await.unwrap();
            i += 32;
        }
        info!("Done send");
        conn.shutdown().await.unwrap();
    });

    let mut output_bytes: Vec<u8> = vec![];

    let mut conn = client_mux.new_stream_channel(&[], 0).await.unwrap();
    conn.shutdown().await.unwrap();
    while output_bytes.len() < len {
        let mut buf = [0u8; 64];
        let bytes = conn.read(&mut buf).await.unwrap();
        if bytes == 0 {
            break;
        }
        output_bytes.extend(&buf[..bytes]);
        debug!("Read {} bytes", output_bytes.len());
    }

    assert_eq!(input_bytes, output_bytes);
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn test_shutdown_has_effect() {
    setup_logging();
    let (client, server) = get_pair(None).await;

    let client_mux = Multiplexor::new(client, None, None);
    let server_mux = Multiplexor::new(server, None, None);

    let server_task = tokio::spawn(async move {
        let mut conn = server_mux.accept_stream_channel().await.unwrap();
        conn.shutdown().await.unwrap();
        conn.write_all(b"hello").await.unwrap_err();
    });

    let mut conn = client_mux.new_stream_channel(&[], 0).await.unwrap();
    conn.shutdown().await.unwrap();
    conn.write_all(b"hello").await.unwrap_err();
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(not(loom))]
async fn test_contention() {
    const NUM_CONCURRENT: usize = 16;
    const EACH_JOB_WRITES: usize = 16;
    setup_logging();
    let (client, server) = get_pair(None).await;

    let client_mux = Multiplexor::new(client, None, None);
    let server_mux = Multiplexor::new(server, None, None);

    let payload: Bytes = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let len = payload.len();
    let s_payload = payload.dupe();

    let mut jobs = tokio::task::JoinSet::new();
    jobs.spawn(async move {
        let mut server_jobs = tokio::task::JoinSet::new();
        for _ in 0..NUM_CONCURRENT {
            let mut stream = server_mux.accept_stream_channel().await.unwrap();
            let s_payload = s_payload.dupe();
            server_jobs.spawn(async move {
                let mut buf = vec![0; len];
                for _ in 0..EACH_JOB_WRITES {
                    stream.write_all(&s_payload).await.unwrap();
                    stream.read_exact(&mut buf).await.unwrap();
                    // No check for correctness as this should be guaranteed by tests
                }
                stream.shutdown().await.unwrap();
            });
        }
        while let Some(res) = server_jobs.join_next().await {
            res.unwrap();
        }
    });
    for _ in 0..NUM_CONCURRENT {
        let mut stream = client_mux.new_stream_channel(&[], 0).await.unwrap();
        jobs.spawn(async move {
            let mut buf = vec![0; len];
            for _ in 0..EACH_JOB_WRITES {
                stream.read_exact(&mut buf).await.unwrap();
                stream.write_all(&buf).await.unwrap();
            }
            stream.shutdown().await.unwrap();
        });
    }
    while let Some(res) = jobs.join_next().await {
        res.unwrap();
    }
}

#[cfg(feature = "tungstenite")]
#[tokio::test(flavor = "multi_thread")]
#[cfg(not(loom))]
async fn test_with_tcpsocket() {
    setup_logging();
    for _ in 0..16 {
        test_with_tcpsocket_inner().await;
    }
}
#[cfg(feature = "tungstenite")]
#[cfg(not(loom))]
async fn test_with_tcpsocket_inner() {
    use tokio_tungstenite::tungstenite::protocol::Role;
    const SINGLE_WRITE_LEN: usize = 4096;
    const ITERATIONS: usize = 256;
    let s_socket = tokio::net::TcpListener::bind(("::1", 0)).await.unwrap();
    let s_addr = s_socket.local_addr().unwrap();
    let all_payload: Bytes = (0..SINGLE_WRITE_LEN * ITERATIONS)
        .map(|_| rand::random::<u8>())
        .collect();
    let mut s_payload = all_payload.dupe();
    tokio::spawn(async move {
        let tcpstream = s_socket.accept().await.unwrap().0;
        let server = WebSocketStream::from_raw_socket(tcpstream, Role::Server, None).await;
        let mux = Multiplexor::new(server, None, None);
        let mut stream = mux.accept_stream_channel().await.unwrap();
        for _ in 0..ITERATIONS {
            let payload = s_payload.split_to(SINGLE_WRITE_LEN);
            stream.write_all(&payload).await.unwrap();
        }
        stream.shutdown().await.unwrap();
    });
    let tcpstream = tokio::net::TcpStream::connect(s_addr).await.unwrap();
    let client = WebSocketStream::from_raw_socket(tcpstream, Role::Client, None).await;
    let mux = Multiplexor::new(client, None, None);
    let mut stream = mux.new_stream_channel(&[], 0).await.unwrap();
    stream.shutdown().await.unwrap();
    // Make sure any mishandling of half-close pop up in the test
    tokio::time::sleep(std::time::Duration::from_millis(rand::random_range(0..500))).await;
    for i in 0..ITERATIONS {
        let mut buf = vec![0; SINGLE_WRITE_LEN];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            all_payload[i * SINGLE_WRITE_LEN..(i + 1) * SINGLE_WRITE_LEN],
            buf
        );
    }
}

#[tokio::test]
#[cfg(not(loom))]
async fn test_early_eof_detected() {
    setup_logging();
    for _ in 0..64 {
        test_early_eof_detected_inner().await;
    }
}

#[cfg(not(loom))]
async fn test_early_eof_detected_inner() {
    let (client, server) = get_pair(None).await;

    let client_mux = Multiplexor::new(client, None, None);
    let server_mux = Multiplexor::new(server, None, None);

    let input_bytes: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
    let len = input_bytes.len();
    let input_bytes_clone = input_bytes.clone();

    let server_task = tokio::spawn(async move {
        let mut conn = server_mux.accept_stream_channel().await.unwrap();
        conn.write_all(&input_bytes_clone).await.unwrap();
        info!("Done send");
    });

    let mut output_bytes: Vec<u8> = vec![];

    let mut conn = client_mux.new_stream_channel(&[], 0).await.unwrap();
    while output_bytes.len() < len + 2 {
        let mut buf = [0u8; 2048];
        let bytes = conn.read(&mut buf).await.unwrap();
        if bytes == 0 {
            break;
        }
        output_bytes.extend(&buf[..bytes]);
        debug!("Read {} bytes", output_bytes.len());
    }

    assert_eq!(input_bytes, output_bytes);
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn test_close_port_behaviour() {
    setup_logging();
    let (mut client, server) = get_pair(None).await;
    // Let's handle the client side of the handshake by hand
    let server_mux = Multiplexor::new(server, None, None);

    let server_task = tokio::spawn(async move {
        // In conn1 we shut down the write side properly and check for `Finish`
        // We deliberately `accept` in the "client" side to demonstrate
        // that the multiplexor is fully symmetric
        let mut conn1 = server_mux.new_stream_channel(&[], 0).await.unwrap();
        conn1.shutdown().await.unwrap();
        drop(conn1);
        // In conn2 we just drop the connection and check for `Reset`
        // This time we  `accept` in the "server" side, just for fun
        let conn2 = server_mux.accept_stream_channel().await.unwrap();
        drop(conn2);
    });
    let Message::Binary(payload) = client.next().await.unwrap().unwrap() else {
        panic!("Expected a binary message");
    };
    let frame = frame::Frame::try_from(payload).unwrap();
    let Frame {
        payload: frame::Payload::Connect(_),
        id: flow_id,
    } = frame
    else {
        panic!("Expected a Connect frame");
    };
    client
        .send(Message::Binary(
            frame::Frame::new_acknowledge(flow_id, 10).finalize().into(),
        ))
        .await
        .unwrap();
    // Expecting a `Finish` frame
    let Message::Binary(payload) = client.next().await.unwrap().unwrap() else {
        panic!("Expected a binary message");
    };
    let frame = frame::Frame::try_from(payload).unwrap();
    let Frame {
        payload: frame::Payload::Finish,
        id: flow_id2,
    } = frame
    else {
        panic!("Expected a Finish frame");
    };
    assert_eq!(flow_id, flow_id2);
    // Send a `Connect` frame to conn2
    client
        .send(Message::Binary(
            frame::Frame::new_connect(&[], 0, 41352u32, 20)
                .finalize()
                .into(),
        ))
        .await
        .unwrap();
    // Expecting a `Acknowledge` frame
    let Message::Binary(payload) = client.next().await.unwrap().unwrap() else {
        panic!("Expected a binary message");
    };
    let frame = frame::Frame::try_from(payload).unwrap();
    let Frame {
        payload: frame::Payload::Acknowledge(_),
        id: flow_id,
    } = frame
    else {
        panic!("Expected a Acknowledge frame");
    };
    assert_eq!(flow_id, 41352);
    // Expecting a `Reset` frame
    let Message::Binary(payload) = client.next().await.unwrap().unwrap() else {
        panic!("Expected a binary message");
    };
    let frame = frame::Frame::try_from(payload).unwrap();
    let Frame {
        payload: frame::Payload::Reset,
        id: flow_id,
    } = frame
    else {
        panic!("Expected a Reset frame");
    };
    assert_eq!(flow_id, 41352);
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn test_several_channels() {
    setup_logging();
    let (client, server) = get_pair(None).await;

    let client_mux = Multiplexor::new(client, None, None);
    let server_mux = Multiplexor::new(server, None, None);

    let server_task = tokio::spawn(async move {
        let mut conn1 = server_mux.accept_stream_channel().await.unwrap();
        info!("server conn1 = {:?}", conn1);
        let mut conn2 = server_mux.accept_stream_channel().await.unwrap();
        info!("server conn2 = {:?}", conn2);
        let mut conn3 = server_mux.accept_stream_channel().await.unwrap();
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
    let mut conn1 = client_mux.new_stream_channel(&[], 0).await.unwrap();
    info!("client conn1 = {:?}", conn1);
    let mut conn2 = client_mux.new_stream_channel(&[], 0).await.unwrap();
    info!("client conn2 = {:?}", conn2);
    let mut conn3 = client_mux.new_stream_channel(&[], 0).await.unwrap();
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

#[tokio::test]
#[cfg(not(loom))]
async fn test_flow_id_contention_will_give_up() {
    setup_logging();
    let (client, mut server) = get_pair(None).await;

    let client_mux = Multiplexor::new(client, None, None);

    let server_task = tokio::spawn(async move {
        // This side receives frames `Connect` and simply `Reset`s them
        while let Some(message) = server.next().await {
            let message = message.unwrap();
            let Message::Binary(payload) = message else {
                continue;
            };
            let frame = frame::Frame::try_from(payload).unwrap();
            if matches!(frame.payload, crate::frame::Payload::Connect(_)) {
                debug!("Server received Connect frame, sending Reset");
                let reset_frame = frame::Frame::new_reset(frame.id);
                server
                    .send(Message::Binary((&reset_frame).into()))
                    .await
                    .unwrap();
            }
        }
    });
    let stream1 = client_mux.new_stream_channel(&[], 0).await;
    assert!(matches!(stream1.unwrap_err(), Error::FlowIdRejected));
    drop(client_mux);
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn test_flow_id_contention_can_succeed() {
    setup_logging();
    let (client, mut server) = get_pair(None).await;

    let client_mux = Multiplexor::new(client, None, None);

    let (serverside_received_ports_tx, serverside_received_ports_rx) = oneshot::channel();

    let server_task = tokio::spawn(async move {
        // This side receives frames `Connect` and `Reset`s the first one
        let mut rx_flow_ids = (0, 0);
        let message = server.next().await.unwrap().unwrap();
        let Message::Binary(payload) = message else {
            return;
        };
        let frame = frame::Frame::try_from(payload).unwrap();
        rx_flow_ids.0 = frame.id;
        if matches!(frame.payload, crate::frame::Payload::Connect(_)) {
            debug!("Server received the first Connect frame, sending Reset");
            let reset_frame = frame::Frame::new_reset(frame.id);
            server
                .send(Message::Binary((&reset_frame).into()))
                .await
                .unwrap();
        }

        let message = server.next().await.unwrap().unwrap();
        let Message::Binary(payload) = message else {
            return;
        };
        let frame = frame::Frame::try_from(payload).unwrap();
        rx_flow_ids.1 = frame.id;
        if matches!(frame.payload, crate::frame::Payload::Connect(_)) {
            debug!("Server received the second Connect frame, sending Acknowledge");
            let reset_frame = frame::Frame::new_acknowledge(frame.id, 10);
            server
                .send(Message::Binary((&reset_frame).into()))
                .await
                .unwrap();
        }
        serverside_received_ports_tx.send(rx_flow_ids).unwrap();
    });
    let stream1 = client_mux.new_stream_channel(&[], 0).await.unwrap();
    drop(client_mux);
    let (_, server_flow_id2) = serverside_received_ports_rx.await.unwrap();
    assert_eq!(stream1.flow_id, server_flow_id2);
    assert_eq!(
        stream1
            .psh_send_remaining
            .load(std::sync::atomic::Ordering::Relaxed),
        10
    );
    debug!("Waiting for server task to finish");
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn test_bind_request() {
    setup_logging();
    let (client, server) = get_pair(None).await;

    let allow_bind_config = crate::config::Options {
        bind_buffer_size: 16,
        ..Default::default()
    };

    let client_mux = Multiplexor::new(client, Some(allow_bind_config), None);
    let server_mux = Multiplexor::new(server, None, None);

    let server_task = tokio::spawn(async move {
        let request = server_mux
            .request_bind(b"testbind", 0, BindType::Datagram)
            .await
            .unwrap();
        assert!(request);
        let request = server_mux
            .request_bind(b"testbind2", 40, BindType::Stream)
            .await
            .unwrap();
        assert!(!request);
        // server is configured to refuse bind requests
        let result = server_mux.next_bind_request().await.unwrap_err();
        assert!(matches!(result, Error::UnsupportedOperation));
        let request = server_mux
            .request_bind(b"testbind3", 8011, BindType::Stream)
            .await
            .unwrap();
        assert!(!request);
    });
    let request = client_mux.next_bind_request().await.unwrap();
    assert_eq!(request.bind_type(), BindType::Datagram);
    assert_ne!(request.flow_id(), 0);
    assert_eq!(request.host(), b"testbind");
    assert_eq!(request.port(), 0);
    request.reply(true).unwrap();
    let request = client_mux.next_bind_request().await.unwrap();
    assert_eq!(request.bind_type(), BindType::Stream);
    assert_ne!(request.flow_id(), 0);
    assert_eq!(request.host(), b"testbind2");
    assert_eq!(request.port(), 40);
    drop(request);
    let request = client_mux
        .request_bind(b"testbindc", 80, BindType::Stream)
        .await
        .unwrap();
    assert!(!request);
    let request = client_mux.next_bind_request().await.unwrap();
    assert_eq!(request.bind_type(), BindType::Stream);
    assert_ne!(request.flow_id(), 0);
    assert_eq!(request.host(), b"testbind3");
    assert_eq!(request.port(), 8011);
    request.reply(false).unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
#[cfg(not(loom))]
async fn test_timeout_if_no_pong_1() {
    setup_logging();
    // use the mock websocket for this test because tungstenite always auto-Pongs for us
    let (client, server) = mock::get_pair(None).await;
    let keepalive_config = crate::config::Options {
        keepalive_interval: crate::timing::OptionalDuration::from_secs(1),
        keepalive_timeout: crate::timing::OptionalDuration::from_secs(2),
        ..Default::default()
    };
    let client_mux = Multiplexor::new(client, Some(keepalive_config), None);
    let _server_mux = Multiplexor::new(server, None, None);
    let r = tokio::time::timeout(std::time::Duration::from_secs(3), client_mux.get_datagram())
        .await
        .expect("Expected the timeout to produce `Ok`");
    // Expect an error instead of elapsed timeout
    let res = r.expect_err("Expected `get_datagram` to error out due to no Pong");
    assert!(matches!(res, Error::Closed));
    // There is no way to check what reason the task exited as of now, except for reading the logs
}

#[tokio::test]
#[cfg(not(loom))]
async fn test_timeout_if_no_pong_2() {
    setup_logging();
    // use the mock websocket for this test because tungstenite always auto-Pongs for us
    let (client, server) = mock::get_pair(None).await;
    let keepalive_config = crate::config::Options {
        keepalive_interval: crate::timing::OptionalDuration::from_secs(1),
        keepalive_timeout: crate::timing::OptionalDuration::from_secs(3),
        ..Default::default()
    };
    let client_mux = Multiplexor::new(client, Some(keepalive_config), None);
    let _server_mux = Multiplexor::new(server, None, None);
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        client_mux.accept_stream_channel(),
    )
    .await
    .expect("Expected the timeout to produce `Ok`");
    // Expect an error instead of elapsed timeout
    let res = r.expect_err("Expected `accept_stream_channel` to error out due to no Pong");
    assert!(matches!(res, Error::Closed));
    // There is no way to check what reason the task exited as of now, except for reading the logs
}

#[tokio::test]
#[cfg(not(loom))]
async fn test_no_timeout_if_no_keepalive() {
    // Make sure that if keepalive is disabled, no Pong timeout occurs
    setup_logging();
    let (client, server) = mock::get_pair(None).await;
    let client_mux = Multiplexor::new(client, None, None);
    let _server_mux = Multiplexor::new(server, None, None);
    // Default is no keepalive
    let r = tokio::time::timeout(std::time::Duration::from_secs(5), client_mux.get_datagram())
        .await
        .expect_err("Expected the timeout to timeout");
    assert!(matches!(r, tokio::time::error::Elapsed { .. }));
}
