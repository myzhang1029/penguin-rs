use super::*;
use crate::{arg::ServerUrl, parse_remote::Remote};
use once_cell::sync::Lazy;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    time::Duration,
};
#[cfg(any(feature = "tests-real-internet4", feature = "tests-real-internet6"))]
use tokio::net::UdpSocket;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[ctor::ctor]
fn test_setup_log() {
    use tracing_subscriber::{filter, fmt, prelude::*};
    let fmt_layer = fmt::Layer::default()
        .compact()
        .with_thread_ids(true)
        .with_timer(fmt::time::time())
        .with_writer(std::io::stderr);
    tracing_subscriber::registry()
        .with(filter::LevelFilter::DEBUG)
        .with(fmt_layer)
        .init();
}

fn make_server_args(host: &str, port: u16) -> arg::ServerArgs {
    arg::ServerArgs {
        host: host.to_string(),
        port,
        backend: None,
        obfs: false,
        not_found_resp: "404".to_string(),
        ws_psk: None,
        tls_ca: None,
        tls_cert: None,
        tls_key: None,
        _pid: false,
        _socks5: false,
        _reverse: false,
        _auth: None,
        _authfile: None,
        _keepalive: 0,
        _key: None,
    }
}

fn make_client_args(servhost: &str, servport: u16, remotes: Vec<Remote>) -> arg::ClientArgs {
    arg::ClientArgs {
        server: ServerUrl::from_str(&format!("ws://{servhost}:{servport}/ws")).unwrap(),
        remote: remotes,
        ws_psk: None,
        keepalive: 0,
        max_retry_count: 10,
        max_retry_interval: 10,
        proxy: None,
        header: vec![],
        tls_ca: None,
        tls_cert: None,
        tls_key: None,
        tls_skip_verify: false,
        hostname: Some(http::HeaderValue::from_static("localhost")),
        _pid: false,
        _fingerprint: None,
        _auth: None,
    }
}

#[tokio::test]
async fn test_it_works() {
    static SERVER_ARGS: Lazy<arg::ServerArgs> = Lazy::new(|| make_server_args("127.0.0.1", 30554));

    static CLIENT_ARGS: Lazy<arg::ClientArgs> = Lazy::new(|| {
        make_client_args(
            "127.0.0.1",
            30554,
            vec![Remote::from_str("127.0.0.1:21628:127.0.0.1:10807").unwrap()],
        )
    });

    let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let second_task = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:10807").await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut output_bytes = vec![0u8; input_len];
        stream.read_exact(&mut output_bytes).await.unwrap();
        output_bytes
    });

    let client_task = tokio::spawn(crate::client::client_main(&CLIENT_ARGS));
    let server_task = tokio::spawn(crate::server::server_main(&SERVER_ARGS));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut sock = TcpStream::connect("127.0.0.1:21628").await.unwrap();
    sock.write_all(&input_bytes).await.unwrap();
    sock.shutdown().await.unwrap();
    let output_bytes = second_task.await.unwrap();
    assert_eq!(input_bytes, output_bytes);
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
async fn test_it_works_v6() {
    static SERVER_ARGS: Lazy<arg::ServerArgs> = Lazy::new(|| make_server_args("::1", 27254));

    static CLIENT_ARGS: Lazy<arg::ClientArgs> = Lazy::new(|| {
        make_client_args(
            "[::1]",
            27254,
            vec![Remote::from_str("[::1]:20246:[::1]:30389").unwrap()],
        )
    });

    let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let second_task = tokio::spawn(async move {
        let listener = TcpListener::bind("[::1]:30389").await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut output_bytes = vec![0u8; input_len];
        stream.read_exact(&mut output_bytes).await.unwrap();
        output_bytes
    });

    let client_task = tokio::spawn(crate::client::client_main(&CLIENT_ARGS));
    let server_task = tokio::spawn(crate::server::server_main(&SERVER_ARGS));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut sock = TcpStream::connect("[::1]:20246").await.unwrap();
    sock.write_all(&input_bytes).await.unwrap();
    sock.shutdown().await.unwrap();
    let output_bytes = second_task.await.unwrap();
    assert_eq!(input_bytes, output_bytes);
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
async fn test_socks5_connect_reliability_v4() {
    static SERVER_ARGS: Lazy<arg::ServerArgs> = Lazy::new(|| make_server_args("127.0.0.1", 24895));
    static CLIENT_ARGS: Lazy<arg::ClientArgs> = Lazy::new(|| {
        make_client_args(
            "127.0.0.1",
            24895,
            vec![Remote::from_str("127.0.0.1:21330:socks").unwrap()],
        )
    });

    let client_task = tokio::spawn(crate::client::client_main(&CLIENT_ARGS));
    let server_task = tokio::spawn(crate::server::server_main(&SERVER_ARGS));

    // Use a small buffer to simulate a HTTP request: if `flush` or `shutdown` is not called, the
    // server will not receive the data.
    let input_bytes: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let target_server_task = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:26307").await.unwrap();
        for _ in 0..64 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut output_bytes = vec![0u8; input_len];
            stream.read_exact(&mut output_bytes).await.unwrap();
            stream.write_all(&output_bytes).await.unwrap();
        }
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    // It would be nice to use `loom`
    for _ in 0..64 {
        let mut sock = TcpStream::connect("127.0.0.1:21330").await.unwrap();
        sock.write_all(b"\x05\x01\x00").await.unwrap();
        let mut buf = vec![0u8; 32];
        let n = sock.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..n], b"\x05\x00");
        sock.write_all(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x66\xc3")
            .await
            .unwrap();
        let n = sock.read(&mut buf).await.unwrap();
        assert!(n > 3);
        assert_eq!(&buf[..3], b"\x05\x00\x00");
        sock.write_all(&input_bytes).await.unwrap();
        let mut output_bytes = vec![0u8; input_len];
        sock.read_exact(&mut output_bytes).await.unwrap();
        assert_eq!(input_bytes, output_bytes);
    }

    target_server_task.await.unwrap();
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
async fn test_socks5_connect_reliability_v6() {
    // "v6" means that the target server is IPv6, but the client here is IPv4 here to test their interaction.
    static SERVER_ARGS: Lazy<arg::ServerArgs> = Lazy::new(|| make_server_args("127.0.0.1", 32233));
    static CLIENT_ARGS: Lazy<arg::ClientArgs> = Lazy::new(|| {
        make_client_args(
            "127.0.0.1",
            32233,
            vec![Remote::from_str("127.0.0.1:13261:socks").unwrap()],
        )
    });

    let client_task = tokio::spawn(crate::client::client_main(&CLIENT_ARGS));
    let server_task = tokio::spawn(crate::server::server_main(&SERVER_ARGS));

    // Use a small buffer to simulate a HTTP request: if `flush` or `shutdown` is not called, the
    // server will not receive the data.
    let input_bytes: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let target_server_task = tokio::spawn(async move {
        let listener = TcpListener::bind("[::1]:13384").await.unwrap();
        for _ in 0..64 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut output_bytes = vec![0u8; input_len];
            stream.read_exact(&mut output_bytes).await.unwrap();
            stream.write_all(&output_bytes).await.unwrap();
        }
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    for _ in 0..64 {
        let mut sock = TcpStream::connect("127.0.0.1:13261").await.unwrap();
        sock.write_all(b"\x05\x01\x00").await.unwrap();
        let mut buf = vec![0u8; 32];
        let n = sock.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..n], b"\x05\x00");
        sock.write_all(b"\x05\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x34\x48")
            .await
            .unwrap();
        let n = sock.read(&mut buf).await.unwrap();
        assert!(n > 3);
        assert_eq!(&buf[..3], b"\x05\x00\x00");
        sock.write_all(&input_bytes).await.unwrap();
        let mut output_bytes = vec![0u8; input_len];
        sock.read_exact(&mut output_bytes).await.unwrap();
        assert_eq!(input_bytes, output_bytes);
    }

    target_server_task.await.unwrap();
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
async fn test_socks5_udp_v4() {
    static SERVER_ARGS: Lazy<arg::ServerArgs> = Lazy::new(|| make_server_args("127.0.0.1", 14119));
    static CLIENT_ARGS: Lazy<arg::ClientArgs> = Lazy::new(|| {
        make_client_args(
            "127.0.0.1",
            14119,
            vec![Remote::from_str("127.0.0.1:30711:socks").unwrap()],
        )
    });

    let client_task = tokio::spawn(crate::client::client_main(&CLIENT_ARGS));
    let server_task = tokio::spawn(crate::server::server_main(&SERVER_ARGS));

    let input_bytes: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let target_server_task = tokio::spawn(async move {
        let listener = UdpSocket::bind("127.0.0.1:14119").await.unwrap();
        for _ in 0..64 {
            let mut buf = vec![0u8; input_len];
            let (n, src) = listener.recv_from(&mut buf).await.unwrap();
            listener.send_to(&buf[..n], src).await.unwrap();
        }
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    for _ in 0..64 {
        let mut sock = TcpStream::connect("127.0.0.1:30711").await.unwrap();
        sock.write_all(b"\x05\x01\x00").await.unwrap();
        let mut buf = vec![0u8; 32];
        let n = sock.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..n], b"\x05\x00");
        sock.write_all(b"\x05\x03\x00\x01\x7f\x00\x00\x01\x37\x27")
            .await
            .unwrap();
        let n = sock.read(&mut buf).await.unwrap();
        assert!(n > 3);
        assert_eq!(&buf[..3], b"\x05\x00\x00");
        let bind_addr = &buf[4..n - 2];
        let bind_port = u16::from_be_bytes([buf[n - 2], buf[n - 1]]);
        let (bind_addr, udp_socket) = match buf[3] {
            1 => {
                let mut addr = [0u8; 4];
                addr.copy_from_slice(bind_addr);
                let bind_addr = IpAddr::V4(Ipv4Addr::from(addr));
                let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                (bind_addr, udp_socket)
            }
            4 => {
                let mut addr = [0u8; 16];
                addr.copy_from_slice(bind_addr);
                let bind_addr = IpAddr::V6(Ipv6Addr::from(addr));
                let udp_socket = UdpSocket::bind("[::1]:0").await.unwrap();
                (bind_addr, udp_socket)
            }
            _ => unreachable!(),
        };
        udp_socket.connect((bind_addr, bind_port)).await.unwrap();
        let request_header = vec![0x00, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x37, 0x27];
        let mut request = request_header.clone();
        request.extend(&input_bytes);
        udp_socket.send(&request).await.unwrap();
        let mut buf = vec![0u8; input_len + request_header.len()];
        let n = udp_socket.recv(&mut buf).await.unwrap();
        assert_eq!(n, input_len + request_header.len());
        assert_eq!(&buf[request_header.len()..], &input_bytes);
    }

    target_server_task.await.unwrap();
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
async fn test_socks5_udp_v6() {
    // "v6" means that the target server is IPv6, but the client here is IPv4 here to test their interaction.
    static SERVER_ARGS: Lazy<arg::ServerArgs> = Lazy::new(|| make_server_args("127.0.0.1", 25347));
    static CLIENT_ARGS: Lazy<arg::ClientArgs> = Lazy::new(|| {
        make_client_args(
            "127.0.0.1",
            25347,
            vec![Remote::from_str("127.0.0.1:26396:socks").unwrap()],
        )
    });

    let client_task = tokio::spawn(crate::client::client_main(&CLIENT_ARGS));
    let server_task = tokio::spawn(crate::server::server_main(&SERVER_ARGS));

    let input_bytes: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let target_server_task = tokio::spawn(async move {
        let listener = UdpSocket::bind("127.0.0.1:25347").await.unwrap();
        for _ in 0..64 {
            let mut buf = vec![0u8; input_len];
            let (n, src) = listener.recv_from(&mut buf).await.unwrap();
            listener.send_to(&buf[..n], src).await.unwrap();
        }
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    for _ in 0..64 {
        let mut sock = TcpStream::connect("127.0.0.1:26396").await.unwrap();
        sock.write_all(b"\x05\x01\x00").await.unwrap();
        let mut buf = vec![0u8; 32];
        let n = sock.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..n], b"\x05\x00");
        sock.write_all(b"\x05\x03\x00\x01\x7f\x00\x00\x01\x63\x03")
            .await
            .unwrap();
        let n = sock.read(&mut buf).await.unwrap();
        assert!(n > 3);
        assert_eq!(&buf[..3], b"\x05\x00\x00");
        let bind_addr = &buf[4..n - 2];
        let bind_port = u16::from_be_bytes([buf[n - 2], buf[n - 1]]);
        let (bind_addr, udp_socket) = match buf[3] {
            1 => {
                let mut addr = [0u8; 4];
                addr.copy_from_slice(bind_addr);
                let bind_addr = IpAddr::V4(Ipv4Addr::from(addr));
                let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                (bind_addr, udp_socket)
            }
            4 => {
                let mut addr = [0u8; 16];
                addr.copy_from_slice(bind_addr);
                let bind_addr = IpAddr::V6(Ipv6Addr::from(addr));
                let udp_socket = UdpSocket::bind("[::1]:0").await.unwrap();
                (bind_addr, udp_socket)
            }
            _ => unreachable!(),
        };
        udp_socket.connect((bind_addr, bind_port)).await.unwrap();
        let request_header = vec![0x00, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x63, 0x03];
        let mut request = request_header.clone();
        request.extend(&input_bytes);
        udp_socket.send(&request).await.unwrap();
        let mut buf = vec![0u8; input_len + request_header.len()];
        let n = udp_socket.recv(&mut buf).await.unwrap();
        assert_eq!(n, input_len + request_header.len());
        assert_eq!(&buf[request_header.len()..], &input_bytes);
    }

    target_server_task.await.unwrap();
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
async fn test_socks4_works() {
    static SERVER_ARGS: Lazy<arg::ServerArgs> = Lazy::new(|| make_server_args("127.0.0.1", 10796));
    static CLIENT_ARGS: Lazy<arg::ClientArgs> = Lazy::new(|| {
        make_client_args(
            "127.0.0.1",
            10796,
            vec![Remote::from_str("127.0.0.1:23213:socks").unwrap()],
        )
    });

    let client_task = tokio::spawn(crate::client::client_main(&CLIENT_ARGS));
    let server_task = tokio::spawn(crate::server::server_main(&SERVER_ARGS));

    let input_bytes: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();

    let target_server_task = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:20591").await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut output_bytes = vec![0u8; input_len];
        stream.read_exact(&mut output_bytes).await.unwrap();
        stream.write_all(&output_bytes).await.unwrap();
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut sock = TcpStream::connect("127.0.0.1:23213").await.unwrap();
    // Just put the IP in the domain field to test `socks4a` as well.
    sock.write_all(b"\x04\x01\x50\x6f\x00\x00\x00\x01\x00\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x00")
        .await
        .unwrap();
    sock.flush().await.unwrap();
    let mut buf = vec![0u8; 32];
    let n = sock.read(&mut buf).await.unwrap();
    assert!(n >= 2);
    assert_eq!(&buf[..2], b"\x00\x5a");
    sock.write_all(&input_bytes).await.unwrap();
    let mut output_bytes = vec![0u8; input_len];
    sock.read_exact(&mut output_bytes).await.unwrap();
    assert_eq!(input_bytes, output_bytes);

    target_server_task.await.unwrap();
    server_task.abort();
    client_task.abort();
}

#[cfg(feature = "tests-real-internet4")]
#[tokio::test]
async fn test_it_works_dns_v4() {
    static SERVER_ARGS: Lazy<arg::ServerArgs> = Lazy::new(|| make_server_args("127.0.0.1", 17706));
    static CLIENT_ARGS: Lazy<arg::ClientArgs> = Lazy::new(|| {
        make_client_args(
            "127.0.0.1",
            17706,
            vec![Remote::from_str("127.0.0.1:20326:1.1.1.1:53/udp").unwrap()],
        )
    });

    let client_task = tokio::spawn(crate::client::client_main(&CLIENT_ARGS));
    let server_task = tokio::spawn(crate::server::server_main(&SERVER_ARGS));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    // Just for fun, let's query AAAA here
    let request = b"\x37\x0a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x1c\x00\x01";
    let expected = b"\x37\x0a\x81\x80\x00\x01";
    sock.send_to(request, "127.0.0.1:20326").await.unwrap();
    let mut buf = [0u8; 1024];
    sock.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], expected);
    server_task.abort();
    client_task.abort();
}

#[cfg(feature = "tests-real-internet6")]
#[tokio::test]
async fn test_it_works_dns_v6() {
    static SERVER_ARGS: Lazy<arg::ServerArgs> = Lazy::new(|| make_server_args("[::1]", 16037));
    static CLIENT_ARGS: Lazy<arg::ClientArgs> = Lazy::new(|| {
        make_client_args(
            "[::1]",
            16037,
            vec![Remote::from_str("[::1]:20326:[2606:4700:4700::1111]:53/udp").unwrap()],
        )
    });

    let client_task = tokio::spawn(crate::client::client_main(&CLIENT_ARGS));
    let server_task = tokio::spawn(crate::server::server_main(&SERVER_ARGS));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let sock = UdpSocket::bind("[::]:0").await.unwrap();
    let request = b"\x39\x36\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01";
    let expected = b"\x39\x36\x81\x80\x00\x01";
    sock.send_to(request, ("::1", 20326)).await.unwrap();
    let mut buf = [0u8; 1024];
    sock.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], expected);
    server_task.abort();
    client_task.abort();
}
