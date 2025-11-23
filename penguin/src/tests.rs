use super::*;
use crate::tls::make_tls_identity;
use crate::{arg::ServerUrl, parse_remote::Remote};
use penguin_mux::timing::OptionalDuration;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[allow(unused_imports)]
use std::sync::{LazyLock, OnceLock};
use std::{str::FromStr, time::Duration};
#[cfg(not(all(feature = "nativetls", any(target_os = "macos", target_os = "windows"))))]
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::debug;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
    #[cfg(feature = "deadlock-detection")]
    penguin_mux::deadlock_detection::try_spawn_deadlock_detection();
}

fn make_server_args(host: &str, port: u16) -> arg::ServerArgs {
    arg::ServerArgs {
        host: vec![host.to_string()],
        port: vec![port],
        not_found_resp: "404".to_string(),
        // Very short timeout for testing purposes.
        timeout: OptionalDuration::from_secs(2),
        ..Default::default()
    }
}

fn make_client_args(servhost: &str, servport: u16, remotes: Vec<Remote>) -> arg::ClientArgs {
    arg::ClientArgs {
        server: ServerUrl::from_str(&format!("ws://{servhost}:{servport}/ws")).unwrap(),
        remote: remotes,
        keepalive: OptionalDuration::NONE,
        max_retry_count: 10,
        max_retry_interval: 10,
        tls_skip_verify: false,
        hostname: Some(http::HeaderValue::from_static("localhost")),
        channel_timeout: OptionalDuration::from_secs(10),
        ..Default::default()
    }
}

/// Generate a self-signed server cert into a temporary directory.
/// Returns the path to the directory. The cert is named `cert.pem` and the key is named `privkey.pem`.
#[cfg(not(all(feature = "nativetls", any(target_os = "macos", target_os = "windows"))))]
async fn make_server_cert_ecdsa(dest: Option<&str>) -> (Option<TempDir>, rcgen::Certificate) {
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut dir = None;
    let dir_path = dest.unwrap_or_else(|| {
        dir = Some(TempDir::new().unwrap());
        dir.as_ref().unwrap().path().to_str().unwrap()
    });
    let cert_path = format!("{dir_path}/cert.pem");
    let key_path = format!("{dir_path}/privkey.pem");
    let cert = cert_params.self_signed(&keypair).unwrap();
    let key_pem = keypair.serialize_pem();
    let cert_pem = cert.pem();
    tokio::fs::write(&cert_path, cert_pem).await.unwrap();
    tokio::fs::write(&key_path, key_pem).await.unwrap();
    // Make sure the files actually exist
    assert!(tokio::fs::metadata(&cert_path).await.is_ok());
    assert!(tokio::fs::metadata(&key_path).await.is_ok());
    (dir, cert)
}

#[tokio::test]
async fn test_client_handshake_timeout() {
    static CLIENT_ARGS: OnceLock<arg::ClientArgs> = OnceLock::new();
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();
    let blackhole = TcpListener::bind("[::1]:0").await.unwrap();
    let addr = blackhole.local_addr().unwrap();
    let client_args = arg::ClientArgs {
        server: ServerUrl::from_str(&format!("ws://{addr}/ws")).unwrap(),
        remote: vec![Remote::from_str("[::1]:0:socks").unwrap()],
        keepalive: OptionalDuration::NONE,
        max_retry_count: 1,
        handshake_timeout: OptionalDuration::from_secs(1),
        ..Default::default()
    };
    CLIENT_ARGS.set(client_args).unwrap();
    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let r = crate::client::client_main_inner(
        CLIENT_ARGS.get().unwrap(),
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    )
    .await
    .unwrap_err();
    let crate::client::Error::MaxRetryCountReached(e) = r else {
        panic!("Expected MaxRetryCountReached, got {r:?}");
    };
    assert!(
        matches!(*e, crate::client::Error::HandshakeTimeout),
        "Expected HandshakeTimeout, got {e:?}",
    );
}

#[tokio::test]
async fn test_client_handshake_timeout_will_retry() {
    static CLIENT_ARGS: OnceLock<arg::ClientArgs> = OnceLock::new();
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();
    let blackhole = TcpListener::bind("[::1]:0").await.unwrap();
    let addr = blackhole.local_addr().unwrap();
    let client_args = arg::ClientArgs {
        server: ServerUrl::from_str(&format!("ws://{addr}/ws")).unwrap(),
        remote: vec![Remote::from_str("[::1]:0:socks").unwrap()],
        keepalive: OptionalDuration::NONE,
        max_retry_count: 3,
        handshake_timeout: OptionalDuration::from_secs(1),
        ..Default::default()
    };
    CLIENT_ARGS.set(client_args).unwrap();
    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let initial_time = std::time::Instant::now();
    let r = crate::client::client_main_inner(
        CLIENT_ARGS.get().unwrap(),
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    )
    .await
    .unwrap_err();
    let elapsed = initial_time.elapsed();
    let crate::client::Error::MaxRetryCountReached(e) = r else {
        panic!("Expected MaxRetryCountReached, got {r:?}");
    };
    assert!(
        matches!(*e, crate::client::Error::HandshakeTimeout),
        "Expected HandshakeTimeout, got {e:?}",
    );
    assert!(elapsed.as_secs() > 2);
}

#[tokio::test]
async fn test_it_works() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("127.0.0.1", 30554));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "127.0.0.1",
            30554,
            vec![Remote::from_str("127.0.0.1:21628:127.0.0.1:10807").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let second_task = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:10807").await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut output_bytes = vec![0u8; input_len];
        stream.read_exact(&mut output_bytes).await.unwrap();
        output_bytes
    });
    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));
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
async fn test_server_timeout() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("::1", 22183));
    setup_logging();
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Connect to the socket and do nothing. Make sure the socket is closed
    let mut sock = TcpStream::connect("[::1]:22183").await.unwrap();
    // We expect the server to timeout after 3 seconds, so we allow a longer time and
    // test the socket really timed out
    let mut buf = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(7), sock.read(&mut buf))
        .await
        .expect("This test should not time out");
    if let Ok(len) = result {
        assert_eq!(len, 0, "Expected to read EOF from timed-out socket");
    }
    server_task.abort();
}

#[tokio::test]
async fn test_server_timeout_does_not_interrupt_ws() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("::1", 23224));

    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "[::1]",
            23224,
            vec![Remote::from_str("[::1]:27848:[::1]:17787").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let second_task = tokio::spawn(async move {
        let listener = TcpListener::bind("[::1]:17787").await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut output_bytes = vec![0u8; input_len];
        stream.read_exact(&mut output_bytes).await.unwrap();
        output_bytes
    });

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));
    // Wait much more than the timeout to ensure that any timeout would pop up.
    tokio::time::sleep(Duration::from_secs(8)).await;
    let mut sock = TcpStream::connect("[::1]:27848").await.unwrap();
    sock.write_all(&input_bytes).await.unwrap();
    sock.shutdown().await.unwrap();
    let output_bytes = second_task.await.unwrap();
    assert_eq!(input_bytes, output_bytes);
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
async fn test_it_works_v6() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("::1", 27254));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "[::1]",
            27254,
            vec![Remote::from_str("[::1]:20246:[::1]:30389").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let second_task = tokio::spawn(async move {
        let listener = TcpListener::bind("[::1]:30389").await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut output_bytes = vec![0u8; input_len];
        stream.read_exact(&mut output_bytes).await.unwrap();
        output_bytes
    });

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut sock = TcpStream::connect("[::1]:20246").await.unwrap();
    sock.write_all(&input_bytes).await.unwrap();
    sock.shutdown().await.unwrap();
    let output_bytes = second_task.await.unwrap();
    assert_eq!(input_bytes, output_bytes);
    server_task.abort();
    client_task.abort();
}

// `native_tls` on macOS and Windows doesn't support reading Ed25519 nor ECDSA-based certificates.
#[tokio::test]
#[cfg(not(all(feature = "nativetls", any(target_os = "macos", target_os = "windows"))))]
async fn test_it_works_tls_simple() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: OnceLock<arg::ServerArgs> = OnceLock::new();
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| arg::ClientArgs {
        server: ServerUrl::from_str("wss://127.0.0.1:20353/ws").unwrap(),
        remote: vec![Remote::from_str("127.0.0.1:24368:127.0.0.1:12034").unwrap()],
        ws_psk: None,
        keepalive: OptionalDuration::NONE,
        keepalive_timeout: OptionalDuration::NONE,
        max_retry_count: 10,
        max_retry_interval: 10,
        handshake_timeout: OptionalDuration::NONE,
        proxy: None,
        header: vec![],
        tls_server_name: None,
        tls_ca: None,
        tls_cert: None,
        tls_key: None,
        tls_skip_verify: true,
        hostname: Some(http::HeaderValue::from_static("localhost")),
        channel_timeout: OptionalDuration::from_secs(10),
        _pid: false,
        _fingerprint: None,
        _auth: None,
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let mut serv_cfg = make_server_args("127.0.0.1", 20353);
    let (cert_dir, _) = make_server_cert_ecdsa(None).await;
    let cert_dir = cert_dir.unwrap();
    serv_cfg.tls_cert = Some(format!("{}/cert.pem", cert_dir.path().display()));
    serv_cfg.tls_key = Some(format!("{}/privkey.pem", cert_dir.path().display()));
    SERVER_ARGS.set(serv_cfg).unwrap();

    let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let second_task = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:12034").await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut output_bytes = vec![0u8; input_len];
        stream.read_exact(&mut output_bytes).await.unwrap();
        output_bytes
    });

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        SERVER_ARGS.get().unwrap(),
        &BACKEND_SUPPORTS_HTTP2,
    ));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut sock = TcpStream::connect("127.0.0.1:24368").await.unwrap();
    sock.write_all(&input_bytes).await.unwrap();
    sock.shutdown().await.unwrap();
    let output_bytes = second_task.await.unwrap();
    assert_eq!(input_bytes, output_bytes);
    server_task.abort();
    client_task.abort();
}

// `native_tls` on macOS and Windows doesn't support reading Ed25519 nor ECDSA-based certificates.
#[tokio::test]
#[cfg(unix)]
#[cfg(not(all(feature = "nativetls", any(target_os = "macos", target_os = "windows"))))]
async fn test_tls_reload() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    use crate::tls::tls_connect;

    static SERVER_ARGS: OnceLock<arg::ServerArgs> = OnceLock::new();
    setup_logging();

    let mut serv_cfg = make_server_args("127.0.0.1", 20353);
    let (cert_dir, cert) = make_server_cert_ecdsa(None).await;
    let cert_dir = cert_dir.unwrap();
    let cert_dir_path = cert_dir.path().display().to_string();
    serv_cfg.tls_cert = Some(format!("{cert_dir_path}/cert.pem"));
    serv_cfg.tls_key = Some(format!("{cert_dir_path}/privkey.pem"));
    SERVER_ARGS.set(serv_cfg).unwrap();

    let server_task = tokio::spawn(crate::server::server_main(
        SERVER_ARGS.get().unwrap(),
        &BACKEND_SUPPORTS_HTTP2,
    ));
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Connect to the server and read the certificate
    let stream = tls_connect("127.0.0.1", 20353, "localhost", None, None, None, true)
        .await
        .unwrap();
    #[cfg(feature = "nativetls")]
    {
        let peer_cert = stream
            .get_ref()
            .peer_certificate()
            .unwrap()
            .unwrap()
            .to_der()
            .unwrap();
        assert_eq!(peer_cert, **cert.der());
    }
    #[cfg(feature = "__rustls")]
    {
        let (_, common_state) = stream.get_ref();
        let peer_cert = common_state.peer_certificates().unwrap();
        // Check that the certificate is what we expect
        assert_eq!(peer_cert.len(), 1);
        assert_eq!(peer_cert[0], *cert.der());
    }
    let (_, new_cert) = make_server_cert_ecdsa(Some(&cert_dir_path)).await;
    assert_ne!(new_cert.der(), cert.der());
    // Reload the server configuration by sending SIGUSR1
    let pid = std::process::id();
    let cmd = tokio::process::Command::new("kill")
        .arg("-USR1")
        .arg(pid.to_string())
        .spawn()
        .unwrap()
        .wait()
        .await
        .unwrap();
    assert!(cmd.success(), "Failed to send SIGUSR1 to self");
    // Check that the server has reloaded the certificate
    tokio::time::sleep(Duration::from_secs(1)).await;
    let stream = tls_connect("127.0.0.1", 20353, "localhost", None, None, None, true)
        .await
        .unwrap();
    #[cfg(feature = "nativetls")]
    {
        let peer_cert = stream
            .get_ref()
            .peer_certificate()
            .unwrap()
            .unwrap()
            .to_der()
            .unwrap();
        assert_eq!(peer_cert, **new_cert.der());
    }
    #[cfg(feature = "__rustls")]
    {
        let (_, common_state) = stream.get_ref();
        let peer_cert = common_state.peer_certificates().unwrap();
        // Check that the certificate is what we expect
        assert_eq!(peer_cert.len(), 1);
        assert_eq!(peer_cert[0], *new_cert.der());
    }
    server_task.abort();
}

async fn check_http_host<T: AsyncRead + Unpin>(stream: &mut T, expected_host: &str) {
    let mut reader = tokio::io::BufReader::new(stream);
    let mut buf = String::new();
    while reader.read_line(&mut buf).await.unwrap() > 0 {
        let line = buf.trim_end();
        debug!("HTTP line: {line}");
        if line.is_empty() {
            break;
        }
        if line.to_lowercase().starts_with("host:") {
            let host_value = line[5..].trim();
            assert_eq!(host_value, expected_host);
            return;
        }
        buf.clear();
    }
    panic!("Did not find Host header in HTTP request");
}

// `native_tls` on macOS and Windows doesn't support reading Ed25519 nor ECDSA-based certificates.
#[tokio::test]
#[cfg(not(all(feature = "nativetls", any(target_os = "macos", target_os = "windows"))))]
async fn test_http_host_and_sni() {
    static CLIENT_ARGS_PLAIN: OnceLock<arg::ClientArgs> = OnceLock::new();
    static CLIENT_ARGS_HAS_HOSTNAME: OnceLock<arg::ClientArgs> = OnceLock::new();
    static CLIENT_ARGS_HAS_SNI: OnceLock<arg::ClientArgs> = OnceLock::new();
    static HANDLER_RESOURCES_1: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    static HANDLER_RESOURCES_2: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    static HANDLER_RESOURCES_3: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    // Just make a normal tls listener without penguin server
    let (cert_dir, _) = make_server_cert_ecdsa(None).await;
    let cert_dir = cert_dir.unwrap();
    let cert_path = format!("{}/cert.pem", cert_dir.path().display());
    let key_path = format!("{}/privkey.pem", cert_dir.path().display());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tls_cfg = make_tls_identity(&cert_path, &key_path, None)
        .await
        .unwrap()
        .load_full();
    #[cfg(feature = "__rustls")]
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
    #[cfg(feature = "nativetls")]
    let acceptor = tls_cfg;

    // The client will be in the task and the server will be the main task

    let mut client_args = arg::ClientArgs {
        server: ServerUrl::from_str(&format!("wss://{addr}/ws")).unwrap(),
        remote: vec![Remote::from_str(&format!("0:127.0.0.1:0")).unwrap()],
        max_retry_count: 1,
        max_retry_interval: 1,
        hostname: None,
        tls_server_name: None,
        tls_skip_verify: true,
        ..Default::default()
    };
    CLIENT_ARGS_PLAIN.set(client_args.clone()).unwrap();
    client_args.hostname = Some(http::HeaderValue::from_static("test-hostname"));
    CLIENT_ARGS_HAS_HOSTNAME.set(client_args.clone()).unwrap();
    // Set both hostname and tls_server_name to make sure they each work: i.e.
    // tls_server_name correctly overrides hostname for the SNI part
    client_args.tls_server_name = Some("test-sni".to_string());
    CLIENT_ARGS_HAS_SNI.set(client_args.clone()).unwrap();

    let (next_test_notify_tx, mut next_test_notify_rx) = tokio::sync::mpsc::channel(1);

    let client_task = tokio::spawn(async move {
        // First test
        {
            let (handler_resources, stream_command_rx, datagram_rx) =
                crate::client::HandlerResources::create();
            HANDLER_RESOURCES_1.set(handler_resources).unwrap();
            let client_task = tokio::spawn(crate::client::client_main_inner(
                CLIENT_ARGS_PLAIN.get().unwrap(),
                HANDLER_RESOURCES_1.get().unwrap(),
                stream_command_rx,
                datagram_rx,
            ));
            next_test_notify_rx.recv().await;
            client_task.abort();
        }
        // Second test
        {
            let (handler_resources, stream_command_rx, datagram_rx) =
                crate::client::HandlerResources::create();
            HANDLER_RESOURCES_2.set(handler_resources).unwrap();
            let client_task = tokio::spawn(crate::client::client_main_inner(
                CLIENT_ARGS_HAS_HOSTNAME.get().unwrap(),
                HANDLER_RESOURCES_2.get().unwrap(),
                stream_command_rx,
                datagram_rx,
            ));
            next_test_notify_rx.recv().await;
            client_task.abort();
        }
        // Third test
        {
            let (handler_resources, stream_command_rx, datagram_rx) =
                crate::client::HandlerResources::create();
            HANDLER_RESOURCES_3.set(handler_resources).unwrap();
            let client_task = tokio::spawn(crate::client::client_main_inner(
                CLIENT_ARGS_HAS_SNI.get().unwrap(),
                HANDLER_RESOURCES_3.get().unwrap(),
                stream_command_rx,
                datagram_rx,
            ));
            next_test_notify_rx.recv().await;
            client_task.abort();
        }
    });

    // First test: expect both Host to be the socket address and SNI to be unset
    let (stream, _) = listener.accept().await.unwrap();
    let mut tls_stream = acceptor.accept(stream).await.unwrap();
    #[cfg(feature = "__rustls")]
    {
        let sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());
        assert!(sni.is_none());
    }
    // check the HTTP Host header
    check_http_host(&mut tls_stream, &addr.to_string()).await;
    next_test_notify_tx.send(()).await.unwrap();
    // Second test: expect Host and SNI to be "test-hostname"
    let (stream, _) = listener.accept().await.unwrap();
    let mut tls_stream = acceptor.accept(stream).await.unwrap();
    #[cfg(feature = "__rustls")]
    {
        let sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());
        assert_eq!(sni, Some("test-hostname".to_string()));
    }
    check_http_host(&mut tls_stream, "test-hostname").await;
    next_test_notify_tx.send(()).await.unwrap();
    // Third test: expect Host to be "test-hostname" and SNI to be "test-sni"
    let (stream, _) = listener.accept().await.unwrap();
    let mut tls_stream = acceptor.accept(stream).await.unwrap();
    #[cfg(feature = "__rustls")]
    {
        let sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());
        assert_eq!(sni, Some("test-sni".to_string()));
    }
    check_http_host(&mut tls_stream, "test-hostname").await;
    next_test_notify_tx.send(()).await.unwrap();
    client_task.await.unwrap();
}

#[tokio::test]
async fn test_socks5_connect_reliability_v4() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("127.0.0.1", 24895));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "127.0.0.1",
            24895,
            vec![Remote::from_str("127.0.0.1:21330:socks").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));

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
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("127.0.0.1", 32233));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "127.0.0.1",
            32233,
            vec![Remote::from_str("127.0.0.1:13261:socks").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));

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
#[cfg(feature = "tests-udp")]
async fn test_socks5_udp_v4v4() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("127.0.0.1", 14119));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "127.0.0.1",
            14119,
            vec![Remote::from_str("127.0.0.1:30711:socks").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));

    let input_bytes: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let udp_listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let listener_port = udp_listener.local_addr().unwrap().port();
    let target_server_task = tokio::spawn(async move {
        for _ in 0..64 {
            let mut buf = vec![0u8; input_len];
            let (n, src) = udp_listener.recv_from(&mut buf).await.unwrap();
            udp_listener.send_to(&buf[..n], src).await.unwrap();
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
        let mut cmd = Vec::from(b"\x05\x03\x00\x01\x7f\x00\x00\x01\xff\xff");
        let len = cmd.len();
        cmd[len - 2..].copy_from_slice(&listener_port.to_be_bytes());
        sock.write_all(&cmd).await.unwrap();
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
        // We don't connect so that we can test if the server sends back
        // with the correct address.
        let mut request_header = vec![0x00, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xff, 0xff];
        let len = request_header.len();
        request_header[len - 2..].copy_from_slice(&listener_port.to_be_bytes());
        let mut request = request_header.clone();
        request.extend(&input_bytes);
        udp_socket
            .send_to(&request, (bind_addr, bind_port))
            .await
            .unwrap();
        let mut buf = vec![0u8; input_len + request_header.len()];
        let (n, addr) = udp_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(addr, (bind_addr, bind_port).into());
        assert_eq!(n, input_len + request_header.len());
        assert_eq!(&buf[request_header.len()..], &input_bytes);
    }

    target_server_task.await.unwrap();
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
#[cfg(feature = "tests-udp")]
async fn test_socks5_udp_v4v6() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    // The target server is IPv6, but the client here is IPv4 here to test their interaction.
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("127.0.0.1", 25347));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "127.0.0.1",
            25347,
            vec![Remote::from_str("127.0.0.1:26396:socks").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));

    let input_bytes: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let udp_listener = UdpSocket::bind("[::1]:0").await.unwrap();
    let listener_port = udp_listener.local_addr().unwrap().port();
    let target_server_task = tokio::spawn(async move {
        for _ in 0..64 {
            let mut buf = vec![0u8; input_len];
            let (n, src) = udp_listener.recv_from(&mut buf).await.unwrap();
            udp_listener.send_to(&buf[..n], src).await.unwrap();
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
        let mut cmd = Vec::from(b"\x05\x03\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\xff");
        let len = cmd.len();
        cmd[len - 2..].copy_from_slice(&listener_port.to_be_bytes());
        sock.write_all(&cmd).await.unwrap();
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
        // We don't connect so that we can test if the server sends back
        // with the correct address.
        let mut request_header = vec![
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff,
        ];
        let len = request_header.len();
        request_header[len - 2..].copy_from_slice(&listener_port.to_be_bytes());
        // Since the local server listens on IPv4, the response header is IPv4.
        let response_header_len = 10;
        let mut request = request_header.clone();
        request.extend(&input_bytes);
        udp_socket
            .send_to(&request, (bind_addr, bind_port))
            .await
            .unwrap();
        let mut buf = vec![0u8; input_len + response_header_len];
        let (n, addr) = udp_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(addr, (bind_addr, bind_port).into());
        assert_eq!(n, input_len + response_header_len);
        assert_eq!(&buf[response_header_len..], &input_bytes);
    }

    target_server_task.await.unwrap();
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
#[cfg(feature = "tests-udp")]
async fn test_socks5_udp_v6v6() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("::1", 31370));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "[::1]",
            31370,
            vec![Remote::from_str("[::1]:12654:socks").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));

    let input_bytes: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
    let input_len = input_bytes.len();
    let udp_listener = UdpSocket::bind("[::1]:0").await.unwrap();
    let listener_port = udp_listener.local_addr().unwrap().port();
    let target_server_task = tokio::spawn(async move {
        for _ in 0..64 {
            let mut buf = vec![0u8; input_len];
            let (n, src) = udp_listener.recv_from(&mut buf).await.unwrap();
            udp_listener.send_to(&buf[..n], src).await.unwrap();
        }
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    for _ in 0..64 {
        let mut sock = TcpStream::connect("[::1]:12654").await.unwrap();
        sock.write_all(b"\x05\x01\x00").await.unwrap();
        let mut buf = vec![0u8; 32];
        let n = sock.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..n], b"\x05\x00");
        let mut cmd = Vec::from(b"\x05\x03\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\xff");
        let len = cmd.len();
        cmd[len - 2..].copy_from_slice(&listener_port.to_be_bytes());
        sock.write_all(&cmd).await.unwrap();
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
        // We don't connect so that we can test if the server sends back
        // with the correct address.
        let mut request_header = vec![
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff,
        ];
        let len = request_header.len();
        request_header[len - 2..].copy_from_slice(&listener_port.to_be_bytes());
        let mut request = request_header.clone();
        request.extend(&input_bytes);
        udp_socket
            .send_to(&request, (bind_addr, bind_port))
            .await
            .unwrap();
        let mut buf = vec![0u8; input_len + request_header.len()];
        let (n, addr) = udp_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(addr, (bind_addr, bind_port).into());
        assert_eq!(n, input_len + request_header.len());
        assert_eq!(&buf[request_header.len()..], &input_bytes);
    }

    target_server_task.await.unwrap();
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
#[cfg(feature = "tests-udp")]
async fn test_socks5_udp_client_prune() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("127.0.0.1", 16720));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "127.0.0.1",
            16720,
            vec![Remote::from_str("127.0.0.1:10350:socks").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();
    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let target_udp_listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let listener_port = target_udp_listener.local_addr().unwrap().port();
    let mut sock = TcpStream::connect("127.0.0.1:10350").await.unwrap();
    sock.write_all(b"\x05\x01\x00").await.unwrap();
    let mut buf = vec![0u8; 32];
    let n = sock.read(&mut buf).await.unwrap();
    assert_eq!(n, 2);
    assert_eq!(&buf[..n], b"\x05\x00");
    let mut cmd = Vec::from(b"\x05\x03\x00\x01\x7f\x00\x00\x01\xff\xff");
    let len = cmd.len();
    cmd[len - 2..].copy_from_slice(&listener_port.to_be_bytes());
    sock.write_all(&cmd).await.unwrap();
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
    // Send a packet and reply after 1/2 the prune timeout
    let mut request_header = vec![0x00, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xff, 0xff];
    let len = request_header.len();
    let data_len = 32 - request_header.len();
    request_header[len - 2..].copy_from_slice(&listener_port.to_be_bytes());
    // Make it immutable
    let request_header = request_header;
    let input_bytes: Vec<u8> = (0..data_len).map(|_| rand::random::<u8>()).collect();
    let mut request = request_header.clone();
    request.extend(&input_bytes);
    udp_socket
        .send_to(&request, (bind_addr, bind_port))
        .await
        .unwrap();
    let mut buf = vec![0u8; input_bytes.len() + request_header.len()];
    let (n, server_src1) = tokio::time::timeout(
        Duration::from_secs(3),
        target_udp_listener.recv_from(&mut buf),
    )
    .await
    .expect("Timed out waiting for client packet 1")
    .unwrap();
    assert_eq!(n, input_bytes.len());
    assert_eq!(&buf[..n], &input_bytes);
    // Wait for half the prune timeout and send another packet
    tokio::time::sleep(config::UDP_PRUNE_TIMEOUT / 2).await;
    let input_bytes: Vec<u8> = (0..data_len).map(|_| rand::random::<u8>()).collect();
    let mut request = request_header.clone();
    request.extend(&input_bytes);
    udp_socket
        .send_to(&request, (bind_addr, bind_port))
        .await
        .unwrap();
    let (n, server_src2) = tokio::time::timeout(
        Duration::from_secs(3),
        target_udp_listener.recv_from(&mut buf),
    )
    .await
    .expect("Timed out waiting for client packet 2")
    .unwrap();
    assert_eq!(server_src1, server_src2);
    assert_eq!(n, input_bytes.len());
    assert_eq!(&buf[..n], &input_bytes);
    // Wait for half plus a bit to exceed the prune timeout,
    // check that the second packet caused the client to extend the timeout
    tokio::time::sleep(config::UDP_PRUNE_TIMEOUT / 2 + Duration::from_millis(100)).await;
    // Send reply
    target_udp_listener
        .send_to(&input_bytes, server_src1)
        .await
        .unwrap();
    let (n, client_src) =
        tokio::time::timeout(Duration::from_secs(3), udp_socket.recv_from(&mut buf))
            .await
            .expect("Timed out waiting for server reply 1")
            .unwrap();
    assert_eq!(client_src, (bind_addr, bind_port).into());
    assert_eq!(n, input_bytes.len() + request_header.len());
    assert_eq!(&buf[request_header.len()..n], &input_bytes);
    // Wait for another half plus a bit to exceed the prune timeout,
    // check that the reply also causes the client to extend the timeout
    tokio::time::sleep(config::UDP_PRUNE_TIMEOUT / 2 + Duration::from_millis(100)).await;
    // Send another reply
    target_udp_listener
        .send_to(&input_bytes, server_src1)
        .await
        .unwrap();
    let (n, client_src) =
        tokio::time::timeout(Duration::from_secs(3), udp_socket.recv_from(&mut buf))
            .await
            .expect("Timed out waiting for server reply 2")
            .unwrap();
    assert_eq!(client_src, (bind_addr, bind_port).into());
    assert_eq!(n, input_bytes.len() + request_header.len());
    assert_eq!(&buf[request_header.len()..n], &input_bytes);
    // Now wait for the prune timeout to expire
    tokio::time::sleep(config::UDP_PRUNE_TIMEOUT + Duration::from_millis(100)).await;
    // Send another packet, which should not be received by the client
    let input_bytes: Vec<u8> = (0..data_len).map(|_| rand::random::<u8>()).collect();
    let mut request = request_header.clone();
    request.extend(&input_bytes);
    target_udp_listener
        .send_to(&request, server_src1)
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), udp_socket.recv_from(&mut buf)).await;
    assert!(result.is_err(), "Did not expect to receive server reply 3");
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
async fn test_socks4_works() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("127.0.0.1", 10796));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "127.0.0.1",
            10796,
            vec![Remote::from_str("127.0.0.1:23213:socks").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));

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

#[cfg(all(feature = "tests-real-internet4", feature = "tests-udp"))]
#[tokio::test]
async fn test_it_works_dns_v4() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("127.0.0.1", 17706));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "127.0.0.1",
            17706,
            vec![Remote::from_str("127.0.0.1:20326:1.1.1.1:53/udp").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    // Just for fun, let's query AAAA here
    let request = b"\x37\x0a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x1c\x00\x01";
    let expected = b"\x37\x0a\x81\x80\x00\x01";
    sock.send_to(request, "127.0.0.1:20326").await.unwrap();
    let mut buf = [0u8; 1024];
    tokio::time::timeout(config::UDP_PRUNE_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .expect("Timed out waiting for DNS response")
        .unwrap();
    assert_eq!(&buf[..6], expected);
    server_task.abort();
    client_task.abort();
}

#[cfg(all(feature = "tests-real-internet6", feature = "tests-udp"))]
#[tokio::test]
async fn test_it_works_dns_v6() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("[::1]", 16037));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "[::1]",
            16037,
            vec![Remote::from_str("[::1]:20326:[2606:4700:4700::1111]:53/udp").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    let server_task = tokio::spawn(crate::server::server_main(
        &SERVER_ARGS,
        &BACKEND_SUPPORTS_HTTP2,
    ));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let sock = UdpSocket::bind("[::]:0").await.unwrap();
    let request = b"\x39\x36\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01";
    let expected = b"\x39\x36\x81\x80\x00\x01";
    sock.send_to(request, ("::1", 20326)).await.unwrap();
    let mut buf = [0u8; 1024];
    tokio::time::timeout(config::UDP_PRUNE_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .expect("Timed out waiting for DNS response")
        .unwrap();
    assert_eq!(&buf[..6], expected);
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
async fn test_tproxy_something_happens() {
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    static SERVER_ARGS: LazyLock<arg::ServerArgs> =
        LazyLock::new(|| make_server_args("[::1]", 28362));
    static CLIENT_ARGS: LazyLock<arg::ClientArgs> = LazyLock::new(|| {
        make_client_args(
            "[::1]",
            28362,
            vec![Remote::from_str("20445:tproxy").unwrap()],
        )
    });
    static HANDLER_RESOURCES: OnceLock<crate::client::HandlerResources> = OnceLock::new();
    setup_logging();

    let (handler_resources, stream_command_rx, datagram_rx) =
        crate::client::HandlerResources::create();
    HANDLER_RESOURCES.set(handler_resources).unwrap();
    let client_task = tokio::spawn(crate::client::client_main_inner(
        &CLIENT_ARGS,
        HANDLER_RESOURCES.get().unwrap(),
        stream_command_rx,
        datagram_rx,
    ));
    #[cfg(not(feature = "tproxy"))]
    {
        let err = client_task.await.unwrap().unwrap_err();
        assert!(matches!(err, crate::client::Error::RemoteHandlerExited(_)));
    }
    #[cfg(feature = "tproxy")]
    {
        let server_task = tokio::spawn(crate::server::server_main(
            &SERVER_ARGS,
            &BACKEND_SUPPORTS_HTTP2,
        ));
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut stream = TcpStream::connect((crate::parse_remote::default_host!(local), 20445))
            .await
            .unwrap();
        // Should immediately EOF
        let mut output_bytes = vec![0u8; 2];
        stream.read_exact(&mut output_bytes).await.unwrap_err();
        server_task.abort();
        client_task.abort();
    }
}
