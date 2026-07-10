#![no_main]

use libfuzzer_sys::fuzz_target;
use rusty_penguin_lib::{server, tls};
use std::io::ErrorKind;
use std::sync::OnceLock;
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime;

static HTTP2_SUPPORT: OnceLock<bool> = OnceLock::new();
static SERVER_STATE: OnceLock<server::State> = OnceLock::new();
static TLS_TEMP_DIR: OnceLock<TempDir> = OnceLock::new();

fn init() {
    tls::init_crypto_provider();
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let dir = TLS_TEMP_DIR.get_or_init(|| tempfile::TempDir::new().unwrap());
    let dir_path = dir.path().to_str().unwrap();
    let cert_path = format!("{dir_path}/cert.pem");
    let key_path = format!("{dir_path}/privkey.pem");
    let cert = cert_params.self_signed(&keypair).unwrap();
    let key_pem = keypair.serialize_pem();
    let cert_pem = cert.pem();
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();
    // Make sure the files actually exist
    assert!(std::fs::metadata(&cert_path).is_ok());
    assert!(std::fs::metadata(&key_path).is_ok());
    SERVER_STATE
        .set(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(server::State::new(&HTTP2_SUPPORT))
                .unwrap(),
        )
        .unwrap();
}

async fn target_async(data: &[u8]) {
    let sock = TcpListener::bind(("::1", 0)).await.unwrap();
    let sa = sock.local_addr().unwrap();
    let certpath = TLS_TEMP_DIR.get().unwrap().path();
    let tls_ident = tls::make_tls_identity(
        certpath.join("cert.pem").to_str().unwrap(),
        certpath.join("privkey.pem").to_str().unwrap(),
        None,
    )
    .await
    .unwrap();
    let server = tokio::spawn(async move {
        let stream = sock.accept().await.unwrap().0;
        server::serve_connection_tls(
            stream,
            SERVER_STATE.get().unwrap().clone(),
            tls_ident.load_full(),
        )
        .await;
    });
    let mut eve = loop {
        match TcpStream::connect(("::1", sa.port())).await {
            Ok(stream) => break Ok(stream),
            Err(e)
                if e.kind() == ErrorKind::ConnectionRefused
                    || e.kind() == ErrorKind::WouldBlock =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(e) => break Err(e),
        }
    }
    .unwrap();
    eve.write_all(data).await.unwrap();
    eve.shutdown().await.unwrap();
    drop(eve);
    server.await.unwrap();
}

fuzz_target! {
    init: init(),
    |data: &[u8]| {
        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(target_async(data));
    }
}
