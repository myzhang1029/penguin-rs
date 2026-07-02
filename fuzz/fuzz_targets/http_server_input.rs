#![no_main]

use libfuzzer_sys::fuzz_target;
use penguin_mux::timing::OptionalDuration;
use rusty_penguin_lib::{server, tls};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime;

static HTTP2_SUPPORT: OnceLock<bool> = OnceLock::new();
static SERVER_STATE: OnceLock<server::State> = OnceLock::new();

fn init() {
    tls::init_crypto_provider();
    SERVER_STATE
        .set(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    server::State::new(
                        None,
                        &HTTP2_SUPPORT,
                        None,
                        "",
                        false,
                        false,
                        Ipv4Addr::UNSPECIFIED,
                        Ipv6Addr::UNSPECIFIED,
                        OptionalDuration::NONE,
                        OptionalDuration::NONE,
                    )
                    .await
                    .unwrap()
                }),
        )
        .unwrap();
}

async fn target_async(data: &[u8]) {
    let sock = TcpListener::bind(("::1", 0)).await.unwrap();
    let sa = sock.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let stream = sock.accept().await.unwrap().0;
        let stream = tls::MaybeTlsStream::Plain(stream);
        server::serve_connection(stream, SERVER_STATE.get().unwrap().clone()).await;
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
