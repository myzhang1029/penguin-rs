//! A fast TCP/UDP tunnel, transported over HTTP WebSockets.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
#![forbid(unsafe_code)]

mod arg;
mod client;
mod mux;
mod parse_remote;
mod proto_version;
mod server;
mod tls;

use clap::Parser;
use thiserror::Error;
use tracing::{error, trace};
use tracing_subscriber::{filter, fmt, prelude::*, reload};

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Client(#[from] client::Error),
    #[error(transparent)]
    Server(#[from] server::Error),
}

#[cfg(not(feature = "more-verbose"))]
const QUIET_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::WARN;
#[cfg(not(feature = "more-verbose"))]
const DEFAULT_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::INFO;
#[cfg(not(feature = "more-verbose"))]
const VERBOSE_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::DEBUG;
#[cfg(feature = "more-verbose")]
const QUIET_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::INFO;
#[cfg(feature = "more-verbose")]
const DEFAULT_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::DEBUG;
#[cfg(feature = "more-verbose")]
const VERBOSE_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::TRACE;

/// Real entry point
async fn main_real() -> Result<(), Error> {
    #[cfg(feature = "more-verbose")]
    let fmt_layer = fmt::Layer::default()
        .with_thread_ids(true)
        .with_timer(fmt::time::time())
        .with_writer(std::io::stderr);
    #[cfg(not(feature = "more-verbose"))]
    let fmt_layer = fmt::Layer::default()
        .compact()
        .with_thread_ids(true)
        .with_timer(fmt::time::time())
        .with_writer(std::io::stderr);
    let (level_layer, reload_handle) = reload::Layer::new(DEFAULT_LOG_LEVEL);
    tracing_subscriber::registry()
        .with(level_layer)
        .with(fmt_layer)
        .init();
    let cli_args = arg::PenguinCli::parse();
    trace!("cli_args = {cli_args:?}");
    if cli_args.verbose {
        reload_handle
            .reload(VERBOSE_LOG_LEVEL)
            .expect("Resetting log level failed");
    } else if cli_args.quiet {
        reload_handle
            .reload(QUIET_LOG_LEVEL)
            .expect("Resetting log level failed");
    }
    match cli_args.subcommand {
        arg::Commands::Client(args) => client::client_main(args).await?,
        arg::Commands::Server(args) => server::server_main(*args).await?,
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = main_real().await {
        error!("Giving up: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{arg::ServerUrl, parse_remote::Remote};
    use std::str::FromStr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    #[tokio::test]
    async fn test_it_works() {
        let server_args = arg::ServerArgs {
            host: "127.0.0.1".to_string(),
            port: 30554,
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
        };
        let client_args = arg::ClientArgs {
            server: ServerUrl::from_str("ws://127.0.0.1:30554/ws").unwrap(),
            remote: vec![Remote::from_str("127.0.0.1:21628:127.0.0.1:10807").unwrap()],
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
        };
        let input_bytes: Vec<u8> = (0..(1024 * 1024)).map(|_| rand::random::<u8>()).collect();
        let input_len = input_bytes.len();
        let second_task = tokio::spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:10807").await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut output_bytes = vec![0u8; input_len];
            stream.read_exact(&mut output_bytes).await.unwrap();
            output_bytes
        });

        let client_task = tokio::spawn(crate::client::client_main(client_args));
        let server_task = tokio::spawn(crate::server::server_main(server_args));
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut sock = TcpStream::connect("127.0.0.1:21628").await.unwrap();
        sock.write_all(&input_bytes).await.unwrap();
        let output_bytes = second_task.await.unwrap();
        assert_eq!(input_bytes, output_bytes);
        server_task.abort();
        client_task.abort();
    }
}
