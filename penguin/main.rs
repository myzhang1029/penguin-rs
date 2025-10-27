//! A thin wrapper around the library to speed up sccached compilation.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
#![warn(rust_2018_idioms, missing_docs, missing_debug_implementations)]
#![warn(clippy::pedantic, clippy::cargo, clippy::unwrap_used)]
#![forbid(unsafe_code)]
#![cfg_attr(not(all(feature = "client", feature = "server")), allow(dead_code))]

use rusty_penguin_lib::arg;
#[cfg(feature = "client")]
use rusty_penguin_lib::client;
#[cfg(feature = "server")]
use rusty_penguin_lib::server;
use std::sync::OnceLock;
use thiserror::Error;
use tracing::trace;
use tracing_subscriber::{filter, fmt, prelude::*, reload};

#[cfg(dhat)]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Errors
#[derive(Error)]
enum Error {
    #[cfg(feature = "client")]
    #[error(transparent)]
    Client(#[from] client::Error),
    #[cfg(feature = "server")]
    #[error(transparent)]
    Server(#[from] server::Error),
}

impl std::fmt::Debug for Error {
    // Simply delegate to `Display` so when `main` exits, there
    // is a nice error message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

const QUIET_QUIET_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::ERROR;
const QUIET_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::WARN;
const DEFAULT_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::INFO;
const VERBOSE_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::DEBUG;
const VERBOSE_VERBOSE_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::TRACE;

#[tokio::main]
/// Entry point
async fn main() -> Result<(), Box<Error>> {
    // Whether the backend supports HTTP/2
    // This setting starts as `None` and will be probed on the first HTTP/2 request.
    #[cfg(feature = "server")]
    static BACKEND_SUPPORTS_HTTP2: OnceLock<bool> = OnceLock::new();
    #[cfg(dhat)]
    let _profiler = dhat::Profiler::new_heap();
    let (level_layer, reload_handle) = reload::Layer::new(DEFAULT_LOG_LEVEL);
    let fmt_layer = fmt::Layer::default()
        .compact()
        .with_timer(fmt::time::time())
        .with_writer(std::io::stderr)
        .with_filter(level_layer);
    #[cfg(not(feature = "tokio-console"))]
    tracing_subscriber::registry().with(fmt_layer).init();
    #[cfg(feature = "tokio-console")]
    tracing_subscriber::registry()
        .with(console_subscriber::spawn())
        .with(fmt_layer)
        .init();
    arg::PenguinCli::parse_global();
    let cli_args = arg::PenguinCli::get_global();
    trace!("cli_args = {cli_args:#?}");
    match cli_args.verbose {
        0 => {}
        1 => reload_handle
            .reload(VERBOSE_LOG_LEVEL)
            .expect("Resetting log level failed (this is a bug)"),
        _ => reload_handle
            .reload(VERBOSE_VERBOSE_LOG_LEVEL)
            .expect("Resetting log level failed (this is a bug)"),
    }
    match cli_args.quiet {
        0 => {}
        1 => reload_handle
            .reload(QUIET_LOG_LEVEL)
            .expect("Resetting log level failed (this is a bug)"),
        _ => reload_handle
            .reload(QUIET_QUIET_LOG_LEVEL)
            .expect("Resetting log level failed (this is a bug)"),
    }

    #[cfg(feature = "deadlock-detection")]
    penguin_mux::deadlock_detection::try_spawn_deadlock_detection();
    match &cli_args.subcommand {
        #[cfg(feature = "client")]
        arg::Commands::Client(args) => client::client_main(args)
            .await
            .map_err(|e| Box::new(e.into()))?,
        #[cfg(feature = "server")]
        arg::Commands::Server(args) => server::server_main(args, &BACKEND_SUPPORTS_HTTP2)
            .await
            .map_err(|e| Box::new(e.into()))?,
    }
    Ok(())
}

#[cfg(all(feature = "rustls-native-roots", feature = "rustls-webpki-roots"))]
compile_error!("Only one of rustls-native-roots and rustls-webpki-roots can be enabled at a time");
#[cfg(all(feature = "__rustls", feature = "nativetls"))]
compile_error!(
    "Only one of rustls-native-roots, rustls-webpki-roots, and nativetls can be enabled at a time"
);
#[cfg(all(feature = "tokio-console", feature = "remove-logging"))]
compile_error!("tokio-console without trace-level logging is likely not desired");
