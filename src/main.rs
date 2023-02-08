//! A fast TCP/UDP tunnel, transported over HTTP WebSockets.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
#![warn(missing_docs, missing_debug_implementations)]
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

mod arg;
mod client;
mod config;
mod parse_remote;
mod proto_version;
mod server;
#[cfg(test)]
mod test;
mod tls;

use thiserror::Error;
use tracing::{error, trace};
#[cfg(not(feature = "tokio-console"))]
use tracing_subscriber::{filter, fmt, prelude::*, reload};

pub use penguin_mux::dupe::Dupe;

/// Errors
#[derive(Debug, Error)]
enum Error {
    #[error(transparent)]
    Client(#[from] client::Error),
    #[error(transparent)]
    Server(#[from] server::Error),
}

#[cfg(not(feature = "tokio-console"))]
const QUIET_QUIET_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::ERROR;
#[cfg(not(feature = "tokio-console"))]
const QUIET_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::WARN;
#[cfg(not(feature = "tokio-console"))]
const DEFAULT_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::INFO;
#[cfg(not(feature = "tokio-console"))]
const VERBOSE_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::DEBUG;
#[cfg(not(feature = "tokio-console"))]
const VERBOSE_VERBOSE_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::TRACE;

#[cfg(feature = "deadlock-detection")]
fn spawn_deadlock_detection() {
    use std::thread;

    // Create a background thread which checks for deadlocks every 10s
    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(10));
        let deadlocks = parking_lot::deadlock::check_deadlock();
        if deadlocks.is_empty() {
            continue;
        }

        error!("{} deadlocks detected", deadlocks.len());
        for (i, threads) in deadlocks.iter().enumerate() {
            error!("Deadlock #{}", i);
            for t in threads {
                error!("Thread Id {:#?}", t.thread_id());
                error!("{:#?}", t.backtrace());
            }
        }
    });
}

#[tokio::main]
/// Entry point
async fn main() -> Result<(), Error> {
    #[cfg(not(feature = "tokio-console"))]
    let reload_handle = {
        let fmt_layer = fmt::Layer::default()
            .compact()
            .with_timer(fmt::time::time())
            .with_writer(std::io::stderr);
        let (level_layer, reload_handle) = reload::Layer::new(DEFAULT_LOG_LEVEL);
        tracing_subscriber::registry()
            .with(level_layer)
            .with(fmt_layer)
            .init();
        reload_handle
    };
    #[cfg(feature = "tokio-console")]
    console_subscriber::init();
    arg::PenguinCli::parse_global();
    let cli_args = arg::PenguinCli::get_global();
    trace!("cli_args = {cli_args:?}");
    #[cfg(not(feature = "tokio-console"))]
    {
        match cli_args.verbose {
            0 => {}
            1 => reload_handle
                .reload(VERBOSE_LOG_LEVEL)
                .expect("Resetting log level failed (this is a bug)"),
            _ => reload_handle
                .reload(VERBOSE_VERBOSE_LOG_LEVEL)
                .expect("Resetting log level failed (this is a bug)"),
        };
        match cli_args.quiet {
            0 => {}
            1 => reload_handle
                .reload(QUIET_LOG_LEVEL)
                .expect("Resetting log level failed (this is a bug)"),
            _ => reload_handle
                .reload(QUIET_QUIET_LOG_LEVEL)
                .expect("Resetting log level failed (this is a bug)"),
        };
    }
    #[cfg(feature = "deadlock-detection")]
    spawn_deadlock_detection();
    match &cli_args.subcommand {
        arg::Commands::Client(args) => client::client_main(args).await?,
        arg::Commands::Server(args) => server::server_main(args).await?,
    }
    Ok(())
}

#[cfg(all(feature = "rustls-native-roots", feature = "rustls-webpki-roots"))]
compile_error!("Only one of rustls-native-roots and rustls-webpki-roots can be enabled at a time");
#[cfg(all(feature = "rustls-native-roots", feature = "nativetls"))]
compile_error!("Only one of rustls-native-roots and nativetls can be enabled at a time");
#[cfg(all(feature = "rustls-webpki-roots", feature = "nativetls"))]
compile_error!("Only one of rustls-webpki-roots and nativetls can be enabled at a time");
