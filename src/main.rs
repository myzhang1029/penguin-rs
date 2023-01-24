//! A fast TCP/UDP tunnel, transported over HTTP WebSockets.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod arg;
mod client;
mod config;
mod mux;
mod parse_remote;
mod proto_version;
mod server;
#[cfg(test)]
mod test;
mod tls;

use thiserror::Error;
use tracing::{error, trace};
use tracing_subscriber::{filter, fmt, prelude::*, reload};

/// Errors
#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Client(#[from] client::Error),
    #[error(transparent)]
    Server(#[from] server::Error),
}

const QUIET_QUIET_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::ERROR;
const QUIET_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::WARN;
const DEFAULT_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::INFO;
const VERBOSE_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::DEBUG;
const VERBOSE_VERBOSE_LOG_LEVEL: filter::LevelFilter = filter::LevelFilter::TRACE;

/// Real entry point
async fn main_real() -> Result<(), Error> {
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
    arg::PenguinCli::parse_global();
    let cli_args = arg::PenguinCli::get_global();
    trace!("cli_args = {cli_args:?}");
    match cli_args.verbose {
        0 => {}
        1 => reload_handle
            .reload(VERBOSE_LOG_LEVEL)
            .expect("Resetting log level failed"),
        _ => reload_handle
            .reload(VERBOSE_VERBOSE_LOG_LEVEL)
            .expect("Resetting log level failed"),
    };
    match cli_args.quiet {
        0 => {}
        1 => reload_handle
            .reload(QUIET_LOG_LEVEL)
            .expect("Resetting log level failed"),
        _ => reload_handle
            .reload(QUIET_QUIET_LOG_LEVEL)
            .expect("Resetting log level failed"),
    };
    match &cli_args.subcommand {
        arg::Commands::Client(args) => client::client_main(args).await?,
        arg::Commands::Server(args) => server::server_main(args).await?,
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
