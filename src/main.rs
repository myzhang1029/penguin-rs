//! A fast TCP/UDP tunnel, transported over HTTP WebSockets.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod arg;
mod client;
mod mux;
mod parse_remote;
mod proto_version;
mod server;

use clap::Parser;
use thiserror::Error;
use tracing::{error, trace};

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Client(#[from] client::Error),
    #[error(transparent)]
    Server(#[from] server::Error),
}

/// Real entry point
#[tracing::instrument]
async fn main_real() -> Result<(), Error> {
    let cli_args = arg::PenguinCli::parse();
    trace!("Parsed: {:?}", cli_args);

    match cli_args.subcommand {
        arg::Commands::Client(args) => client::client_main(args).await?,
        arg::Commands::Server(args) => server::server_main(args).await?,
    }
    Ok(())
}

#[tokio::main]
#[tracing::instrument]
async fn main() {
    //env_logger::init();
    env_logger::builder().format_timestamp_nanos().init();
    if let Err(e) = main_real().await {
        error!("Error: {e}");
        std::process::exit(1);
    }
}
