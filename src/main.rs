//! A fast TCP/UDP tunnel, transported over HTTP WebSockets.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod arg;
mod client;
mod mux;
mod proto_version;
mod server;

use clap::Parser;
use log::trace;
use thiserror::Error;

/// Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Client(#[from] client::Error),
    #[error("{0}")]
    Server(#[from] server::Error),
}

/// Real entry point
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
async fn main() {
    env_logger::init();
    if let Err(e) = main_real().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
