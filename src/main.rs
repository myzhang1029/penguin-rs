//! A fast TCP/UDP tunnel, transported over HTTP WebSockets.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod arg;
mod client;
mod proto_version;
mod server;

use clap::Parser;
use log::trace;

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli_args = arg::PenguinCli::parse();
    trace!("Parsed: {:?}", cli_args);

    match cli_args.subcommand {
        arg::Commands::Client(args) => client::client_main(args).await,
        arg::Commands::Server(args) => server::server_main(args).await,
    }
}
