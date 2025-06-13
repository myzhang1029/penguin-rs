//! A fast TCP/UDP tunnel, transported over HTTP WebSocket.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
#![warn(rust_2018_idioms, missing_docs, missing_debug_implementations)]
#![warn(clippy::pedantic, clippy::cargo, clippy::unwrap_used)]
#![forbid(unsafe_code)]
#![cfg_attr(not(all(feature = "client", feature = "server")), allow(dead_code))]

pub mod arg;
#[cfg(feature = "client")]
pub mod client;
pub mod config;
pub mod parse_remote;
#[cfg(feature = "server")]
pub mod server;
#[cfg(test)]
mod tests;
pub mod tls;
