//! Abstraction `AsyncAcceptable` over tokio listeners with an async `accept()` method
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

#![deny(rust_2018_idioms, missing_docs, missing_debug_implementations)]
#![deny(clippy::pedantic, clippy::cargo, clippy::nursery, clippy::unwrap_used)]
#![allow(clippy::multiple_crate_versions)]

mod async_acceptable;
#[cfg(feature = "stdio")]
mod stdio;

pub use async_acceptable::{AsyncAcceptable, AsyncAcceptableExt};
#[cfg(feature = "stdio")]
pub use stdio::{ReusableListener, ReusableListenerStream};
