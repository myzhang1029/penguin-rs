//! Tools for working with [`crate::MuxStream`]s.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
mod copy_bidirectional;
mod greedy_buf_reader;

pub use copy_bidirectional::CopyBidirectional;
pub use greedy_buf_reader::GreedyBufReader;
