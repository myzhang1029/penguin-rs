//! Penguin client.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::arg::ClientArgs;
use log::debug;

pub async fn client_main(args: ClientArgs) {
    debug!("Client args: {:?}", args);
}
