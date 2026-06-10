//! Support for HTTP proxy servers
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::HandlerResources;

pub(super) async fn handle_http(
    lhost: &'static str,
    lport: u16,
    handler_resources: &'static HandlerResources,
) -> Result<(), super::FatalError> {
    todo!("HTTP proxy support is not implemented yet");
}

pub(super) async fn handle_http_stdio(
    handler_resources: &'static HandlerResources,
) -> Result<(), super::FatalError> {
    todo!("HTTP proxy support is not implemented yet");
}
