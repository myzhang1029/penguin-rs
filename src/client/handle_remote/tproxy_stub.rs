//! Stub implementations of tproxy functions for non-linux platforms.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::{FatalError, HandlerResources};

pub(super) async fn handle_tproxy_tcp(
    _lhost: &str,
    _lport: u16,
    _handler_resources: &HandlerResources,
) -> Result<(), FatalError> {
    Err(FatalError::TproxyNotLinux)
}

pub(super) async fn handle_tproxy_udp(
    _lhost: &str,
    _lport: u16,
    _handler_resources: &HandlerResources,
) -> Result<(), FatalError> {
    Err(FatalError::TproxyNotLinux)
}
