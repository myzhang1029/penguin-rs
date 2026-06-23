//! IP address types that default to the unspecified address.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::net::{Ipv4Addr, Ipv6Addr};

/// An IPv4 address to bind to
#[derive(Clone, Copy, Debug, derive_more::Display, derive_more::FromStr, PartialEq, Eq, Hash)]
pub struct BindIpv4(pub Ipv4Addr);

impl Default for BindIpv4 {
    fn default() -> Self {
        Self(Ipv4Addr::UNSPECIFIED)
    }
}

/// An IPv6 address to bind to
#[derive(Clone, Copy, Debug, derive_more::Display, derive_more::FromStr, PartialEq, Eq, Hash)]
pub struct BindIpv6(pub Ipv6Addr);

impl Default for BindIpv6 {
    fn default() -> Self {
        Self(Ipv6Addr::UNSPECIFIED)
    }
}
