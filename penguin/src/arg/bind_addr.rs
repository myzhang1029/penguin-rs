//! IP address types that default to the unspecified address.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An IPv4 address to bind to
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BindIpv4(pub Ipv4Addr);

impl Default for BindIpv4 {
    fn default() -> Self {
        Self(Ipv4Addr::UNSPECIFIED)
    }
}

impl FromStr for BindIpv4 {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv4Addr::from_str(s).map(Self)
    }
}

impl Display for BindIpv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// An IPv6 address to bind to
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BindIpv6(pub Ipv6Addr);

impl Default for BindIpv6 {
    fn default() -> Self {
        Self(Ipv6Addr::UNSPECIFIED)
    }
}

impl FromStr for BindIpv6 {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv6Addr::from_str(s).map(Self)
    }
}

impl Display for BindIpv6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}
