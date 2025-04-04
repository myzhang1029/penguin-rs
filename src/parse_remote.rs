//! Client `remote` specification.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::{fmt::Display, str::FromStr};
use thiserror::Error;

#[cfg(not(feature = "default-is-ipv6"))]
/// Default host for local and unspecified addresses.
macro_rules! default_host {
    (local) => {
        String::from("127.0.0.1")
    };
    (unspec) => {
        String::from("0.0.0.0")
    };
}
#[cfg(feature = "default-is-ipv6")]
/// Default host for local and unspecified addresses.
macro_rules! default_host {
    (local) => {
        String::from("::1")
    };
    (unspec) => {
        String::from("::")
    };
}

// Export this macro for use in `arg.rs`.
pub(crate) use default_host;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Remote {
    pub local_addr: LocalSpec,
    #[allow(clippy::struct_field_names)]
    pub remote_addr: RemoteSpec,
    pub protocol: Protocol,
}

/// The local side can be either IP+port or "stdio".
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum LocalSpec {
    Inet((String, u16)),
    Stdio,
}

/// The remote side can be either IP+port or "socks".
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum RemoteSpec {
    Inet((String, u16)),
    Socks,
}

/// Protocol can be either "tcp" or "udp".
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Errors that can occur when parsing a remote.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid format")]
    Format,
    #[error("Invalid protocol")]
    Protocol,
    #[error("Invalid host")]
    Host,
    #[error("Invalid port")]
    Port(#[from] std::num::ParseIntError),
    #[error("socks remote must be TCP")]
    UdpSocks,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(Error::Protocol),
        }
    }
}

/// Tokenize a remote string by splitting on `:`.
/// We don't need RE!
fn tokenize_remote(s: &str) -> Result<Vec<&str>, Error> {
    let mut tokens = Vec::new();
    let mut stuff = s;
    loop {
        // IPv6 address in brackets
        if stuff.starts_with('[') {
            let end = stuff.find(']').ok_or(Error::Host)? + 1;
            tokens.push(&stuff[..end]);
            // Now stuff[end..] should start with ':', so we assert that and skip it.
            if !stuff[end..].is_empty() && !stuff[end..].starts_with(':') {
                return Err(Error::Format);
            }
            stuff = &stuff[end + 1..];
        } else if let Some((token, rest)) = stuff.split_once(':') {
            tokens.push(token);
            stuff = rest;
        } else {
            tokens.push(stuff);
            return Ok(tokens);
        }
    }
}

impl Display for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.local_addr {
            LocalSpec::Inet((host, port)) => {
                if host.contains(':') {
                    write!(f, "[{host}]:{port}")?;
                } else {
                    write!(f, "{host}:{port}")?;
                }
            }
            LocalSpec::Stdio => f.write_str("stdio")?,
        }
        match &self.remote_addr {
            RemoteSpec::Inet((host, port)) => {
                if host.contains(':') {
                    write!(f, ":[{host}]:{port}")?;
                } else {
                    write!(f, ":{host}:{port}")?;
                }
            }
            RemoteSpec::Socks => f.write_str(":socks")?,
        }
        write!(f, "/{}", self.protocol)?;
        Ok(())
    }
}

impl FromStr for Remote {
    type Err = Error;

    /// Parse a remote specification.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rest, proto) = match s.rsplit_once('/') {
            Some((rest, proto)) => (rest, proto.parse()?),
            None => (s, Protocol::Tcp),
        };
        let tokens = tokenize_remote(rest)?;
        let result = match tokens[..] {
            // One element: either "socks" or a port number.
            ["socks"] => Ok(Self {
                local_addr: LocalSpec::Inet((default_host!(local), 1080)),
                remote_addr: RemoteSpec::Socks,
                protocol: proto,
            }),
            [port] => Ok(Self {
                local_addr: LocalSpec::Inet((default_host!(unspec), port.parse()?)),
                remote_addr: RemoteSpec::Inet((default_host!(local), port.parse()?)),
                protocol: proto,
            }),
            // Two elements: either "socks" and local port number, or remote host and port number.
            ["stdio", "socks"] => Ok(Self {
                local_addr: LocalSpec::Stdio,
                remote_addr: RemoteSpec::Socks,
                protocol: proto,
            }),
            [port, "socks"] => Ok(Self {
                local_addr: LocalSpec::Inet((default_host!(local), port.parse()?)),
                remote_addr: RemoteSpec::Socks,
                protocol: proto,
            }),
            ["stdio", port] => Ok(Self {
                local_addr: LocalSpec::Stdio,
                remote_addr: RemoteSpec::Inet((default_host!(local), port.parse()?)),
                protocol: proto,
            }),
            [host, port] => Ok(Self {
                local_addr: LocalSpec::Inet((default_host!(unspec), port.parse()?)),
                remote_addr: RemoteSpec::Inet((remove_brackets(host).to_string(), port.parse()?)),
                protocol: proto,
            }),
            // Three elements:
            // - "stdio", remote host, and port number,
            // - local host, local port number, and "socks", or
            // - local port number, remote host, and port number.
            ["stdio", remote_host, remote_port] => Ok(Self {
                local_addr: LocalSpec::Stdio,
                remote_addr: RemoteSpec::Inet((
                    remove_brackets(remote_host).to_string(),
                    remote_port.parse()?,
                )),
                protocol: proto,
            }),
            [local_host, local_port, "socks"] => Ok(Self {
                local_addr: LocalSpec::Inet((
                    remove_brackets(local_host).to_string(),
                    local_port.parse()?,
                )),
                remote_addr: RemoteSpec::Socks,
                protocol: proto,
            }),
            [local_port, remote_host, remote_port] => Ok(Self {
                local_addr: LocalSpec::Inet((default_host!(unspec), local_port.parse()?)),
                remote_addr: RemoteSpec::Inet((
                    remove_brackets(remote_host).to_string(),
                    remote_port.parse()?,
                )),
                protocol: proto,
            }),
            [local_host, local_port, remote_host, remote_port] => Ok(Self {
                local_addr: LocalSpec::Inet((
                    remove_brackets(local_host).to_string(),
                    local_port.parse()?,
                )),
                remote_addr: RemoteSpec::Inet((
                    remove_brackets(remote_host).to_string(),
                    remote_port.parse()?,
                )),
                protocol: proto,
            }),
            _ => Err(Error::Format),
        };
        // I love Rust's pattern matching
        // (this sentence is written by GitHub Copilot)
        if let Ok(Self {
            remote_addr: RemoteSpec::Socks,
            protocol: Protocol::Udp,
            ..
        }) = &result
        {
            Err(Error::UdpSocks)
        } else {
            result
        }
    }
}

pub fn remove_brackets(s: &str) -> &str {
    if s.starts_with('[') && s.ends_with(']') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // We could have DRYed, but this is to physically show the difference.
    #[cfg(not(feature = "default-is-ipv6"))]
    #[test]
    fn test_default_host() {
        crate::tests::setup_logging();
        assert_eq!(
            std::net::Ipv4Addr::from_str(&default_host!(unspec)).unwrap(),
            std::net::Ipv4Addr::UNSPECIFIED
        );
        assert_eq!(
            std::net::Ipv4Addr::from_str(&default_host!(local)).unwrap(),
            std::net::Ipv4Addr::LOCALHOST
        );
    }
    #[cfg(feature = "default-is-ipv6")]
    #[test]
    fn test_default_host() {
        crate::tests::setup_logging();
        assert_eq!(
            std::net::Ipv6Addr::from_str(&default_host!(unspec)).unwrap(),
            std::net::Ipv6Addr::UNSPECIFIED
        );
        assert_eq!(
            std::net::Ipv6Addr::from_str(&default_host!(local)).unwrap(),
            std::net::Ipv6Addr::LOCALHOST
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_parse_remote() {
        crate::tests::setup_logging();
        let tests: &[(&str, Remote)] = &[
            // jpillora's tests and an exhausive list of cases
            (
                "3000",
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 3000)),
                    remote_addr: RemoteSpec::Inet((default_host!(local), 3000)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "4000/udp",
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 4000)),
                    remote_addr: RemoteSpec::Inet((default_host!(local), 4000)),
                    protocol: Protocol::Udp,
                },
            ),
            (
                "google.com:80",
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 80)),
                    remote_addr: RemoteSpec::Inet((String::from("google.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "示例網站.com:80",
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 80)),
                    remote_addr: RemoteSpec::Inet((String::from("示例網站.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "8080:example.com:80",
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 8080)),
                    remote_addr: RemoteSpec::Inet((String::from("example.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "socks",
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(local), 1080)),
                    remote_addr: RemoteSpec::Socks,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "127.0.0.1:1081:socks",
                Remote {
                    local_addr: LocalSpec::Inet((String::from("127.0.0.1"), 1081)),
                    remote_addr: RemoteSpec::Socks,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "9050:socks",
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(local), 9050)),
                    remote_addr: RemoteSpec::Socks,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "1.1.1.1:53/udp",
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 53)),
                    remote_addr: RemoteSpec::Inet((String::from("1.1.1.1"), 53)),
                    protocol: Protocol::Udp,
                },
            ),
            (
                "localhost:5353:1.1.1.1:53/udp",
                Remote {
                    local_addr: LocalSpec::Inet((String::from("localhost"), 5353)),
                    remote_addr: RemoteSpec::Inet((String::from("1.1.1.1"), 53)),
                    protocol: Protocol::Udp,
                },
            ),
            (
                "[::1]:8080:google.com:80",
                Remote {
                    local_addr: LocalSpec::Inet((String::from("::1"), 8080)),
                    remote_addr: RemoteSpec::Inet((String::from("google.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "localhost:5354:[2001:4860:4860:0:0:0:0:8888]:53/udp",
                Remote {
                    local_addr: LocalSpec::Inet((String::from("localhost"), 5354)),
                    remote_addr: RemoteSpec::Inet((
                        String::from("2001:4860:4860:0:0:0:0:8888"),
                        53,
                    )),
                    protocol: Protocol::Udp,
                },
            ),
            (
                "stdio:google.com:80",
                Remote {
                    local_addr: LocalSpec::Stdio,
                    remote_addr: RemoteSpec::Inet((String::from("google.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "stdio:socks",
                Remote {
                    local_addr: LocalSpec::Stdio,
                    remote_addr: RemoteSpec::Socks,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "stdio:443",
                Remote {
                    local_addr: LocalSpec::Stdio,
                    remote_addr: RemoteSpec::Inet((default_host!(local), 443)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "stdio:5353/udp",
                Remote {
                    local_addr: LocalSpec::Stdio,
                    remote_addr: RemoteSpec::Inet((default_host!(local), 5353)),
                    protocol: Protocol::Udp,
                },
            ),
        ];
        for (s, expected) in tests {
            // Test that the common format is parsed correctly
            let actual = s.parse::<Remote>().unwrap();
            assert_eq!(actual, *expected);
            // Test that the canonical format is made and parsed correctly
            let reparsed = actual.to_string().parse::<Remote>().unwrap();
            assert_eq!(reparsed, *expected);
        }
        "just_a_hostname".parse::<Remote>().unwrap_err();
        "socks/udp".parse::<Remote>().unwrap_err();
    }
}
