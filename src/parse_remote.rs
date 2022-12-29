//! Client `remote` specification.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::{fmt::Display, str::FromStr};
use thiserror::Error;

#[derive(Debug, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct Remote {
    pub local_addr: LocalSpec,
    pub remote_addr: RemoteSpec,
    pub protocol: Protocol,
}

/// The local side can be either IP+port or "stdio".
#[derive(Debug, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub enum LocalSpec {
    Inet((String, u16)),
    Stdio,
}

/// The remote side can be either IP+port or "socks".
#[derive(Debug, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub enum RemoteSpec {
    Inet((String, u16)),
    Socks,
}

/// Protocol can be either "tcp" or "udp".
#[derive(Debug, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
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
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
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
            LocalSpec::Inet((host, port)) => write!(f, "{host}:{port}")?,
            LocalSpec::Stdio => write!(f, "stdio")?,
        }
        match &self.remote_addr {
            RemoteSpec::Inet((host, port)) => write!(f, ":{host}:{port}")?,
            RemoteSpec::Socks => write!(f, ":socks")?,
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
            ["socks"] => Ok(Remote {
                local_addr: LocalSpec::Inet(("127.0.0.1".to_string(), 1080)),
                remote_addr: RemoteSpec::Socks,
                protocol: proto,
            }),
            [port] => Ok(Remote {
                local_addr: LocalSpec::Inet(("0.0.0.0".to_string(), port.parse()?)),
                remote_addr: RemoteSpec::Inet(("127.0.0.1".to_string(), port.parse()?)),
                protocol: proto,
            }),
            // Two elements: either "socks" and local port number, or remote host and port number.
            ["stdio", "socks"] => Ok(Remote {
                local_addr: LocalSpec::Stdio,
                remote_addr: RemoteSpec::Socks,
                protocol: proto,
            }),
            [port, "socks"] => Ok(Remote {
                local_addr: LocalSpec::Inet(("127.0.0.1".to_string(), port.parse()?)),
                remote_addr: RemoteSpec::Socks,
                protocol: proto,
            }),
            ["stdio", port] => Ok(Remote {
                local_addr: LocalSpec::Stdio,
                remote_addr: RemoteSpec::Inet(("127.0.0.1".to_string(), port.parse()?)),
                protocol: proto,
            }),
            [host, port] => Ok(Remote {
                local_addr: LocalSpec::Inet(("0.0.0.0".to_string(), port.parse()?)),
                remote_addr: RemoteSpec::Inet((remove_brackets(host).to_string(), port.parse()?)),
                protocol: proto,
            }),
            // Three elements:
            // - "stdio", remote host, and port number,
            // - local host, local port number, and "socks", or
            // - local port number, remote host, and port number.
            ["stdio", remote_host, remote_port] => Ok(Remote {
                local_addr: LocalSpec::Stdio,
                remote_addr: RemoteSpec::Inet((
                    remove_brackets(remote_host).to_string(),
                    remote_port.parse()?,
                )),
                protocol: proto,
            }),
            [local_host, local_port, "socks"] => Ok(Remote {
                local_addr: LocalSpec::Inet((
                    remove_brackets(local_host).to_string(),
                    local_port.parse()?,
                )),
                remote_addr: RemoteSpec::Socks,
                protocol: proto,
            }),
            [local_port, remote_host, remote_port] => Ok(Remote {
                local_addr: LocalSpec::Inet(("0.0.0.0".to_string(), local_port.parse()?)),
                remote_addr: RemoteSpec::Inet((
                    remove_brackets(remote_host).to_string(),
                    remote_port.parse()?,
                )),
                protocol: proto,
            }),
            [local_host, local_port, remote_host, remote_port] => Ok(Remote {
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
        if let Ok(Remote {
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

    /// Simply jpillora's test cases and a few additions.
    #[test]
    fn test_parse_remote() {
        let tests: &[(&str, Remote)] = &[
            (
                "3000",
                Remote {
                    local_addr: LocalSpec::Inet((String::from("0.0.0.0"), 3000)),
                    remote_addr: RemoteSpec::Inet((String::from("127.0.0.1"), 3000)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "google.com:80",
                Remote {
                    local_addr: LocalSpec::Inet((String::from("0.0.0.0"), 80)),
                    remote_addr: RemoteSpec::Inet((String::from("google.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "示例網站.com:80",
                Remote {
                    local_addr: LocalSpec::Inet((String::from("0.0.0.0"), 80)),
                    remote_addr: RemoteSpec::Inet((String::from("示例網站.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "socks",
                Remote {
                    local_addr: LocalSpec::Inet((String::from("127.0.0.1"), 1080)),
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
                "1.1.1.1:53/udp",
                Remote {
                    local_addr: LocalSpec::Inet((String::from("0.0.0.0"), 53)),
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
                "stdio:5353/udp",
                Remote {
                    local_addr: LocalSpec::Stdio,
                    remote_addr: RemoteSpec::Inet((String::from("127.0.0.1"), 5353)),
                    protocol: Protocol::Udp,
                },
            ),
        ];
        for (s, expected) in tests {
            let actual = s.parse::<Remote>().unwrap();
            assert_eq!(actual, *expected);
        }
    }
}
