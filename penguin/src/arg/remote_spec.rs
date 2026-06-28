//! Client `remote` specification.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::path::PathBuf;
use std::str::FromStr;
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

// Export this macro for use in tests
#[cfg(all(test, feature = "client"))]
pub(crate) use default_host;

/// Default SOCKS port
pub const SOCKS_DEFAULT_PORT: u16 = 1080;
/// Default HTTP proxy port
pub const HTTP_DEFAULT_PORT: u16 = 8080;
/// Default TPROXY port
pub const TPROXY_DEFAULT_PORT: u16 = 1234;

macro_rules! add_brackets {
    ($host:expr) => {
        if $host.contains(':') {
            format!("[{}]", $host)
        } else {
            $host.to_string()
        }
    };
}

/// Errors that can occur when parsing a remote
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Given an empty string where a valid value should be
    #[error("empty address or port")]
    EmptySegment,
    /// IPv6 address missing closing bracket
    #[error("missing closing `]`")]
    BracketMismatch,
    /// Unexpected character after an IPv6 address
    #[error("found garbage following IPv6 (first offending character `{0}`)")]
    GarbageAfterAddress(char),
    #[error("invalid port or unexpected host `{0}`: {1:?}")]
    Port(String, std::num::IntErrorKind),
    #[error("invalid protocol `{0}`")]
    Protocol(String),
    #[error("cannot use {0} with {1}")]
    UnsupportedCombination(&'static str, &'static str),
    #[error("found more than four colon-separated segments")]
    TooManySegments,
    #[error("invalid domain name `{0}`")]
    InvalidDomain(String),
}

/// Configuration for one item to forward
#[derive(Debug, derive_more::Display, Clone, Eq, PartialEq)]
#[display("{local_addr}:{remote_addr}/{protocol}")]
pub struct Remote {
    /// Local-side forwarding info
    pub local_addr: LocalSpec,
    /// Peer-side forwarding info
    #[expect(clippy::struct_field_names)]
    pub remote_addr: RemoteSpec,
    /// Layer-4 protocol this instance forwards
    pub protocol: Protocol,
}

/// The local side can be either IP+port or "stdio"
#[derive(Debug, derive_more::Display, Clone, Eq)]
pub enum LocalSpec {
    /// An IP socket
    #[display("{}:{}", add_brackets!(_0.0), _0.1)]
    Inet((String, u16)),
    /// Standard input/output
    #[display("stdio")]
    Stdio,
    /// Unix domain socket
    #[display("[unix:{}]", _0.display())]
    DomainSocket(PathBuf),
}

impl PartialEq for LocalSpec {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Inet((host1, port1)), Self::Inet((host2, port2))) => {
                host1.eq_ignore_ascii_case(host2) && port1 == port2
            }
            (Self::Stdio, Self::Stdio) => true,
            (Self::DomainSocket(path1), Self::DomainSocket(path2)) => path1 == path2,
            _ => false,
        }
    }
}

/// The remote side can be either IP+port, "socks", "http", or "tproxy"
#[derive(Debug, derive_more::Display, Clone, Eq)]
pub enum RemoteSpec {
    /// An IP socket
    #[display("{}:{}", add_brackets!(_0.0), _0.1)]
    Inet((String, u16)),
    /// Function as a SOCKS proxy
    #[display("socks")]
    Socks,
    /// Function as a HTTP proxy
    #[display("http")]
    Http,
    /// Configure the listen socket for Transparent Proxy
    #[display("tproxy")]
    Tproxy,
}

impl PartialEq for RemoteSpec {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Inet((host1, port1)), Self::Inet((host2, port2))) => {
                host1.eq_ignore_ascii_case(host2) && port1 == port2
            }
            (Self::Socks, Self::Socks)
            | (Self::Http, Self::Http)
            | (Self::Tproxy, Self::Tproxy) => true,
            _ => false,
        }
    }
}

/// Protocol can be either "tcp" or "udp".
#[derive(Debug, derive_more::Display, Copy, Clone, Hash, Eq, PartialEq)]
#[display(rename_all = "lowercase")]
pub enum Protocol {
    /// Transmission Control Protocol
    Tcp,
    /// User Datagram Protocol
    Udp,
}

/// Tokenize a remote string by splitting on `:`.
/// We don't need RE!
fn tokenize_remote(s: &str) -> Result<Vec<&str>, Error> {
    let mut tokens = Vec::new();
    let mut stuff = s;
    macro_rules! check_and_push {
        ($token:expr) => {
            if tokens.len() >= 4 {
                // Check for this early to reduce work in the error case
                return Err(Error::TooManySegments);
            }
            if $token.is_empty() {
                return Err(Error::EmptySegment);
            }
            tokens.push($token);
        };
    }
    loop {
        // IPv6 address in brackets
        if stuff.starts_with('[') {
            // `str::find` gives us the index of ']', and since it is single-byte,
            // `end+1` is also a byte index on UTF-8 boundaries and thus safe for slicing.
            let end = stuff.find(']').ok_or(Error::BracketMismatch)?;
            // Excluding the brackets here
            check_and_push!(&stuff[1..end]);
            // Now stuff[end+1..] should start with ':', so we check that
            match stuff[end + 1..].chars().next() {
                // Good. skip the ':' and continue processing the rest
                Some(':') => stuff = &stuff[end + 2..],
                Some(ch) => return Err(Error::GarbageAfterAddress(ch)),
                // If the string ends at the ']', then we are done
                // Note that such a case is (currently) not a valid remote
                // but we handle that later in `Remote::from_str` so this tokenizer
                // remains neutral in case some future format needs this construction
                None => return Ok(tokens),
            }
        } else if let Some((token, rest)) = stuff.split_once(':') {
            check_and_push!(token);
            stuff = rest;
        } else {
            check_and_push!(stuff);
            return Ok(tokens);
        }
    }
}

impl FromStr for Remote {
    type Err = Error;

    /// Parse a remote specification.
    #[expect(clippy::too_many_lines)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        macro_rules! parse_port_or_bail {
            ($port_str:expr) => {
                $port_str
                    .parse::<u16>()
                    .map_err(|e| Error::Port($port_str.to_string(), *e.kind()))?
            };
        }
        macro_rules! parse_remote_special {
            ($special_name:expr) => {
                match $special_name {
                    "socks" => RemoteSpec::Socks,
                    "http" => RemoteSpec::Http,
                    "tproxy" => RemoteSpec::Tproxy,
                    // The caller must ensure this
                    _ => unreachable!(),
                }
            };
        }
        let (rest, proto) = match s.rsplit_once('/') {
            Some((rest, proto)) if !proto.contains(':') => (rest, proto.parse()?),
            _ => (s, Protocol::Tcp),
        };
        let tokens = tokenize_remote(rest)?;
        let result = match tokens[..] {
            // One element: either "socks", "http", "tproxy" or a port number.
            ["socks"] => Self {
                local_addr: LocalSpec::Inet((default_host!(local), SOCKS_DEFAULT_PORT)),
                remote_addr: RemoteSpec::Socks,
                protocol: proto,
            },
            ["http"] => Self {
                local_addr: LocalSpec::Inet((default_host!(local), HTTP_DEFAULT_PORT)),
                remote_addr: RemoteSpec::Http,
                protocol: proto,
            },
            ["tproxy"] => Self {
                local_addr: LocalSpec::Inet((default_host!(local), TPROXY_DEFAULT_PORT)),
                remote_addr: RemoteSpec::Tproxy,
                protocol: proto,
            },
            [port] => Self {
                local_addr: LocalSpec::Inet((default_host!(unspec), parse_port_or_bail!(port))),
                remote_addr: RemoteSpec::Inet((default_host!(local), parse_port_or_bail!(port))),
                protocol: proto,
            },
            // Two elements:
            // - "stdio" and "socks", "http", or "tproxy",
            // - "stdio" and remote port number,
            // - unix domain socket and "socks", "http", or "tproxy",
            // - local port number and "socks", "http", or "tproxy",
            // - unix domain socket and remote port number, or
            // - remote host and port number.
            ["stdio", "socks" | "http"] => Self {
                local_addr: LocalSpec::Stdio,
                remote_addr: parse_remote_special!(tokens[1]),
                protocol: proto,
            },
            ["stdio", "tproxy"] => {
                return Err(Error::UnsupportedCombination(
                    "stdio local",
                    "tproxy remote",
                ));
            }
            ["stdio", port] => Self {
                local_addr: LocalSpec::Stdio,
                remote_addr: RemoteSpec::Inet((default_host!(local), parse_port_or_bail!(port))),
                protocol: proto,
            },
            [uds_path, "socks" | "http" | "tproxy"] if uds_path.starts_with("unix:") => Self {
                local_addr: LocalSpec::DomainSocket(PathBuf::from(&uds_path[5..])),
                remote_addr: parse_remote_special!(tokens[1]),
                protocol: proto,
            },
            [port, "socks" | "http" | "tproxy"] => Self {
                local_addr: LocalSpec::Inet((default_host!(local), parse_port_or_bail!(port))),
                remote_addr: parse_remote_special!(tokens[1]),
                protocol: proto,
            },
            [uds_path, port] if uds_path.starts_with("unix:") => Self {
                local_addr: LocalSpec::DomainSocket(PathBuf::from(&uds_path[5..])),
                remote_addr: RemoteSpec::Inet((default_host!(local), parse_port_or_bail!(port))),
                protocol: proto,
            },
            [host, port] => Self {
                local_addr: LocalSpec::Inet((default_host!(unspec), parse_port_or_bail!(port))),
                remote_addr: RemoteSpec::Inet((
                    idna::domain_to_ascii(host)
                        .map_err(|_| Error::InvalidDomain(host.to_string()))?,
                    parse_port_or_bail!(port),
                )),
                protocol: proto,
            },
            // Three elements:
            // - "stdio", remote host, and port number,
            // - local host, local port number, and (either "socks", "http", or "tproxy"),
            // - local port number, remote host, and port number, or
            // - unix domain socket, remote host, and port number.
            ["stdio", remote_host, remote_port] => Self {
                local_addr: LocalSpec::Stdio,
                remote_addr: RemoteSpec::Inet((
                    idna::domain_to_ascii(remote_host)
                        .map_err(|_| Error::InvalidDomain(remote_host.to_string()))?,
                    parse_port_or_bail!(remote_port),
                )),
                protocol: proto,
            },
            [local_host, local_port, "socks" | "http" | "tproxy"] => Self {
                local_addr: LocalSpec::Inet((
                    idna::domain_to_ascii(local_host)
                        .map_err(|_| Error::InvalidDomain(local_host.to_string()))?,
                    parse_port_or_bail!(local_port),
                )),
                remote_addr: parse_remote_special!(tokens[2]),
                protocol: proto,
            },
            [uds_path, remote_host, remote_port] if uds_path.starts_with("unix:") => Self {
                local_addr: LocalSpec::DomainSocket(PathBuf::from(&uds_path[5..])),
                remote_addr: RemoteSpec::Inet((
                    idna::domain_to_ascii(remote_host)
                        .map_err(|_| Error::InvalidDomain(remote_host.to_string()))?,
                    parse_port_or_bail!(remote_port),
                )),
                protocol: proto,
            },
            [local_port, remote_host, remote_port] => Self {
                local_addr: LocalSpec::Inet((
                    default_host!(unspec),
                    parse_port_or_bail!(local_port),
                )),
                remote_addr: RemoteSpec::Inet((
                    idna::domain_to_ascii(remote_host)
                        .map_err(|_| Error::InvalidDomain(remote_host.to_string()))?,
                    parse_port_or_bail!(remote_port),
                )),
                protocol: proto,
            },
            // Four elements: local host, local port, remote host, and remote port.
            [local_host, local_port, remote_host, remote_port] => Self {
                local_addr: LocalSpec::Inet((
                    idna::domain_to_ascii(local_host)
                        .map_err(|_| Error::InvalidDomain(local_host.to_string()))?,
                    parse_port_or_bail!(local_port),
                )),
                remote_addr: RemoteSpec::Inet((
                    idna::domain_to_ascii(remote_host)
                        .map_err(|_| Error::InvalidDomain(remote_host.to_string()))?,
                    parse_port_or_bail!(remote_port),
                )),
                protocol: proto,
            },
            _ => {
                // This should be unreachable since we check in `tokenize_remote`
                debug_assert!(
                    false,
                    "`tokenize_remote` did not catch too many segments (this is a bug)"
                );
                return Err(Error::TooManySegments);
            }
        };
        // Check for invalid cases
        if matches!(
            result,
            Self {
                remote_addr: RemoteSpec::Socks | RemoteSpec::Http,
                protocol: Protocol::Udp,
                ..
            }
        ) {
            return Err(Error::UnsupportedCombination("socks or http local", "udp"));
        }
        if matches!(
            result,
            Self {
                local_addr: LocalSpec::DomainSocket(_),
                protocol: Protocol::Udp,
                ..
            }
        ) {
            return Err(Error::UnsupportedCombination(
                "unix domain socket local",
                "udp",
            ));
        }
        if matches!(
            result,
            Self {
                local_addr: LocalSpec::DomainSocket(_),
                remote_addr: RemoteSpec::Tproxy,
                ..
            }
        ) {
            return Err(Error::UnsupportedCombination(
                "unix domain socket local",
                "tproxy remote",
            ));
        }
        Ok(result)
    }
}

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(Error::Protocol(other.to_string())),
        }
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
        let tests: &[(&str, String, Remote)] = &[
            // jpillora's tests and an exhausive list of cases
            // See <https://www.iana.org/domains/reserved> for the
            // official IDN test domains
            (
                "3000",
                format!(
                    "{}:3000:{}:3000/tcp",
                    add_brackets!(default_host!(unspec)),
                    add_brackets!(default_host!(local))
                ),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 3000)),
                    remote_addr: RemoteSpec::Inet((default_host!(local), 3000)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "4000/udp",
                format!(
                    "{}:4000:{}:4000/udp",
                    add_brackets!(default_host!(unspec)),
                    add_brackets!(default_host!(local))
                ),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 4000)),
                    remote_addr: RemoteSpec::Inet((default_host!(local), 4000)),
                    protocol: Protocol::Udp,
                },
            ),
            (
                "google.com:80",
                format!(
                    "{}:80:google.com:80/tcp",
                    add_brackets!(default_host!(unspec))
                ),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 80)),
                    remote_addr: RemoteSpec::Inet((String::from("google.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "テスト.テスト:80",
                format!(
                    "{}:80:XN--ZCKZAH.XN--ZCKZAH:80/tcp",
                    add_brackets!(default_host!(unspec))
                ),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 80)),
                    remote_addr: RemoteSpec::Inet((String::from("XN--ZCKZAH.XN--ZCKZAH"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "8080:example.com:80",
                format!(
                    "{}:8080:example.com:80/tcp",
                    add_brackets!(default_host!(unspec))
                ),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 8080)),
                    remote_addr: RemoteSpec::Inet((String::from("example.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "socks",
                format!(
                    "{}:{SOCKS_DEFAULT_PORT}:socks/tcp",
                    add_brackets!(default_host!(local))
                ),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(local), SOCKS_DEFAULT_PORT)),
                    remote_addr: RemoteSpec::Socks,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "9050:socks",
                format!("{}:9050:socks/tcp", add_brackets!(default_host!(local))),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(local), 9050)),
                    remote_addr: RemoteSpec::Socks,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "127.0.0.1:1081:socks",
                String::from("127.0.0.1:1081:socks/tcp"),
                Remote {
                    local_addr: LocalSpec::Inet((String::from("127.0.0.1"), 1081)),
                    remote_addr: RemoteSpec::Socks,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "http",
                format!(
                    "{}:{HTTP_DEFAULT_PORT}:http/TCP",
                    add_brackets!(default_host!(local))
                ),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(local), HTTP_DEFAULT_PORT)),
                    remote_addr: RemoteSpec::Http,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "8888:http",
                format!("{}:8888:http/tcp", add_brackets!(default_host!(local))),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(local), 8888)),
                    remote_addr: RemoteSpec::Http,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "[2001:db8::1]:3081:socks",
                String::from("[2001:db8::1]:3081:socks/tcp"),
                Remote {
                    local_addr: LocalSpec::Inet((String::from("2001:db8::1"), 3081)),
                    remote_addr: RemoteSpec::Socks,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "tproxy",
                format!(
                    "{}:{TPROXY_DEFAULT_PORT}:tproxy/tcp",
                    add_brackets!(default_host!(local))
                ),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(local), TPROXY_DEFAULT_PORT)),
                    remote_addr: RemoteSpec::Tproxy,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "tproxy/udp",
                format!(
                    "{}:{TPROXY_DEFAULT_PORT}:tproxy/udp",
                    add_brackets!(default_host!(local))
                ),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(local), TPROXY_DEFAULT_PORT)),
                    remote_addr: RemoteSpec::Tproxy,
                    protocol: Protocol::Udp,
                },
            ),
            (
                "5000:tproxy",
                format!("{}:5000:tproxy/tcp", add_brackets!(default_host!(local))),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(local), 5000)),
                    remote_addr: RemoteSpec::Tproxy,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "4567:tproxy/udp",
                format!("{}:4567:tproxy/udp", add_brackets!(default_host!(local))),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(local), 4567)),
                    remote_addr: RemoteSpec::Tproxy,
                    protocol: Protocol::Udp,
                },
            ),
            (
                "127.0.0.1:1081:tproxy",
                String::from("127.0.0.1:1081:tproxy/tcp"),
                Remote {
                    local_addr: LocalSpec::Inet((String::from("127.0.0.1"), 1081)),
                    remote_addr: RemoteSpec::Tproxy,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "127.0.0.1:1081:tproxy/udp",
                String::from("127.0.0.1:1081:tproxy/udp"),
                Remote {
                    local_addr: LocalSpec::Inet((String::from("127.0.0.1"), 1081)),
                    remote_addr: RemoteSpec::Tproxy,
                    protocol: Protocol::Udp,
                },
            ),
            (
                "[::1]:12345:tproxy/udp",
                String::from("[::1]:12345:tproxy/udp"),
                Remote {
                    local_addr: LocalSpec::Inet((String::from("::1"), 12345)),
                    remote_addr: RemoteSpec::Tproxy,
                    protocol: Protocol::Udp,
                },
            ),
            (
                "[unix:/tmp/socket]:8080",
                format!(
                    "[unix:/tmp/socket]:{}:8080/tcp",
                    add_brackets!(default_host!(local))
                ),
                Remote {
                    local_addr: LocalSpec::DomainSocket(PathBuf::from("/tmp/socket")),
                    remote_addr: RemoteSpec::Inet((default_host!(local), 8080)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "[unix:/tmp/socket]:socks",
                String::from("[unix:/tmp/socket]:socks/tcp"),
                Remote {
                    local_addr: LocalSpec::DomainSocket(PathBuf::from("/tmp/socket")),
                    remote_addr: RemoteSpec::Socks,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "[unix:/tmp/path:with:a:colon]:http",
                String::from("[unix:/tmp/path:with:a:colon]:http/tcp"),
                Remote {
                    local_addr: LocalSpec::DomainSocket(PathBuf::from("/tmp/path:with:a:colon")),
                    remote_addr: RemoteSpec::Http,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "[unix:/tmp/socket]:example.com:80",
                String::from("[unix:/tmp/socket]:example.com:80/tcp"),
                Remote {
                    local_addr: LocalSpec::DomainSocket(PathBuf::from("/tmp/socket")),
                    remote_addr: RemoteSpec::Inet((String::from("example.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "[unix:/tmp/用户路径]:测试.テスト:443",
                String::from("[unix:/tmp/用户路径]:XN--0ZWM56D.XN--ZCKZAH:443/tcp"),
                Remote {
                    local_addr: LocalSpec::DomainSocket(PathBuf::from("/tmp/用户路径")),
                    remote_addr: RemoteSpec::Inet((String::from("xn--0zwm56d.xn--zckzah"), 443)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "1.1.1.1:53/udp",
                format!("{}:53:1.1.1.1:53/udp", add_brackets!(default_host!(unspec))),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 53)),
                    remote_addr: RemoteSpec::Inet((String::from("1.1.1.1"), 53)),
                    protocol: Protocol::Udp,
                },
            ),
            (
                "localhost:5353:1.1.1.1:53/udp",
                String::from("localhost:5353:1.1.1.1:53/udp"),
                Remote {
                    local_addr: LocalSpec::Inet((String::from("localhost"), 5353)),
                    remote_addr: RemoteSpec::Inet((String::from("1.1.1.1"), 53)),
                    protocol: Protocol::Udp,
                },
            ),
            (
                "22:example.com:22",
                format!(
                    "{}:22:example.com:22/tcp",
                    add_brackets!(default_host!(unspec))
                ),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 22)),
                    remote_addr: RemoteSpec::Inet((String::from("example.com"), 22)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "5444:example.테스트:5442",
                format!(
                    "{}:5444:example.XN--9T4B11YI5A:5442/tcp",
                    add_brackets!(default_host!(unspec))
                ),
                Remote {
                    local_addr: LocalSpec::Inet((default_host!(unspec), 5444)),
                    remote_addr: RemoteSpec::Inet((String::from("example.XN--9T4B11YI5A"), 5442)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "[::1]:8080:google.com:80",
                String::from("[::1]:8080:google.com:80/tcp"),
                Remote {
                    local_addr: LocalSpec::Inet((String::from("::1"), 8080)),
                    remote_addr: RemoteSpec::Inet((String::from("google.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "localhost:5354:[2001:db8:4860:0:0:0:0:8888]:53/udp",
                String::from("localhost:5354:[2001:db8:4860:0:0:0:0:8888]:53/udp"),
                Remote {
                    local_addr: LocalSpec::Inet((String::from("localhost"), 5354)),
                    remote_addr: RemoteSpec::Inet((String::from("2001:db8:4860:0:0:0:0:8888"), 53)),
                    protocol: Protocol::Udp,
                },
            ),
            (
                // Make sure your editor supports mixed LTR and RTL before editing this line
                "آزمایشی.испытание:123:δοκιμή.net:9999/tcp",
                String::from("XN--HGBK6AJ7F53BBA.XN--80AKHBYKNJ4F:123:XN--JXALPDLP.net:9999/tcp"),
                Remote {
                    local_addr: LocalSpec::Inet((
                        String::from("XN--HGBK6AJ7F53BBA.XN--80AKHBYKNJ4F"),
                        123,
                    )),
                    remote_addr: RemoteSpec::Inet((String::from("XN--JXALPDLP.net"), 9999)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "stdio:google.com:80",
                String::from("stdio:google.com:80/tcp"),
                Remote {
                    local_addr: LocalSpec::Stdio,
                    remote_addr: RemoteSpec::Inet((String::from("google.com"), 80)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "stdio:socks",
                String::from("stdio:socks/tcp"),
                Remote {
                    local_addr: LocalSpec::Stdio,
                    remote_addr: RemoteSpec::Socks,
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "stdio:443",
                format!("stdio:{}:443/tcp", add_brackets!(default_host!(local))),
                Remote {
                    local_addr: LocalSpec::Stdio,
                    remote_addr: RemoteSpec::Inet((default_host!(local), 443)),
                    protocol: Protocol::Tcp,
                },
            ),
            (
                "stdio:5353/udp",
                format!("stdio:{}:5353/udp", add_brackets!(default_host!(local))),
                Remote {
                    local_addr: LocalSpec::Stdio,
                    remote_addr: RemoteSpec::Inet((default_host!(local), 5353)),
                    protocol: Protocol::Udp,
                },
            ),
        ];
        for (s, canonical, expected) in tests {
            // Test that the common format is parsed correctly
            let actual = s.parse::<Remote>().unwrap();
            assert_eq!(actual, *expected);
            // Test that the canonical format is as expected
            if !actual.to_string().eq_ignore_ascii_case(&canonical) {
                assert!(
                    false,
                    "Assertion failed: actual.to_string() = {:?}, canonical = {canonical:?}",
                    actual.to_string()
                );
            }
            // Test that the canonical format is made and parsed correctly
            let reparsed = actual.to_string().parse::<Remote>().unwrap();
            assert_eq!(reparsed, *expected);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_parse_remote_bad() {
        crate::tests::setup_logging();
        let tests: &[(&str, Error)] = &[
            ("", Error::EmptySegment),
            (":80", Error::EmptySegment),
            (":9000:example.com:22", Error::EmptySegment),
            ("0.0.0.0:80::80/udp", Error::EmptySegment),
            ("[::]:80:[]:80", Error::EmptySegment),
            ("[]:80", Error::EmptySegment),
            (
                "example.com",
                Error::Port(
                    String::from("example.com"),
                    std::num::IntErrorKind::InvalidDigit,
                ),
            ),
            (
                "[::1]",
                Error::Port(String::from("::1"), std::num::IntErrorKind::InvalidDigit),
            ),
            (
                "just_a_hostname",
                Error::Port(
                    String::from("just_a_hostname"),
                    std::num::IntErrorKind::InvalidDigit,
                ),
            ),
            (
                "99999",
                Error::Port(String::from("99999"), std::num::IntErrorKind::PosOverflow),
            ),
            ("1:2:3:4:5", Error::TooManySegments),
            (
                "host:port",
                Error::Port(String::from("port"), std::num::IntErrorKind::InvalidDigit),
            ),
            // More of just abusing Rust's UTF-8 support
            ("[::1]إختبار:80", Error::GarbageAfterAddress('إ')),
            ("[::1:80", Error::BracketMismatch),
            (
                "[::1]:99/nonsense",
                Error::Protocol(String::from("nonsense")),
            ),
            (
                "socks/udp",
                Error::UnsupportedCombination("socks or http local", "udp"),
            ),
            (
                "http/udp",
                Error::UnsupportedCombination("socks or http local", "udp"),
            ),
            (
                "stdio:tproxy",
                Error::UnsupportedCombination("stdio local", "tproxy remote"),
            ),
            (
                "[unix:/tmp/socket]:tproxy/udp",
                Error::UnsupportedCombination("unix domain socket local", "udp"),
            ),
            (
                "[unix:/tmp/socket]:tproxy",
                Error::UnsupportedCombination("unix domain socket local", "tproxy remote"),
            ),
        ];
        for (s, expected) in tests {
            // Test that an incorrect format is rejected with the correct error
            let actual = s.parse::<Remote>().unwrap_err();
            assert_eq!(actual, *expected);
        }
    }
}
