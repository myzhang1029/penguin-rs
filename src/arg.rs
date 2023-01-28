//! Command line arguments parsing.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::parse_remote::Remote;
use clap::{arg, command, ArgAction, Args, Parser, Subcommand};
use http::{
    header::HeaderName,
    uri::{Authority, PathAndQuery, Scheme},
    HeaderValue, Uri,
};
use once_cell::sync::OnceCell;
use std::{ops::Deref, str::FromStr};
use thiserror::Error;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct PenguinCli {
    #[clap(subcommand)]
    pub(crate) subcommand: Commands,
    #[arg(short, long, conflicts_with = "quiet", action = ArgAction::Count, global = true)]
    pub(crate) verbose: u8,
    #[arg(short, long, conflicts_with = "verbose", action = ArgAction::Count, global = true)]
    pub(crate) quiet: u8,
}

/// Global args to avoid cloning
pub(crate) static ARGS: OnceCell<PenguinCli> = OnceCell::new();

impl PenguinCli {
    pub fn get_global() -> &'static Self {
        ARGS.get().expect("ARGS is not initialized (this is a bug)")
    }

    pub(crate) fn parse_global() {
        ARGS.set(PenguinCli::parse())
            .expect("`parse_global` should not be called twice (this is a bug)");
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Penguin client
    #[clap(name = "client")]
    Client(ClientArgs),
    /// Penguin server
    #[clap(name = "server")]
    Server(Box<ServerArgs>),
}

// Descriptions are mainly directly stripped from myzhang1029/penguin
/// Penguin client arguments.
#[derive(Args, Debug)]
pub struct ClientArgs {
    /// URL to the penguin server.
    pub(crate) server: ServerUrl,
    /// Remote connections tunneled through the server, each of
    /// which come in the form:
    ///
    /// <local-host>:<local-port>:<remote-host>:<remote-port>/<protocol>
    ///
    /// - local-host defaults to 0.0.0.0 (all interfaces).
    ///
    /// - local-port defaults to remote-port.
    ///
    /// - remote-port is required*.
    ///
    /// - remote-host defaults to 127.0.0.1 (server localhost).
    ///
    /// - protocol defaults to tcp.
    ///
    /// which shares <remote-host>:<remote-port> from the server to the client
    /// as <local-host>:<local-port>.
    ///
    ///   example remotes
    ///
    ///     3000
    ///
    ///     example.com:3000
    ///
    ///     3000:google.com:80
    ///
    ///     192.168.0.5:3000:google.com:80
    ///
    ///     socks
    ///
    ///     5000:socks
    ///
    ///     stdio:example.com:22
    ///
    ///     1.1.1.1:53/udp
    ///
    ///   When the penguin server has --socks5 enabled, remotes can
    ///   specify "socks" in place of remote-host and remote-port.
    ///   The default local host and port for a "socks" remote is
    ///   127.0.0.1:1080. Connections to this remote will terminate
    ///   at the server's internal SOCKS5 proxy.
    ///
    ///   When stdio is used as local-host, the tunnel will connect standard
    ///   input/output of this program with the remote. This is useful when
    ///   combined with ssh ProxyCommand. You can use
    ///     ssh -o ProxyCommand='penguin client <server> stdio:%h:%p'
    ///         user@example.com
    ///   to connect to an SSH server through the tunnel.
    // The underlying port is a u16, which gives 0..=65535; 0 is not allowed,
    // so the range of available ports is 1..=65535,
    // giving 65535 available remotes.
    #[arg(num_args=1..=65535, required = true)]
    pub(crate) remote: Vec<Remote>,
    /// An optional Pre-Shared Key for WebSocket upgrade to present
    /// to the server in the HTTP header X-Penguin-PSK. If the server requires
    /// this key but the client does not present the correct key, the upgrade
    /// to WebSocket silently fails.
    #[arg(long)]
    pub(crate) ws_psk: Option<HeaderValue>,
    /// An optional keepalive interval. Since the underlying
    /// transport is HTTP, in many instances we'll be traversing through
    /// proxies, often these proxies will close idle connections. You must
    /// specify a time in seconds (set to 0 to disable).
    #[arg(long, default_value_t = 25)]
    pub(crate) keepalive: u64,
    /// Maximum number of times to retry before exiting.
    /// Defaults 0, meaning unlimited.
    #[arg(long, default_value_t = 0)]
    pub(crate) max_retry_count: u32,
    /// Maximum wait time (in milliseconds) before retrying after a
    /// disconnection.
    #[arg(long, default_value_t = 300000)]
    pub(crate) max_retry_interval: u64,
    /// An optional HTTP CONNECT or SOCKS5 proxy which will be
    /// used to reach the penguin server. Authentication can be specified
    /// inside the URL.
    /// For example, http://admin:password@my-server.com:8081
    ///         or: socks://admin:password@my-server.com:1080
    #[arg(short = 'x', long)]
    pub(crate) proxy: Option<String>,
    /// Set a custom header in the form "HeaderName: HeaderContent".
    /// Can be used multiple times.
    /// (e.g --header "Foo: Bar" --header "Hello: World")
    #[arg(short = 'H', long)]
    pub(crate) header: Vec<Header>,
    /// Optionally set the 'Host' header (defaults to the host
    /// found in the server url).
    #[arg(long)]
    pub(crate) hostname: Option<HeaderValue>,
    /// An optional root certificate bundle used to verify the
    /// penguin server. Only valid when connecting to the server with
    /// "https" or "wss". By default, the operating system CAs will be used.
    #[arg(short, long)]
    pub(crate) tls_ca: Option<String>,
    /// Skip server TLS certificate verification of
    /// chain and host name (if TLS is used for transport connections to
    /// server). If set, client accepts any TLS certificate presented by
    /// the server and any host name in that certificate. This only affects
    /// transport https (wss) connection.
    #[arg(short = 'k', long)]
    pub(crate) tls_skip_verify: bool,
    /// A path to a PEM encoded private key used for client
    /// authentication (mutual-TLS).
    #[arg(long, requires = "tls_cert")]
    pub(crate) tls_key: Option<String>,
    /// A path to a PEM encoded certificate matching the provided
    /// private key. The certificate must have client authentication
    /// enabled (mutual-TLS).
    #[arg(long, requires = "tls_key")]
    pub(crate) tls_cert: Option<String>,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "pid")]
    pub(crate) _pid: bool,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "fingerprint")]
    pub(crate) _fingerprint: Option<String>,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "auth")]
    pub(crate) _auth: Option<String>,
}

/// Penguin server arguments.
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct ServerArgs {
    /// Defines the HTTP listening host - the network interface
    /// (defaults to ::).
    #[arg(long, default_value = "::")]
    pub(crate) host: String,
    /// Defines the HTTP listening port (defaults to port 8080).
    #[arg(short, long, default_value_t = 8080)]
    pub(crate) port: u16,
    /// Specifies another HTTP server to proxy requests to when
    /// penguin receives a normal HTTP request. Useful for hiding penguin in
    /// plain sight.
    #[arg(long)]
    pub(crate) backend: Option<BackendUrl>,
    /// Try harder to hide from Active Probes (disable /health and
    /// /version endpoints and HTTP headers that could potentially be used
    /// to fingerprint penguin). It is strongly recommended to use --ws-psk
    /// and TLS.
    #[arg(long)]
    pub(crate) obfs: bool,
    /// Content to send with a 404 response. Defaults to 'Not found'.
    #[arg(long = "404-resp", default_value = "Not found")]
    pub(crate) not_found_resp: String,
    /// An optional Pre-Shared Key for WebSocket upgrade. If this
    /// option is supplied but the client does not present the correct key
    /// in the HTTP header X-Penguin-PSK, the upgrade to WebSocket silently fails.
    #[arg(long)]
    pub(crate) ws_psk: Option<HeaderValue>,
    /// Enables TLS and provides optional path to a PEM-encoded
    /// TLS private key. When this flag is set, you must also set --tls-cert,
    /// and you cannot set --tls-domain.
    #[arg(long, requires = "tls_cert")]
    pub(crate) tls_key: Option<String>,
    /// Enables TLS and provides optional path to a PEM-encoded
    /// TLS certificate. When this flag is set, you must also set --tls-key,
    /// and you cannot set --tls-domain.
    #[arg(long, requires = "tls_key")]
    pub(crate) tls_cert: Option<String>,
    /// A path to a PEM encoded CA certificate bundle or a directory
    /// holding multiple PEM encode CA certificate bundle files, which is used to
    /// validate client connections. The provided CA certificates will be used
    /// instead of the system roots. This is commonly used to implement mutual-TLS.
    #[arg(long)]
    pub(crate) tls_ca: Option<String>,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "pid")]
    pub(crate) _pid: bool,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "socks5")]
    pub(crate) _socks5: bool,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "reverse")]
    pub(crate) _reverse: bool,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "keepalive", default_value_t = 0)]
    pub(crate) _keepalive: u64,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "auth")]
    pub(crate) _auth: Option<String>,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "authfile")]
    pub(crate) _authfile: Option<String>,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "key")]
    pub(crate) _key: Option<String>,
}

/// Server URL parsing errors
#[derive(Debug, Error)]
pub enum ServerUrlError {
    #[error("failed to parse server URL: {0}")]
    UrlParse(#[from] http::uri::InvalidUri),
    #[error("incorrect scheme in server URL: {0}")]
    IncorrectScheme(String),
    #[error("missing host in server URL")]
    MissingHost,
    #[error("cannot build server URL: {0}")]
    BuildUrl(#[from] http::Error),
}

/// Server URL
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerUrl(pub Uri);

impl FromStr for ServerUrl {
    type Err = ServerUrlError;

    /// Sanitize the URL for WebSocket
    fn from_str(url: &str) -> Result<Self, Self::Err> {
        let url_parts = match Uri::from_str(url) {
            Ok(url) => url.into_parts(),
            Err(e) => {
                // Try harder to provide a default scheme if none is provided
                // `Uri`'s parser will not accept a URL without a scheme
                // unless it only contains authority
                if !url.starts_with("http://")
                    && !url.starts_with("https://")
                    && !url.starts_with("ws://")
                    && !url.starts_with("wss://")
                {
                    let url = format!("ws://{url}");
                    Uri::from_str(&url)?.into_parts()
                } else {
                    return Err(e.into());
                }
            }
        };
        let old_scheme = url_parts.scheme.unwrap_or(http::uri::Scheme::HTTP);
        let new_scheme = match old_scheme.as_ref() {
            "http" | "ws" => Ok("ws"),
            "https" | "wss" => Ok("wss"),
            _ => Err(ServerUrlError::IncorrectScheme(old_scheme.to_string())),
        }?;
        // Convert to a `Uri`.
        let url = Uri::builder()
            .scheme(new_scheme)
            .authority(url_parts.authority.ok_or(Self::Err::MissingHost)?)
            .path_and_query(
                url_parts
                    .path_and_query
                    .unwrap_or_else(|| PathAndQuery::from_static("/")),
            )
            .build()?;
        Ok(ServerUrl(url))
    }
}

impl Deref for ServerUrl {
    type Target = Uri;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Backend URL parsing errors
#[derive(Debug, Error)]
pub enum BackendUrlError {
    #[error("failed to parse backend URL: {0}")]
    UrlParse(#[from] http::uri::InvalidUri),
    #[error("missing authority in backend URL")]
    MissingAuthority,
    #[error("invalid backend scheme: {0}")]
    InvalidScheme(String),
}

/// Backend URL
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendUrl {
    pub scheme: Scheme,
    pub authority: Authority,
    pub path: PathAndQuery,
}

impl FromStr for BackendUrl {
    type Err = BackendUrlError;

    /// Sanitize the backend URL
    fn from_str(url: &str) -> Result<Self, Self::Err> {
        // We don't try as hard to parse the URL as we do for the server URL
        // because the backend URL is on the server side, so we don't need to
        // be as forgiving.
        let url_parts = Uri::from_str(url)?.into_parts();
        let scheme = url_parts.scheme.unwrap_or(Scheme::HTTP);
        if scheme != Scheme::HTTP && scheme != Scheme::HTTPS {
            return Err(BackendUrlError::InvalidScheme(scheme.to_string()));
        }
        Ok(BackendUrl {
            scheme,
            authority: url_parts
                .authority
                .ok_or(BackendUrlError::MissingAuthority)?,
            path: url_parts
                .path_and_query
                .unwrap_or_else(|| PathAndQuery::from_static("/")),
        })
    }
}

impl ToString for BackendUrl {
    fn to_string(&self) -> String {
        let mut url = String::new();
        url.push_str(self.scheme.as_str());
        url.push_str("://");
        url.push_str(self.authority.as_str());
        url.push_str(self.path.as_str());
        url
    }
}

/// HTTP Header parsing errors
#[derive(Debug, Error)]
pub enum HeaderError {
    #[error("invalid header value or hostname: {0}")]
    Value(#[from] http::header::InvalidHeaderValue),
    #[error("invalid header name: {0}")]
    Name(#[from] http::header::InvalidHeaderName),
    #[error("invalid header: {0}")]
    Format(String),
}

/// HTTP Header
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Header {
    pub(crate) name: HeaderName,
    pub(crate) value: HeaderValue,
}

impl FromStr for Header {
    type Err = HeaderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, value) = s
            .split_once(':')
            .ok_or_else(|| Self::Err::Format(s.to_string()))?;
        let name = HeaderName::from_str(name)?;
        let value = HeaderValue::from_str(value.trim())?;
        Ok(Header { name, value })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::parse_remote::{LocalSpec, Protocol, RemoteSpec};

    use super::*;

    #[test]
    fn test_serverurl_fromstr() {
        assert_eq!(
            ServerUrl::from_str("example.com").unwrap().to_string(),
            "ws://example.com/"
        );
        assert_eq!(
            ServerUrl::from_str("wss://example.com")
                .unwrap()
                .to_string(),
            "wss://example.com/"
        );
        assert_eq!(
            ServerUrl::from_str("ws://example.com").unwrap().to_string(),
            "ws://example.com/"
        );
        assert_eq!(
            ServerUrl::from_str("https://example.com")
                .unwrap()
                .to_string(),
            "wss://example.com/"
        );
        assert_eq!(
            ServerUrl::from_str("http://example.com")
                .unwrap()
                .to_string(),
            "ws://example.com/"
        );
        assert!(ServerUrl::from_str("ftp://example.com").is_err());
    }

    #[test]
    fn test_backendurl_fromstr() {
        assert_eq!(
            BackendUrl::from_str("https://example.com")
                .unwrap()
                .to_string(),
            "https://example.com/"
        );
        assert_eq!(
            BackendUrl::from_str("http://example.com")
                .unwrap()
                .to_string(),
            "http://example.com/"
        );
        assert_eq!(
            BackendUrl::from_str("https://example.com/foo").unwrap(),
            BackendUrl {
                scheme: Scheme::HTTPS,
                authority: Authority::from_static("example.com"),
                path: PathAndQuery::from_static("/foo"),
            }
        );
        assert_eq!(
            BackendUrl::from_str("http://example.com/foo?bar")
                .unwrap()
                .to_string(),
            "http://example.com/foo?bar"
        );
        assert!(BackendUrl::from_str("ftp://example.com").is_err());
        assert!(BackendUrl::from_str("http://").is_err());
    }

    #[test]
    fn test_header_parser() {
        let header = Header::from_str("X-Test: test").unwrap();
        assert_eq!(header.name.as_str().to_lowercase(), "X-Test".to_lowercase());
        assert!(header.value.to_str().is_ok());
        assert_eq!(header.value.to_str().unwrap(), "test");
        assert!(Header::from_str("X-Test").is_err());
        // HTTP forbids empty header values, but we allow it
        //assert!(Header::from_str("X-Test:").is_err());
        assert!(Header::from_str(": test").is_err());
        let header = Header::from_str("X-Test: test: test").unwrap();
        assert_eq!(header.name.as_str().to_lowercase(), "X-Test".to_lowercase());
        assert!(header.value.to_str().is_ok());
        assert_eq!(header.value.to_str().unwrap(), "test: test");
        let header = Header::from_str("X-Test:test").unwrap();
        assert_eq!(header.name.as_str().to_lowercase(), "X-Test".to_lowercase());
        assert!(header.value.to_str().is_ok());
        assert_eq!(header.value.to_str().unwrap(), "test");
    }

    #[test]
    fn test_client_args_minimal() {
        let args = PenguinCli::parse_from(["penguin", "client", "127.0.0.1:9999/endpoint", "1234"]);
        assert!(matches!(args.subcommand, Commands::Client(_)));
        if let Commands::Client(args) = args.subcommand {
            let server_uri = args.server.0;
            // Make sure the server URI is interpreted correctly
            assert_eq!(server_uri.scheme_str(), Some("ws"));
            assert_eq!(server_uri.host(), Some("127.0.0.1"));
            assert_eq!(server_uri.port_u16(), Some(9999));
            assert_eq!(server_uri.path(), "/endpoint");
            assert_eq!(
                args.remote,
                [Remote {
                    local_addr: LocalSpec::Inet(("0.0.0.0".to_string(), 1234)),
                    remote_addr: RemoteSpec::Inet(("127.0.0.1".to_string(), 1234)),
                    protocol: Protocol::Tcp,
                }]
            );
        }
    }

    #[test]
    fn test_client_args_full() {
        let args = PenguinCli::parse_from([
            "penguin",
            "client",
            "wss://127.0.0.1:9999/endpoint",
            "stdio:localhost:53/udp",
            "192.168.1.1:8080:localhost:80/tcp",
            "--ws-psk",
            "avocado",
            "--keepalive",
            "10",
            "--max-retry-count",
            "400",
            "--max-retry-interval",
            "1000",
            "--proxy",
            "socks5://abc:123@localhost:1080",
            "--header",
            "X-Test: test",
            "--hostname",
            "example.com",
        ]);
        assert!(matches!(args.subcommand, Commands::Client(_)));
        if let Commands::Client(args) = args.subcommand {
            assert_eq!(
                args.server,
                ServerUrl::from_str("wss://127.0.0.1:9999/endpoint").unwrap()
            );
            assert_eq!(
                args.remote,
                [
                    Remote {
                        local_addr: LocalSpec::Stdio,
                        remote_addr: RemoteSpec::Inet(("localhost".to_string(), 53)),
                        protocol: Protocol::Udp,
                    },
                    Remote {
                        local_addr: LocalSpec::Inet(("192.168.1.1".to_string(), 8080)),
                        remote_addr: RemoteSpec::Inet(("localhost".to_string(), 80)),
                        protocol: Protocol::Tcp,
                    },
                ]
            );
            assert_eq!(args.ws_psk, Some(HeaderValue::from_static("avocado")));
            assert_eq!(args.keepalive, 10);
            assert_eq!(args.max_retry_count, 400);
            assert_eq!(args.max_retry_interval, 1000);
            assert_eq!(
                args.proxy,
                Some("socks5://abc:123@localhost:1080".to_string())
            );
            assert_eq!(args.header, [Header::from_str("X-Test:test").unwrap()]);
            assert_eq!(args.hostname, Some(HeaderValue::from_static("example.com")));
        }
    }
}
