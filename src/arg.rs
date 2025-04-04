//! Command line arguments parsing.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::parse_remote::Remote;
#[cfg(feature = "acme")]
use crate::server::acme::ChallengeHelper;
use clap::{arg, command, ArgAction, Args, Parser, Subcommand};
use http::{
    header::HeaderName,
    uri::{Authority, PathAndQuery, Scheme},
    HeaderValue, Uri,
};
#[cfg(feature = "acme")]
use instant_acme::LetsEncrypt;
use penguin_mux::timing::OptionalDuration;
use std::{fmt::Debug, ops::Deref, str::FromStr, sync::OnceLock};
use thiserror::Error;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct PenguinCli {
    #[clap(subcommand)]
    pub subcommand: Commands,
    #[arg(short, long, conflicts_with = "quiet", action = ArgAction::Count, global = true)]
    pub verbose: u8,
    #[arg(short, long, conflicts_with = "verbose", action = ArgAction::Count, global = true)]
    pub quiet: u8,
}

/// Global args to avoid cloning
pub static ARGS: OnceLock<PenguinCli> = OnceLock::new();

impl PenguinCli {
    pub fn get_global() -> &'static Self {
        ARGS.get().expect("ARGS is not initialized (this is a bug)")
    }

    pub fn parse_global() {
        ARGS.set(Self::parse())
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
    Server(ServerArgs),
}

// Descriptions are mainly directly stripped from myzhang1029/penguin
/// Penguin client arguments.
#[derive(Args, Debug, Default)]
pub struct ClientArgs {
    /// URL to the penguin server.
    pub server: ServerUrl,
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
    ///   The word "socks" may be in the place of remote-host and remote-port
    ///   to create a SOCKS4/SOCKS5 proxy server. The default local host and
    ///   port for a "socks" remote is 127.0.0.1:1080. "socks" remotes cannot
    ///   be UDP.
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
    pub remote: Vec<Remote>,
    /// An optional Pre-Shared Key for WebSocket upgrade to present
    /// to the server in the HTTP header X-Penguin-PSK. If the server requires
    /// this key but the client does not present the correct key, the upgrade
    /// to WebSocket silently fails.
    #[arg(long)]
    pub ws_psk: Option<HeaderValue>,
    /// An optional keepalive interval. Since the underlying
    /// transport is HTTP, in many instances we'll be traversing through
    /// proxies, often these proxies will close idle connections. You must
    /// specify a time in seconds (set to 0 to disable).
    #[arg(long, default_value = "25")]
    pub keepalive: OptionalDuration,
    /// Maximum number of times to retry before exiting.
    /// A value of 0 means unlimited.
    #[arg(long, default_value_t = 0)]
    pub max_retry_count: u32,
    /// Maximum wait time (in milliseconds) before retrying after a
    /// disconnection.
    #[arg(long, default_value_t = 300000)]
    pub max_retry_interval: u64,
    /// An optional HTTP CONNECT or SOCKS5 proxy which will be
    /// used to reach the penguin server. Authentication can be specified
    /// inside the URL.
    /// For example, http://admin:password@my-server.com:8081
    ///         or: socks://admin:password@my-server.com:1080
    #[arg(short = 'x', long)]
    pub proxy: Option<String>,
    /// Set a custom header in the form "HeaderName: HeaderContent".
    /// Can be used multiple times.
    /// (e.g --header "Foo: Bar" --header "Hello: World")
    #[arg(short = 'H', long)]
    pub header: Vec<Header>,
    /// Optionally set the 'Host' header (defaults to the host
    /// found in the server url).
    #[arg(long)]
    pub hostname: Option<HeaderValue>,
    /// An optional root certificate bundle used to verify the
    /// penguin server. Only valid when connecting to the server with
    /// "https" or "wss". By default, the operating system CAs will be used.
    #[arg(short, long)]
    pub tls_ca: Option<String>,
    /// Skip server TLS certificate verification of
    /// chain and host name (if TLS is used for transport connections to
    /// server). If set, client accepts any TLS certificate presented by
    /// the server and any host name in that certificate. This only affects
    /// transport https (wss) connection.
    #[arg(short = 'k', long)]
    pub tls_skip_verify: bool,
    /// A path to a PEM encoded private key used for client
    /// authentication (mutual-TLS).
    #[arg(long, requires = "tls_cert")]
    pub tls_key: Option<String>,
    /// A path to a PEM encoded certificate matching the provided
    /// private key. The certificate must have client authentication
    /// enabled (mutual-TLS).
    #[arg(long, requires = "tls_key")]
    pub tls_cert: Option<String>,
    /// Timeout for establishing channels (in seconds).
    #[arg(long, default_value_t = 10)]
    pub channel_timeout: u64,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "pid")]
    pub _pid: bool,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "fingerprint")]
    pub _fingerprint: Option<String>,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "auth")]
    pub _auth: Option<String>,
}

/// Penguin server arguments.
#[derive(Args, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct ServerArgs {
    /// Defines the HTTP listening host - the network interface.
    /// If multiple ports are specified, `penguin` will listen on all of them.
    /// If TLS is enabled, it will apply to all listening hosts.
    #[arg(long, default_values = ["::"])]
    pub host: Vec<String>,
    /// Defines the HTTP listening port.
    /// If the number of ports is less than the number of hosts,
    /// the last port will be used for the remaining hosts. If the number of
    /// ports is greater than the number of hosts, the remaining ports will
    /// be ignored.
    #[arg(short, long, default_values_t = [8080])]
    pub port: Vec<u16>,
    /// Specifies another HTTP server to proxy requests to when
    /// penguin receives a normal HTTP request. Useful for hiding penguin in
    /// plain sight.
    #[arg(long)]
    pub backend: Option<BackendUrl>,
    /// Try harder to hide from Active Probes (disable /health and
    /// /version endpoints and HTTP headers that could potentially be used
    /// to fingerprint penguin). It is strongly recommended to use --ws-psk
    /// and TLS.
    #[arg(long)]
    pub obfs: bool,
    /// Content to send with a 404 response.
    #[arg(long = "404-resp", default_value = "Not found")]
    pub not_found_resp: String,
    /// An optional Pre-Shared Key for WebSocket upgrade. If this
    /// option is supplied but the client does not present the correct key
    /// in the HTTP header X-Penguin-PSK, the upgrade to WebSocket silently fails.
    #[arg(long)]
    pub ws_psk: Option<HeaderValue>,
    /// Enables TLS and provides optional path to a PEM-encoded
    /// TLS private key. When this flag is set, you must also set --tls-cert,
    /// and you cannot set --tls-domain.
    #[arg(long, requires = "tls_cert")]
    pub tls_key: Option<String>,
    /// Enables TLS and provides optional path to a PEM-encoded
    /// TLS certificate. When this flag is set, you must also set --tls-key,
    /// and you cannot set --tls-domain.
    #[arg(long, requires = "tls_key")]
    pub tls_cert: Option<String>,
    /// A path to a PEM encoded CA certificate bundle or a directory
    /// holding multiple PEM encode CA certificate bundle files, which is used to
    /// validate client connections. The provided CA certificates will be used
    /// instead of the system roots. This is commonly used to implement mutual-TLS.
    #[arg(long)]
    pub tls_ca: Option<String>,
    #[cfg(feature = "acme")]
    /// Automatically obtain a TLS certificate for the specified domain using
    /// ACME. We only support the HTTP-01 challenge type and requires a helper
    /// command specified in --tls-acme-challenge-helper.
    #[arg(long, conflicts_with_all = ["tls_key", "tls_cert"], requires = "tls_acme_accept_tos", requires = "tls_acme_challenge_helper")]
    pub tls_domain: Vec<String>,
    #[cfg(feature = "acme")]
    /// ACME directory URL to use for the ACME challenge.
    /// Defaults to the Let's Encrypt production URL.
    #[arg(long, default_value = LetsEncrypt::Production.url())]
    pub tls_acme_url: String,
    #[cfg(feature = "acme")]
    /// Email address to use for ACME account registration.
    #[arg(long)]
    pub tls_acme_email: Option<String>,
    #[cfg(feature = "acme")]
    /// Accept the ACME terms of service. You must expressly accept the terms of
    /// service by setting this flag to true.
    #[arg(long)]
    pub tls_acme_accept_tos: bool,
    #[cfg(feature = "acme")]
    /// Command to run for the ACME HTTP-01 challenge. The arguments will be in
    /// the form of:
    /// <cmd> (create|remove) xxxx.yyyy
    /// The command should create a file at
    /// /.well-known/acme-challenge/xxxx
    /// containing only xxxx.yyyy (the token) when `create` is passed, and remove
    /// the file when `remove` is passed. This is used by the ACME client to
    #[arg(long)]
    pub tls_acme_challenge_helper: Option<ChallengeHelper>,
    /// Timeout for TLS handshake and HTTP data in seconds.
    /// Setting to 0 disables timeouts.
    #[arg(long, default_value = "60")]
    pub timeout: OptionalDuration,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "pid")]
    pub _pid: bool,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "socks5")]
    pub _socks5: bool,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "reverse")]
    pub _reverse: bool,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "keepalive", default_value = "0")]
    pub _keepalive: OptionalDuration,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "auth")]
    pub _auth: Option<String>,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "authfile")]
    pub _authfile: Option<String>,
    /// For compatibility with `chisel` only. This option is a no-op.
    #[arg(long = "key")]
    pub _key: Option<String>,
}

/// Server URL parsing errors
#[derive(Debug, Error)]
pub enum ServerUrlError {
    #[error("failed to parse server URL: {0}")]
    UrlParse(#[from] http::uri::InvalidUri),
    #[error("incorrect scheme in server URL: {0}")]
    IncorrectScheme(Scheme),
    #[error("missing host in server URL")]
    MissingHost,
    #[error("cannot build server URL: {0}")]
    BuildUrl(#[from] http::Error),
}

/// Server URL
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
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
            _ => Err(ServerUrlError::IncorrectScheme(old_scheme)),
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
        Ok(Self(url))
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
    InvalidScheme(Scheme),
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
            return Err(BackendUrlError::InvalidScheme(scheme));
        }
        Ok(Self {
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

impl std::fmt::Display for BackendUrl {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}{}", self.scheme, self.authority, self.path)
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
    pub name: HeaderName,
    pub value: HeaderValue,
}

impl FromStr for Header {
    type Err = HeaderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, value) = s
            .split_once(':')
            .ok_or_else(|| Self::Err::Format(s.to_string()))?;
        let name = HeaderName::from_str(name)?;
        let value = HeaderValue::from_str(value.trim())?;
        Ok(Self { name, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_remote::{LocalSpec, Protocol, RemoteSpec};

    #[test]
    fn test_serverurl_fromstr() {
        crate::tests::setup_logging();
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
        ServerUrl::from_str("ftp://example.com").unwrap_err();
    }

    #[test]
    fn test_backendurl_fromstr() {
        crate::tests::setup_logging();
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
        BackendUrl::from_str("ftp://example.com").unwrap_err();
        BackendUrl::from_str("http://").unwrap_err();
    }

    #[test]
    fn test_header_parser() {
        crate::tests::setup_logging();
        let header = Header::from_str("X-Test: test").unwrap();
        assert_eq!(header.name.as_str().to_lowercase(), "X-Test".to_lowercase());
        header.value.to_str().unwrap();
        assert_eq!(header.value.to_str().unwrap(), "test");
        Header::from_str("X-Test").unwrap_err();
        // HTTP forbids empty header values, but we allow it
        //assert!(Header::from_str("X-Test:").is_err());
        Header::from_str(": test").unwrap_err();
        let header = Header::from_str("X-Test: test: test").unwrap();
        assert_eq!(header.name.as_str().to_lowercase(), "X-Test".to_lowercase());
        header.value.to_str().unwrap();
        assert_eq!(header.value.to_str().unwrap(), "test: test");
        let header = Header::from_str("X-Test:test").unwrap();
        assert_eq!(header.name.as_str().to_lowercase(), "X-Test".to_lowercase());
        header.value.to_str().unwrap();
        assert_eq!(header.value.to_str().unwrap(), "test");
    }

    #[test]
    fn test_client_args_minimal() {
        crate::tests::setup_logging();
        let args = PenguinCli::parse_from(["penguin", "client", "127.0.0.1:9999/endpoint", "1234"]);
        assert!(matches!(args.subcommand, Commands::Client(_)));
        if let Commands::Client(args) = args.subcommand {
            let server_uri = args.server.0;
            // Make sure the server URI is interpreted correctly
            assert_eq!(server_uri.scheme_str(), Some("ws"));
            assert_eq!(server_uri.host(), Some("127.0.0.1"));
            assert_eq!(server_uri.port_u16(), Some(9999));
            assert_eq!(server_uri.path(), "/endpoint");
            // This probably is covered by tests in `parse_remote`, but just in case
            assert_eq!(
                args.remote,
                [Remote {
                    local_addr: LocalSpec::Inet((crate::parse_remote::default_host!(unspec), 1234)),
                    remote_addr: RemoteSpec::Inet((
                        crate::parse_remote::default_host!(local),
                        1234
                    )),
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
            assert_eq!(args.keepalive, OptionalDuration::from_secs(10));
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

    #[test]
    fn test_server_args_minimal() {
        let args = PenguinCli::parse_from(["penguin", "server"]);
        assert!(matches!(args.subcommand, Commands::Server(_)));
        if let Commands::Server(args) = args.subcommand {
            assert_eq!(args.host, ["::"]);
            assert_eq!(args.port, [8080]);
            assert_eq!(args.backend, None);
            assert!(!args.obfs);
            assert_eq!(args.not_found_resp, "Not found");
            assert_eq!(args.ws_psk, None);
            assert_eq!(args.tls_key, None);
            assert_eq!(args.tls_cert, None);
            assert_eq!(args.tls_ca, None);
            // default timeout; make sure is not None
            assert_eq!(args.timeout, OptionalDuration::from_secs(60));
        }
    }

    #[test]
    fn test_server_args_just_host() {
        let args = PenguinCli::parse_from(["penguin", "server", "--host", "0.0.0.0"]);
        assert!(matches!(args.subcommand, Commands::Server(_)));
        if let Commands::Server(args) = args.subcommand {
            assert_eq!(args.host, ["0.0.0.0"]);
            assert_eq!(args.port, [8080]);
            assert_eq!(args.backend, None);
            assert!(!args.obfs);
            assert_eq!(args.not_found_resp, "Not found");
            assert_eq!(args.ws_psk, None);
            assert_eq!(args.tls_key, None);
            assert_eq!(args.tls_cert, None);
            assert_eq!(args.tls_ca, None);
        }
    }

    #[test]
    fn test_server_args_just_port() {
        let args = PenguinCli::parse_from(["penguin", "server", "--port", "45"]);
        assert!(matches!(args.subcommand, Commands::Server(_)));
        if let Commands::Server(args) = args.subcommand {
            assert_eq!(args.host, ["::"]);
            assert_eq!(args.port, [45]);
            assert_eq!(args.backend, None);
            assert!(!args.obfs);
            assert_eq!(args.not_found_resp, "Not found");
            assert_eq!(args.ws_psk, None);
            assert_eq!(args.tls_key, None);
            assert_eq!(args.tls_cert, None);
            assert_eq!(args.tls_ca, None);
        }
    }

    #[test]
    fn test_server_args_port_cover_ahead() {
        let args = PenguinCli::parse_from([
            "penguin",
            "server",
            "--host",
            "0.0.0.0",
            "--host",
            "127.0.0.1",
        ]);
        assert!(matches!(args.subcommand, Commands::Server(_)));
        if let Commands::Server(args) = args.subcommand {
            assert_eq!(args.host, ["0.0.0.0", "127.0.0.1"]);
            assert_eq!(args.port, [8080]);
            assert_eq!(args.backend, None);
            assert!(!args.obfs);
            assert_eq!(args.not_found_resp, "Not found");
            assert_eq!(args.ws_psk, None);
            assert_eq!(args.tls_key, None);
            assert_eq!(args.tls_cert, None);
            assert_eq!(args.tls_ca, None);
        }
    }

    #[cfg(feature = "acme")]
    #[test]
    fn test_server_args_must_agree_tos() {
        let result = PenguinCli::try_parse_from([
            "penguin",
            "server",
            "--host",
            "example.com",
            "--port",
            "1234",
            "--host",
            "2.example.com",
            "--tls-domain",
            "example.com",
            "--tls-domain",
            "example.net",
            "--tls-acme-email",
            "test@example.com",
            "--timeout",
            "50",
        ]);
        assert!(
            result.is_err(),
            "Expected an error due to missing --tls-acme-accept-tos"
        );
    }

    #[cfg(feature = "acme")]
    #[test]
    fn test_server_args_acme_full() {
        let args = PenguinCli::parse_from([
            "penguin",
            "server",
            "--host",
            "example.com",
            "--port",
            "1234",
            "--host",
            "2.example.com",
            "--port",
            "5678",
            "--backend",
            "https://example.com",
            "--obfs",
            "--404-resp",
            "404",
            "--ws-psk",
            "avocado",
            "--tls-domain",
            "example.com",
            "--tls-domain",
            "example.net",
            "--tls-acme-email",
            "test@example.com",
            "--tls-acme-accept-tos",
            "--tls-acme-challenge-helper",
            "echo",
            "--timeout",
            "50",
        ]);
        assert!(matches!(args.subcommand, Commands::Server(_)));
        if let Commands::Server(args) = args.subcommand {
            assert_eq!(args.host, ["example.com", "2.example.com"]);
            assert_eq!(args.port, [1234, 5678]);
            assert_eq!(
                args.backend,
                Some(BackendUrl::from_str("https://example.com").unwrap())
            );
            assert!(args.obfs);
            assert_eq!(args.not_found_resp, "404");
            assert_eq!(args.ws_psk, Some(HeaderValue::from_static("avocado")));
            assert_eq!(args.tls_key, None);
            assert_eq!(args.tls_cert, None);
            assert_eq!(args.tls_domain, ["example.com", "example.net"]);
            assert_eq!(args.tls_ca, None);
            assert_eq!(args.timeout, OptionalDuration::from_secs(50));
        }
    }

    #[test]
    fn test_server_args_full() {
        let args = PenguinCli::parse_from([
            "penguin",
            "server",
            "--host",
            "example.com",
            "--port",
            "1234",
            "--host",
            "2.example.com",
            "--port",
            "5678",
            "--backend",
            "https://example.com",
            "--obfs",
            "--404-resp",
            "404",
            "--ws-psk",
            "avocado",
            "--tls-key",
            "key.pem",
            "--tls-cert",
            "cert.pem",
            "--tls-ca",
            "ca.pem",
            "--timeout",
            "50",
        ]);
        assert!(matches!(args.subcommand, Commands::Server(_)));
        if let Commands::Server(args) = args.subcommand {
            assert_eq!(args.host, ["example.com", "2.example.com"]);
            assert_eq!(args.port, [1234, 5678]);
            assert_eq!(
                args.backend,
                Some(BackendUrl::from_str("https://example.com").unwrap())
            );
            assert!(args.obfs);
            assert_eq!(args.not_found_resp, "404");
            assert_eq!(args.ws_psk, Some(HeaderValue::from_static("avocado")));
            assert_eq!(args.tls_key, Some("key.pem".to_string()));
            assert_eq!(args.tls_cert, Some("cert.pem".to_string()));
            assert_eq!(args.tls_ca, Some("ca.pem".to_string()));
            #[cfg(feature = "acme")]
            assert_eq!(args.tls_domain, Vec::<String>::new());
            assert_eq!(args.timeout, OptionalDuration::from_secs(50));
        }
    }
}
