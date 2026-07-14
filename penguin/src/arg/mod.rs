//! Command line arguments parsing.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

#[cfg(feature = "server")]
mod backend_url;
#[cfg(feature = "server")]
mod bind_addr;
#[cfg(feature = "client")]
mod header;
#[cfg(feature = "client")]
#[macro_use]
mod remote_spec;
#[cfg(feature = "client")]
mod server_url;
mod url_common;

#[cfg(feature = "server")]
pub use self::{
    backend_url::BackendUrl,
    bind_addr::{BindIpv4, BindIpv6},
};
#[cfg(feature = "client")]
pub use self::{
    header::Header,
    remote_spec::{LocalSpec, Protocol, Remote, RemoteSpec},
    server_url::ServerUrl,
};
// Export this macro for use in tests
#[cfg(feature = "client")]
pub(crate) use self::remote_spec::default_host;

#[cfg(feature = "acme")]
use crate::server::ChallengeHelper;
use clap::{ArgAction, Args, Parser, Subcommand};
use http::HeaderValue;
#[cfg(feature = "client")]
use http::Uri;
#[cfg(feature = "acme")]
use instant_acme::LetsEncrypt;
use penguin_mux::timing::OptionalDuration;
use std::{fmt::Debug, sync::OnceLock};

/// Command line arguments (main application)
#[derive(Parser, Debug)]
#[command(
    author, about, long_about = None,
    version = format!(concat!(clap::crate_version!(), " (protocol {})"), penguin_mux::PROTOCOL_VERSION)
)]
#[command(propagate_version = true)]
pub struct PenguinCli {
    /// Subcommand (`client` or `server`)
    #[clap(subcommand)]
    pub subcommand: Commands,
    /// Level of verbosity
    #[arg(short, long, conflicts_with = "quiet", action = ArgAction::Count, global = true)]
    pub verbose: u8,
    /// Level of quietness
    #[arg(short, long, conflicts_with = "verbose", action = ArgAction::Count, global = true)]
    pub quiet: u8,
}

/// Global args to avoid cloning
pub static ARGS: OnceLock<PenguinCli> = OnceLock::new();

impl PenguinCli {
    /// Obtain reference to the global static instance
    ///
    /// # Panics
    /// Panics if `ARGS` is not initialized
    pub fn get_global() -> &'static Self {
        ARGS.get().expect("ARGS is not initialized (this is a bug)")
    }

    /// Parse command line arguments and set the global static instance
    ///
    /// # Panics
    /// Panics if `ARGS` is already initialized
    pub fn parse_global() {
        ARGS.set(Self::parse())
            .expect("`parse_global` should not be called twice (this is a bug)");
    }
}

/// Possible subcommands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Penguin client
    #[cfg(feature = "client")]
    #[clap(name = "client")]
    Client(ClientArgs),
    /// Penguin server
    #[cfg(feature = "server")]
    #[clap(name = "server")]
    Server(ServerArgs),
}

#[cfg(feature = "client")]
const REMOTE_SPEC_HELP: &str = concat!(
    r#"Remote connections tunneled through the server, each of which come in the form:

[R:][LOCAL_SPEC:]REMOTE_SPEC[/PROTOCOL]

where

- LOCAL_SPEC is { [LOCAL_HOST:]LOCAL_PORT | stdio | \[unix:PATH\] }
- REMOTE_SPEC is { [REMOTE_HOST:]REMOTE_PORT | socks | http | tproxy }
- PROTOCOL is { tcp | udp }

When REMOTE_HOST is omitted, it defaults to `"#,
    default_host!([local]),
    r#"` (server localhost).
When LOCAL_HOST is omitted, it defaults to `"#,
    default_host!([unspec]),
    r#"` (all interfaces),
with the exception of `socks`, `http`, and `tproxy` remotes, whose default LOCAL_HOST is
`"#,
    default_host!([local]),
    r#"` (client localhost).
When LOCAL_PORT is omitted, it defaults to REMOTE_PORT.
When PROTOCOL is omitted, it defaults to `tcp`.

LOCAL_HOST and REMOTE_HOST must be enclosed in brackets if they are IPv6 addresses, e.g. `[::1]`.

The prefix `R:` indicates that the roles of the server and client are reversed (for only this remote).
That is, the server will listen on LOCAL_HOST:LOCAL_PORT and forward connections to
REMOTE_HOST:REMOTE_PORT on the client. Reverse remotes does not support `stdio` or unix domain sockets
as LOCAL_SPEC, nor `socks`, `http`, or `tproxy` as REMOTE_SPEC.

Examples:
- 3000
- R:3000/udp
- example.com:3000
- 3000:google.com:80
- R:192.168.0.5:3000:google.com:80
- socks
- 5000:socks
- stdio:example.com:22
- 1.1.1.1:53/udp
- tproxy/udp
- 5000:tproxy
- [::1]:12345:tproxy/udp

When REMOTE_SPEC is `socks`, penguin listens on `LOCAL_HOST:LOCAL_PORT` and
acts as a SOCKS4/SOCKS5 proxy server (both versions supported).
The default LOCAL_PORT of a `socks` remote is `1080`. `socks` remotes cannot be UDP.

When REMOTE_SPEC is `http`, penguin listens on `LOCAL_HOST:LOCAL_PORT` and
acts as an HTTP proxy server (GET or CONNECT).
The default LOCAL_PORT of an `http` remote is `8080`. `http` remotes cannot be UDP.

When REMOTE_SPEC is `tproxy`, penguin listens on `LOCAL_HOST:LOCAL_PORT` and
forwards traffic to the destination address obtained from `SO_ORIGINAL_DST` (Linux)
or `/dev/pf` (BSD, in progress). The default LOCAL_PORT of a `tproxy` remote is `1234`.
`tproxy` remotes cannot be used with `stdio` or `unix` sockets.

When LOCAL_SPEC is `stdio`, penguin connects standard input/output of this program with
the remote. For example, one may use this option with ssh ProxyCommand:
```sh
ssh -o ProxyCommand='penguin client <server> stdio:%h:%p'
    user@example.com
```
to connect to an SSH server through the tunnel.
Only one `stdio` remote is allowed, but it can be combined with other remotes.

When LOCAL_SPEC is a unix domain socket, penguin listens on the specified path instead of
an `AF_INET[6]` socket. Unix UDP sockets and Windows named pipes are not supported.
"#
);

/// Penguin client arguments.
#[expect(clippy::doc_markdown, clippy::pub_underscore_fields)]
#[cfg(feature = "client")]
#[derive(Args, Clone, Debug, Default)]
pub struct ClientArgs {
    /// URL to the penguin server.
    pub server: ServerUrl,
    /// Remote port forwarding specifications.
    // The underlying port is a `u16`, which gives `0..=65535`; 0 is not allowed,
    // so the range of available ports is `1..=65535`,
    // giving 65535 available remotes.
    #[arg(num_args=1..=65535, required = true, help = crate::arg::REMOTE_SPEC_HELP)]
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
    /// Allow this amount of time without the server acknowledging the
    /// keepalive pings before disconnecting.
    /// This value must be at least `keepalive`, and will be implicitly
    /// clamped to that value if it is lower.
    #[arg(long, default_value = "60")]
    pub keepalive_timeout: OptionalDuration,
    /// Maximum number of times to retry before exiting.
    /// A value of 0 means unlimited.
    #[arg(long, default_value_t = 0)]
    pub max_retry_count: u32,
    /// Maximum wait time (in milliseconds) before retrying after a
    /// disconnection.
    #[arg(long, default_value_t = 300000)]
    pub max_retry_interval: u64,
    /// Timeout for the initial `WebSocket` handshake (in seconds).
    /// A value of 0 disables the timeout.
    #[arg(long, default_value = "10")]
    pub handshake_timeout: OptionalDuration,
    /// An optional HTTP CONNECT or SOCKS5 proxy which will be
    /// used to reach the penguin server. Authentication can be specified
    /// inside the URL.
    /// For example, http://admin:password@my-server.com:8081
    ///         or: socks://admin:password@my-server.com:1080
    #[arg(short = 'x', long)]
    pub proxy: Option<Uri>,
    /// Set a custom header in the form "HeaderName: HeaderContent".
    /// Can be used multiple times.
    /// (e.g --header "Foo: Bar" --header "Hello: World")
    #[arg(short = 'H', long)]
    pub header: Vec<Header>,
    /// Optionally set the 'Host' header (defaults to the host
    /// found in the server url). If `tls-server-name` is not set,
    /// this value will also be used as the TLS Server Name.
    #[arg(long)]
    pub hostname: Option<HeaderValue>,
    /// Optionally set the TLS Server Name for the SNI field.
    /// Defaults to the value passed to `hostname`, or the host
    /// found in the server url if `hostname` is not set.
    #[arg(long)]
    pub tls_server_name: Option<String>,
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
    #[arg(long, default_value = "10")]
    pub channel_timeout: OptionalDuration,
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
#[cfg(feature = "server")]
#[derive(Args, Debug, Default)]
#[expect(clippy::struct_excessive_bools, clippy::pub_underscore_fields)]
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
    /// Whether HTTP forwarding headers should be added to requests proxied to
    /// the backend.
    #[arg(long, default_value_t = false)]
    pub backend_add_forwarding_headers: bool,
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
    /// Allow clients to specify reverse port forwarding remotes in addition to
    /// normal remotes.
    #[arg(long = "reverse")]
    pub reverse: bool,
    /// Bind outgoing IPv4 sockets to this IP address.
    #[arg(long, default_value_t)]
    pub outgoing_from_v4: BindIpv4,
    /// Bind outgoing IPv6 sockets to this IP address.
    #[arg(long, default_value_t)]
    pub outgoing_from_v6: BindIpv6,
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

/// Remove brackets from possbly an IPv6 address
#[must_use]
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
    use std::str::FromStr;

    #[cfg(feature = "client")]
    #[cfg_attr(not(feature = "server"), expect(irrefutable_let_patterns))]
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
                    local_addr: LocalSpec::Inet((crate::arg::default_host!(unspec), 1234)),
                    remote_addr: RemoteSpec::Inet((crate::arg::default_host!(local), 1234)),
                    protocol: Protocol::Tcp,
                    reversed: false,
                }]
            );
        }
    }

    #[cfg(feature = "client")]
    #[cfg_attr(not(feature = "server"), expect(irrefutable_let_patterns))]
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
            "--keepalive-timeout",
            "15",
            "--max-retry-count",
            "400",
            "--max-retry-interval",
            "1000",
            "--handshake-timeout",
            "5",
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
                        reversed: false,
                    },
                    Remote {
                        local_addr: LocalSpec::Inet(("192.168.1.1".to_string(), 8080)),
                        remote_addr: RemoteSpec::Inet(("localhost".to_string(), 80)),
                        protocol: Protocol::Tcp,
                        reversed: false,
                    },
                ]
            );
            assert_eq!(args.ws_psk, Some(HeaderValue::from_static("avocado")));
            assert_eq!(args.keepalive, OptionalDuration::from_secs(10));
            assert_eq!(args.keepalive_timeout, OptionalDuration::from_secs(15));
            assert_eq!(args.max_retry_count, 400);
            assert_eq!(args.max_retry_interval, 1000);
            assert_eq!(args.handshake_timeout, OptionalDuration::from_secs(5));
            let proxy = args.proxy.unwrap().into_parts();
            assert_eq!(
                proxy.scheme.unwrap(),
                http::uri::Scheme::from_str("socks5").unwrap()
            );
            assert_eq!(proxy.path_and_query.unwrap(), "/");
            assert_eq!(proxy.authority.as_ref().unwrap().host(), "localhost");
            assert_eq!(proxy.authority.as_ref().unwrap().port_u16().unwrap(), 1080);
            assert_eq!(
                proxy.authority.unwrap(),
                http::uri::Authority::from_static("abc:123@localhost:1080")
            );
            assert_eq!(args.header, [Header::from_str("X-Test:test").unwrap()]);
            assert_eq!(args.hostname, Some(HeaderValue::from_static("example.com")));
        }
    }

    #[cfg(feature = "server")]
    #[cfg_attr(not(feature = "client"), expect(irrefutable_let_patterns))]
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

    #[cfg(feature = "server")]
    #[cfg_attr(not(feature = "client"), expect(irrefutable_let_patterns))]
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

    #[cfg(feature = "server")]
    #[cfg_attr(not(feature = "client"), expect(irrefutable_let_patterns))]
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

    #[cfg(feature = "server")]
    #[cfg_attr(not(feature = "client"), expect(irrefutable_let_patterns))]
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
            assert!(!args.reverse);
            assert_eq!(args.tls_key, None);
            assert_eq!(args.tls_cert, None);
            assert_eq!(args.tls_domain, ["example.com", "example.net"]);
            assert_eq!(args.tls_ca, None);
            assert_eq!(args.timeout, OptionalDuration::from_secs(50));
        }
    }

    #[cfg(feature = "server")]
    #[cfg_attr(not(feature = "client"), expect(irrefutable_let_patterns))]
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
            "--backend-add-forwarding-headers",
            "--obfs",
            "--404-resp",
            "404",
            "--ws-psk",
            "avocado",
            "--reverse",
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
            assert!(args.reverse);
            assert_eq!(args.tls_key, Some("key.pem".to_string()));
            assert_eq!(args.tls_cert, Some("cert.pem".to_string()));
            assert_eq!(args.tls_ca, Some("ca.pem".to_string()));
            #[cfg(feature = "acme")]
            assert_eq!(args.tls_domain, Vec::<String>::new());
            assert_eq!(args.timeout, OptionalDuration::from_secs(50));
        }
    }
}
