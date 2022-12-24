//! Command line arguments parsing.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::parse_remote::Remote;
use clap::{arg, command, Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct PenguinCli {
    #[clap(subcommand)]
    pub(crate) subcommand: Commands,
    #[arg(short, long)]
    pub(crate) verbose: bool,
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
#[derive(Args, Debug)]
pub struct ClientArgs {
    /// URL to the penguin server.
    pub(crate) server: String,
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
    // 1 is the control channel, so the range of available ports is 2..=65535,
    // giving 65534 available remotes.
    #[arg(num_args=1..65535)]
    pub(crate) remote: Vec<Remote>,
    /// An optional Pre-Shared Key for WebSocket upgrade to present
    /// to the server in the HTTP header X-Penguin-PSK. If the server requires
    /// this key but the client does not present the correct key, the upgrade
    /// to WebSocket silently fails.
    #[arg(long)]
    pub(crate) ws_psk: Option<String>,
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
    pub(crate) header: Vec<String>,
    /// Optionally set the 'Host' header (defaults to the host
    /// found in the server url).
    #[arg(long)]
    pub(crate) hostname: Option<String>,
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
}

/// Penguin server arguments.
#[derive(Args, Debug)]
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
    pub(crate) backend: Option<String>,
    /// Allow clients to access the internal SOCKS5 proxy. See
    /// `penguin client --help` for more information.
    #[arg(long)]
    pub(crate) socks5: bool,
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
    pub(crate) ws_psk: Option<String>,
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
}
