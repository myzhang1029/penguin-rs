//! Common TLS functionalities.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

#[cfg(all(feature = "aws-lc-rs", feature = "meek-chromium"))]
pub mod aws_lc_rs_chromium;
mod maybe_tls;
#[cfg(feature = "nativetls")]
mod native;
#[cfg(feature = "__rustls")]
mod rustls;

#[cfg(all(feature = "nativetls", feature = "acme"))]
use self::native::make_server_config_from_pem;
#[cfg(all(feature = "__rustls", feature = "acme"))]
use self::rustls::make_server_config_from_pem;
#[cfg(feature = "__rustls")]
use ::rustls::pki_types::InvalidDnsNameError;
use arc_swap::ArcSwap;
use std::sync::Arc;
use thiserror::Error;
#[cfg(any(feature = "client", test))]
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(all(feature = "__rustls", feature = "server"))]
pub use self::rustls::{HyperConnector, make_hyper_connector};
#[expect(clippy::module_name_repetitions)]
#[cfg(feature = "__rustls")]
pub use self::rustls::{TlsIdentityInner, make_client_config, make_server_config};
#[cfg(all(feature = "nativetls", feature = "server"))]
pub use native::{HyperConnector, make_hyper_connector};
#[cfg(feature = "nativetls")]
pub use native::{TlsIdentityInner, make_client_config, make_server_config};

#[cfg(feature = "nativetls")]
use tokio_native_tls::TlsStream;
#[cfg(feature = "__rustls")]
use tokio_rustls::TlsStream;

pub use maybe_tls::MaybeTlsStream;

/// A hot-swappable container for a TLS key and certificate.
#[expect(clippy::module_name_repetitions)]
pub type TlsIdentity = Arc<ArcSwap<TlsIdentityInner>>;

/// Error type for TLS configuration
#[derive(Error, Debug)]
pub enum Error {
    /// IO errors when reading certificates, keys, or CA files
    #[error("error reading certificate, key, or CA: {0}")]
    ReadCert(std::io::Error),
    /// IO errors when making connections
    #[error("error making a TCP connection: {0}")]
    TcpConnect(std::io::Error),
    /// Errors from `rustls`
    #[error("rustls error: {0}")]
    #[cfg(feature = "__rustls")]
    Rustls(#[from] ::rustls::Error),
    /// Could not determine the server name for SNI
    #[cfg(feature = "__rustls")]
    #[error("unable to determine server name for SNI")]
    DnsName(#[from] InvalidDnsNameError),
    /// Could not create a TLS verifier for `rustls`
    #[error("verifier error: {0}")]
    #[cfg(feature = "__rustls")]
    Verifier(#[from] ::rustls::client::VerifierBuilderError),
    /// Failed to parse certificates
    #[error("failed to parse certificates: {0}")]
    #[cfg(feature = "nativetls")]
    CertParse(#[from] tokio_native_tls::native_tls::Error),
    /// Unsupported feature
    #[error("{0} is not supported: {1}")]
    UnsupportedFeature(&'static str, &'static str),
}

/// Initialize the process-wide Rustls crypto provider according to the features enabled in this build.
#[expect(clippy::must_use_candidate)]
pub fn init_crypto_provider() -> Option<()> {
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    ::rustls::crypto::ring::default_provider()
        .install_default()
        .ok()?;
    #[cfg(all(feature = "aws-lc-rs", feature = "meek-chromium"))]
    aws_lc_rs_chromium::chromium_like_provider()
        .install_default()
        .ok()?;
    #[cfg(all(feature = "aws-lc-rs", not(feature = "meek-chromium")))]
    ::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok()?;
    Some(())
}

/// Create a TCP connection and wrap it in a TLS stream
///
/// # Errors
/// - Returns [`Error::TcpConnect`] if the TCP connection fails.
/// - Returns the appropriate TLS error from the TLS library used.
#[cfg(any(feature = "client", test))]
pub async fn tls_connect<IO>(
    underlying_io: IO,
    server_name: &str,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tls_ca: Option<&str>,
    tls_insecure: bool,
) -> Result<TlsStream<IO>, Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let config =
        make_client_config(tls_cert, tls_key, tls_ca, tls_insecure, Some(&["http/1.1"])).await?;
    #[cfg(feature = "nativetls")]
    let tls_stream = {
        let connector = tokio_native_tls::TlsConnector::from(config);
        connector.connect(server_name, underlying_io).await?
    };
    #[cfg(feature = "__rustls")]
    let tls_stream = {
        let connector: tokio_rustls::TlsConnector = Arc::new(config).into();
        let server_name = ::rustls::pki_types::ServerName::try_from(server_name.to_string())?;
        let client_st = connector
            .connect(server_name, underlying_io)
            .await
            .map_err(Error::TcpConnect)?;
        TlsStream::Client(client_st)
    };
    Ok(tls_stream)
}

/// Create a TLS identity from certificate and key file paths
///
/// # Errors
/// - See [`make_server_config`] for details on errors.
pub async fn make_tls_identity(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<TlsIdentity, Error> {
    let identity = make_server_config(cert_path, key_path, client_ca_path).await?;
    Ok(Arc::new(ArcSwap::from_pointee(identity)))
}

/// Create a TLS identity from a keypair in PEM format
///
/// # Errors
/// See [`make_server_config_from_pem`] for details on errors.
#[cfg(feature = "acme")]
pub async fn make_tls_identity_from_pem(
    certs: String,
    priv_key_pem: String,
    client_ca_path: Option<&str>,
) -> Result<TlsIdentity, Error> {
    let identity = make_server_config_from_pem(certs, priv_key_pem, client_ca_path).await?;
    Ok(Arc::new(ArcSwap::from_pointee(identity)))
}

/// Reload the TLS identity with the provided certificate and key file paths
///
/// # Errors
/// See [`make_server_config`] for details on errors.
#[cfg(unix)]
pub async fn reload_tls_identity(
    identity: &TlsIdentity,
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<(), Error> {
    let new = make_server_config(cert_path, key_path, client_ca_path).await?;
    identity.store(Arc::new(new));
    Ok(())
}

/// Reload the TLS identity with a keypair in PEM format
///
/// # Errors
/// See [`make_tls_identity_from_pem`] for details on errors.
#[cfg(feature = "acme")]
pub async fn reload_tls_identity_from_pem(
    identity: &TlsIdentity,
    certs: String,
    priv_key_pem: String,
    client_ca_path: Option<&str>,
) -> Result<(), Error> {
    let new = make_server_config_from_pem(certs, priv_key_pem, client_ca_path).await?;
    identity.store(Arc::new(new));
    Ok(())
}
