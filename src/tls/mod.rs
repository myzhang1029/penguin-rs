mod acceptor;
#[cfg(feature = "nativetls")]
mod native;
#[cfg(feature = "__rustls")]
mod rustls;

#[cfg(feature = "__rustls")]
use self::rustls::{make_client_config, make_server_config, TlsIdentityInner};
use arc_swap::ArcSwap;
use hyper::client::HttpConnector;
#[cfg(feature = "__rustls")]
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
#[cfg(feature = "nativetls")]
use hyper_tls::HttpsConnector;
#[cfg(feature = "nativetls")]
use native::{make_client_config, make_server_config, TlsIdentityInner};
use std::sync::Arc;
use thiserror::Error;
use tokio_tungstenite::Connector;

pub use acceptor::{TlsAcceptor, TlsStream};

/// A hot-swappable container for a TLS key and certificate.
pub type TlsIdentity = Arc<ArcSwap<TlsIdentityInner>>;

/// Error type for TLS configuration
#[derive(Error, Debug)]
pub enum Error {
    #[error("Error reading certificate, key, or CA: {0}")]
    ReadCert(#[from] std::io::Error),
    #[error("Empty client certificate store")]
    #[cfg(feature = "__rustls")]
    EmptyClientCertStore,
    #[error("Failed to parse CA store: {0}")]
    #[cfg(feature = "__rustls")]
    CaStoreParse(#[from] webpki::Error),
    #[error("Rustls error: {0}")]
    #[cfg(feature = "__rustls")]
    Rustls(#[from] ::rustls::Error),
    #[error("Failed to parse certificates: {0}")]
    #[cfg(feature = "nativetls")]
    CertParse(#[from] native_tls::Error),
    #[error("Unsupported private key type")]
    #[cfg(feature = "__rustls")]
    PrivateKeyNotSupported,
}

#[cfg(feature = "rustls-native-roots")]
pub fn make_client_https() -> HttpsConnector<HttpConnector> {
    HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build()
}
#[cfg(feature = "rustls-webpki-roots")]
pub fn make_client_https() -> HttpsConnector<HttpConnector> {
    HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build()
}
#[cfg(feature = "nativetls")]
pub fn make_client_https() -> HttpsConnector<HttpConnector> {
    HttpsConnector::new()
}

/// Make a `Connector`.
pub async fn make_tls_connector(
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tls_ca: Option<&str>,
    tls_insecure: bool,
) -> Result<Connector, Error> {
    let tls_config = make_client_config(tls_cert, tls_key, tls_ca, tls_insecure).await?;
    #[cfg(feature = "__rustls")]
    let result = Ok(Connector::Rustls(tls_config.into()));
    #[cfg(feature = "nativetls")]
    let result = Ok(Connector::NativeTls(tls_config));
    result
}

pub async fn make_tls_identity(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<TlsIdentity, Error> {
    let identity = make_server_config(cert_path, key_path, client_ca_path).await?;
    Ok(Arc::new(ArcSwap::from_pointee(identity)))
}

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
