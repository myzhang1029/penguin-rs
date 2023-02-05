mod acceptor;
#[cfg(feature = "nativetls")]
mod native;
#[cfg(feature = "__rustls")]
mod rustls;

#[cfg(feature = "__rustls")]
use ::rustls::ServerConfig;
use arc_swap::ArcSwap;
use hyper::client::HttpConnector;
#[cfg(feature = "__rustls")]
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
#[cfg(feature = "nativetls")]
use hyper_tls::HttpsConnector;
#[cfg(feature = "nativetls")]
use native_tls::TlsConnector;
use std::sync::Arc;
use thiserror::Error;
use tokio_tungstenite::Connector;

pub use acceptor::{TlsAcceptor, TlsStream};

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

/// Make a `Connector` with native TLS.
#[cfg(feature = "nativetls")]
pub async fn make_tls_connector(
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tls_ca: Option<&str>,
    tls_insecure: bool,
) -> Result<Connector, Error> {
    let mut tls_config_builder = TlsConnector::builder();
    tls_config_builder
        .danger_accept_invalid_certs(tls_insecure)
        .danger_accept_invalid_hostnames(tls_insecure);
    if let Some(tls_ca) = tls_ca {
        let ca = tokio::fs::read(tls_ca).await?;
        tls_config_builder.add_root_certificate(native_tls::Certificate::from_pem(&ca)?);
    }
    if let Some(tls_cert) = tls_cert {
        let cert = tokio::fs::read(tls_cert).await?;
        let key = tokio::fs::read(tls_key.unwrap_or(tls_cert)).await?;
        tls_config_builder.identity(native_tls::Identity::from_pkcs8(&cert, &key)?);
    }
    let tls_config = tls_config_builder.build()?;
    Ok(Connector::NativeTls(tls_config))
}

/// Make a `Connector` with rustls.
#[cfg(feature = "__rustls")]
pub async fn make_tls_connector(
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tls_ca: Option<&str>,
    tls_insecure: bool,
) -> Result<Connector, Error> {
    let tls_config = rustls::make_client_config(tls_cert, tls_key, tls_ca, tls_insecure).await?;
    Ok(Connector::Rustls(tls_config.into()))
}

#[cfg(feature = "__rustls")]
pub type TlsIdentity = Arc<ArcSwap<ServerConfig>>;
#[cfg(feature = "nativetls")]
pub type TlsIdentity = Arc<ArcSwap<tokio_native_tls::TlsAcceptor>>;

#[cfg(feature = "__rustls")]
pub async fn make_tls_identity(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<TlsIdentity, Error> {
    let config = rustls::make_server_config(cert_path, key_path, client_ca_path).await?;
    Ok(Arc::new(ArcSwap::from_pointee(config)))
}
#[cfg(feature = "nativetls")]
pub async fn make_tls_identity(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<TlsIdentity, Error> {
    let identity = native::make_tls_identity(cert_path, key_path, client_ca_path).await?;
    let raw_acceptor = native_tls::TlsAcceptor::builder(identity).build()?;
    Ok(Arc::new(ArcSwap::from_pointee(raw_acceptor.into())))
}

pub async fn reload_tls_identity(
    identity: &TlsIdentity,
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<(), Error> {
    #[cfg(feature = "__rustls")]
    let new = rustls::make_server_config(cert_path, key_path, client_ca_path).await?;
    #[cfg(feature = "nativetls")]
    let new = native::make_tls_identity(cert_path, key_path, client_ca_path).await?;
    #[cfg(feature = "nativetls")]
    let new = native_tls::TlsAcceptor::builder(new).build()?.into();
    identity.store(Arc::new(new));
    Ok(())
}
