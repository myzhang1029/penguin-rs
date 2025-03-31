//! Common TLS functionalities.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

#[cfg(feature = "nativetls")]
mod native;
#[cfg(feature = "__rustls")]
mod rustls;

#[cfg(all(feature = "__rustls", feature = "acme"))]
use self::rustls::make_server_config_from_rcgen_pem;
#[cfg(feature = "__rustls")]
use self::rustls::{make_client_config, make_server_config};
use arc_swap::ArcSwap;
#[cfg(all(feature = "nativetls", feature = "acme"))]
use native::make_server_config_from_rcgen_pem;
#[cfg(feature = "nativetls")]
use native::{make_client_config, make_server_config};
use std::sync::Arc;
use thiserror::Error;
use tokio_tungstenite::Connector;

#[allow(clippy::module_name_repetitions)]
#[cfg(feature = "__rustls")]
pub use self::rustls::TlsIdentityInner;
#[cfg(feature = "nativetls")]
pub use native::TlsIdentityInner;

/// A hot-swappable container for a TLS key and certificate.
#[allow(clippy::module_name_repetitions)]
pub type TlsIdentity = Arc<ArcSwap<TlsIdentityInner>>;

/// Error type for TLS configuration
#[derive(Error, Debug)]
pub enum Error {
    #[error("Error reading certificate, key, or CA: {0}")]
    ReadCert(#[from] std::io::Error),
    #[error("Empty client certificate store")]
    #[cfg(feature = "__rustls")]
    EmptyClientCertStore,
    #[error("Rustls error: {0}")]
    #[cfg(feature = "__rustls")]
    Rustls(#[from] ::rustls::Error),
    #[error("Verifier error: {0}")]
    #[cfg(feature = "__rustls")]
    Verifier(#[from] ::rustls::client::VerifierBuilderError),
    #[error("Failed to parse certificates: {0}")]
    #[cfg(feature = "nativetls")]
    CertParse(#[from] tokio_native_tls::native_tls::Error),
    #[error("Unsupported private key type")]
    #[cfg(feature = "__rustls")]
    PrivateKeyNotSupported,
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

#[cfg(feature = "acme")]
pub async fn make_tls_identity_from_rcgen_pem(
    certs: String,
    keypair: rcgen::KeyPair,
    client_ca_path: Option<&str>,
) -> Result<TlsIdentity, Error> {
    let identity = make_server_config_from_rcgen_pem(certs, keypair, client_ca_path).await?;
    Ok(Arc::new(ArcSwap::from_pointee(identity)))
}

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

#[cfg(feature = "acme")]
pub async fn reload_tls_identity_from_rcgen_pem(
    identity: &TlsIdentity,
    certs: String,
    keypair: rcgen::KeyPair,
    client_ca_path: Option<&str>,
) -> Result<(), Error> {
    let new = make_server_config_from_rcgen_pem(certs, keypair, client_ca_path).await?;
    identity.store(Arc::new(new));
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use rcgen::CertificateParams;
    use tempfile::tempdir;

    #[tokio::test]
    #[cfg(not(all(any(target_os = "macos", target_os = "windows"), feature = "nativetls")))]
    async fn test_server_config_reload() {
        let tmpdir = tempdir().unwrap();
        let key_path = tmpdir.path().join("key.pem");
        let cert_path = tmpdir.path().join("cert.pem");
        let custom_crt = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let crt = custom_crt.cert.pem();
        let crt_key = custom_crt.key_pair.serialize_pem();
        tokio::fs::write(&cert_path, crt).await.unwrap();
        tokio::fs::write(&key_path, crt_key).await.unwrap();
        let identity = make_tls_identity(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            None,
        )
        .await
        .unwrap();
        let old_identity = identity.load().clone();
        let custom_crt = generate_simple_self_signed(vec!["2.example.com".into()]).unwrap();
        let crt = custom_crt.cert.pem();
        let crt_key = custom_crt.key_pair.serialize_pem();
        tokio::fs::write(&cert_path, crt).await.unwrap();
        tokio::fs::write(&key_path, crt_key).await.unwrap();
        reload_tls_identity(
            &identity,
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            None,
        )
        .await
        .unwrap();
        let new_identity = identity.load().clone();
        // Better comparison?
        assert_ne!(format!("{old_identity:?}"), format!("{new_identity:?}"));
    }

    #[tokio::test]
    #[cfg(feature = "acme")]
    #[cfg(not(all(any(target_os = "macos", target_os = "windows"), feature = "nativetls")))]
    async fn test_server_config_reload_from_rcgen_pem() {
        let cert_params = CertificateParams::new(vec!["example.com".into()]).unwrap();
        let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let custom_crt = cert_params.self_signed(&keypair).unwrap();
        let crt = custom_crt.pem();
        let identity = make_tls_identity_from_rcgen_pem(crt, keypair, None)
            .await
            .unwrap();
        let old_identity = identity.load().clone();
        let cert_params = CertificateParams::new(vec!["2.example.com".into()]).unwrap();
        let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let custom_crt = cert_params.self_signed(&keypair).unwrap();
        let crt = custom_crt.pem();
        reload_tls_identity_from_rcgen_pem(&identity, crt, keypair, None)
            .await
            .unwrap();
        let new_identity = identity.load().clone();
        // Better comparison?
        assert_ne!(format!("{old_identity:?}"), format!("{new_identity:?}"));
    }
}
