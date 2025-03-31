//! TLS-related code for `native-tls`.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::Error;
use tokio_native_tls::native_tls::{Certificate, Identity, TlsAcceptor, TlsConnector};

/// Type alias for the inner TLS identity type.
pub type TlsIdentityInner = tokio_native_tls::TlsAcceptor;

pub async fn make_server_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<TlsIdentityInner, Error> {
    let identity = read_key_cert(key_path, cert_path).await?;
    make_server_config_from_mem(identity, client_ca_path)
}

#[cfg(feature = "acme")]
#[allow(clippy::unused_async)]
pub async fn make_server_config_from_rcgen_pem(
    certs: String,
    keypair: rcgen::KeyPair,
    client_ca_path: Option<&str>,
) -> Result<TlsIdentityInner, Error> {
    let identity = Identity::from_pkcs8(certs.as_bytes(), keypair.serialize_pem().as_bytes())?;
    make_server_config_from_mem(identity, client_ca_path)
}

fn make_server_config_from_mem(
    identity: Identity,
    _client_ca_path: Option<&str>,
) -> Result<TlsIdentityInner, Error> {
    // TODO: support client CA (sfackler/rust-native-tls#161)
    let raw_acceptor = TlsAcceptor::builder(identity).build()?;
    Ok(raw_acceptor.into())
}

pub async fn make_client_config(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    ca_path: Option<&str>,
    tls_skip_verify: bool,
) -> Result<TlsConnector, Error> {
    let mut tls_config_builder = TlsConnector::builder();
    tls_config_builder
        .danger_accept_invalid_certs(tls_skip_verify)
        .danger_accept_invalid_hostnames(tls_skip_verify);
    if let Some(ca_path) = ca_path {
        let ca = tokio::fs::read(ca_path).await?;
        tls_config_builder.add_root_certificate(Certificate::from_pem(&ca)?);
    }
    if let Some(cert_path) = cert_path {
        let identity = read_key_cert(key_path.unwrap_or(cert_path), cert_path).await?;
        tls_config_builder.identity(identity);
    }
    Ok(tls_config_builder.build()?)
}

async fn read_key_cert(key_path: &str, cert_path: &str) -> Result<Identity, Error> {
    let key = tokio::fs::read(key_path).await?;
    let cert = tokio::fs::read(cert_path).await?;
    Ok(Identity::from_pkcs8(&cert, &key)?)
}

#[cfg(test)]
mod test {
    // `native_tls` on macOS and Windows doesn't support reading Ed25519 nor ECDSA-based certificates.
    #[tokio::test]
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    async fn test_read_key_cert() {
        use super::*;
        use rcgen::CertificateParams;
        use tempfile::tempdir;
        let tmpdir = tempdir().unwrap();
        let key_path = tmpdir.path().join("key.pem");
        let cert_path = tmpdir.path().join("cert.pem");
        let cert_params = CertificateParams::new(vec!["example.com".into()]).unwrap();
        let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let custom_crt = cert_params.self_signed(&keypair).unwrap();
        let crt = custom_crt.pem();
        let crt_key = keypair.serialize_pem();
        tokio::fs::write(&cert_path, crt).await.unwrap();
        tokio::fs::write(&key_path, crt_key).await.unwrap();
        read_key_cert(key_path.to_str().unwrap(), cert_path.to_str().unwrap())
            .await
            .unwrap();
    }
}
