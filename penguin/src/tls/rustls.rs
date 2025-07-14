//! TLS-related code for `rustls`.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::Error;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    client::danger::{ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::WebPkiClientVerifier,
};
use std::sync::Arc;
use tracing::debug;

/// Type alias for the inner TLS identity type.
pub type TlsIdentityInner = ServerConfig;

/// Type alias for the Hyper HTTPS connector.
#[cfg(feature = "server")]
pub type HyperConnector =
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;

/// Create a `rustls::ServerConfig` from the given certificate
pub async fn make_server_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> Result<TlsIdentityInner, Error> {
    // Load certificate
    // `expect`: we only get `None` if `key_path` and `cert_path` are `None`,
    // which is not the case here.
    let (certs, key) = try_load_certificate(Some(key_path), Some(cert_path))
        .await?
        .expect("`try_load_certificate` returned `None` (this is a bug)");
    make_server_config_from_mem(certs, key, client_ca_path).await
}

/// Create a `rustls::ServerConfig` from a keypair.
/// Both `certs` and `keypair` should be PEM-encoded strings.
///
/// # Errors
/// - Returns [`Error::ReadCert`] if the resulting certificate is unreadable (should not happen).
/// - Returns [`Error::PrivateKeyNotSupported`] if the type of private key is not supported.
#[cfg(feature = "acme")]
pub async fn make_server_config_from_pem(
    certs: String,
    priv_key_pem: String,
    client_ca_path: Option<&str>,
) -> Result<TlsIdentityInner, Error> {
    let certs: std::io::Result<Vec<CertificateDer<'_>>> =
        rustls_pemfile::certs(&mut certs.as_bytes()).collect();
    let key = rustls_pemfile::private_key(&mut priv_key_pem.as_bytes())
        .map_err(Error::ReadCert)?
        .ok_or(Error::PrivateKeyNotSupported)?;
    make_server_config_from_mem(certs.map_err(Error::ReadCert)?, key, client_ca_path).await
}

async fn make_server_config_from_mem(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_ca_path: Option<&str>,
) -> Result<TlsIdentityInner, Error> {
    // Build config
    let config = ServerConfig::builder();
    let mut config = if let Some(client_ca_path) = client_ca_path {
        let store = generate_rustls_rootcertstore(Some(client_ca_path)).await?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(store)).build()?;
        config.with_client_cert_verifier(verifier)
    } else {
        config.with_no_client_auth()
    }
    .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    #[cfg(feature = "rustls-keylog")]
    {
        config.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    Ok(config)
}

/// Create a `rustls::ClientConfig` with possibly a client certificate and a custom CA store
pub async fn make_client_config(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    ca_path: Option<&str>,
    tls_skip_verify: bool,
    tls_alpn: Option<&[&str]>,
) -> Result<ClientConfig, Error> {
    let config = ClientConfig::builder();
    // Whether there is a custom CA store
    let roots = generate_rustls_rootcertstore(ca_path).await?;
    let client_certificate = try_load_certificate(key_path, cert_path).await?;
    // Whether to skip TLS verification and whether there is a client certificate
    let mut config = match (tls_skip_verify, client_certificate) {
        (true, Some((cert_chain, key_der))) => config
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(EmptyVerifier(
                CryptoProvider::get_default()
                    .expect("no process-level CryptoProvider available (this is a bug)"),
            )))
            .with_client_auth_cert(cert_chain, key_der)?,
        (true, None) => config
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(EmptyVerifier(
                CryptoProvider::get_default()
                    .expect("no process-level CryptoProvider available (this is a bug)"),
            )))
            .with_no_client_auth(),
        (false, Some((cert_chain, key_der))) => config
            .with_root_certificates(roots)
            .with_client_auth_cert(cert_chain, key_der)?,
        (false, None) => config.with_root_certificates(roots).with_no_client_auth(),
    };
    if let Some(tls_alpn) = tls_alpn {
        config.alpn_protocols = tls_alpn.iter().map(|&x| x.as_bytes().to_vec()).collect();
    }
    // else leave it empty
    #[cfg(feature = "rustls-keylog")]
    {
        config.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    Ok(config)
}

/// Load system certificates or a custom CA store.
async fn generate_rustls_rootcertstore(
    custom_ca_path: Option<&str>,
) -> Result<RootCertStore, Error> {
    let mut roots = RootCertStore::empty();
    // Whether to use a custom CA store.
    if let Some(ca_path) = custom_ca_path {
        let client_ca = tokio::fs::read(ca_path).await.map_err(Error::ReadCert)?;
        let client_ca: std::io::Result<Vec<CertificateDer<'_>>> =
            rustls_pemfile::certs(&mut client_ca.as_ref()).collect();
        let (_, ignored) =
            roots.add_parsable_certificates(client_ca.map_err(Error::ReadCert)?.into_iter());
        debug!("ignored {ignored} certificates from {ca_path}");
    } else {
        #[cfg(feature = "rustls-native-roots")]
        {
            let certerr = rustls_native_certs::load_native_certs();
            if !certerr.errors.is_empty() {
                tracing::warn!(
                    "Could not access some system certificates: {:?}",
                    certerr.errors
                );
            }
            let (_, ignored) = roots.add_parsable_certificates(certerr.certs);
            debug!("ignored {ignored} certificates from the system root");
        }
        #[cfg(feature = "rustls-webpki-roots")]
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.to_vec());
    }
    Ok(roots)
}

/// Load certificate and key if provided.
async fn try_load_certificate(
    tls_key: Option<&str>,
    tls_cert: Option<&str>,
) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>, Error> {
    if let (Some(key), Some(cert)) = (tls_key, tls_cert) {
        // Load certificate chain
        let certs = tokio::fs::read(cert).await.map_err(Error::ReadCert)?;
        let certs: std::io::Result<Vec<CertificateDer<'_>>> =
            rustls_pemfile::certs(&mut certs.as_ref()).collect();
        // Load private key
        let key = tokio::fs::read(key).await.map_err(Error::ReadCert)?;
        let Some(key) = rustls_pemfile::private_key(&mut key.as_ref()).map_err(Error::ReadCert)?
        else {
            return Err(Error::PrivateKeyNotSupported);
        };
        Ok(Some((certs.map_err(Error::ReadCert)?, key)))
    } else {
        Ok(None)
    }
}

/// Skip TLS verification
#[derive(Debug)]
pub struct EmptyVerifier(&'static Arc<CryptoProvider>);

impl ServerCertVerifier for EmptyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// For backend requests
#[cfg(feature = "server")]
#[allow(clippy::unnecessary_wraps)]
pub fn make_hyper_connector() -> std::io::Result<HyperConnector> {
    #[cfg(feature = "rustls-native-roots")]
    let builder1 = hyper_rustls::HttpsConnectorBuilder::new().with_native_roots()?;
    #[cfg(feature = "rustls-webpki-roots")]
    let builder1 = hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots();
    let conn = builder1
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Ok(conn)
}

#[cfg(test)]
mod tests {
    #[allow(clippy::unwrap_used)]
    use super::*;
    use rcgen::CertificateParams;
    use rcgen::generate_simple_self_signed;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_generate_rustls_rootcertstore() {
        crate::tests::setup_logging();
        // No custom CA store
        let sys_root = generate_rustls_rootcertstore(None).await.unwrap();
        assert!(!sys_root.is_empty());
        // Custom CA store
        let tmpdir = tempdir().unwrap();
        let ca_path = tmpdir.path().join("ca.pem");
        let custom_ca = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        tokio::fs::write(&ca_path, custom_ca.cert.pem())
            .await
            .unwrap();
        let custom_root = generate_rustls_rootcertstore(Some(ca_path.to_str().unwrap()))
            .await
            .unwrap();
        assert_eq!(custom_root.len(), 1);
    }

    #[tokio::test]
    async fn test_try_load_certificate() {
        crate::tests::setup_logging();
        // No certificate and key
        let no_cert = try_load_certificate(None, None).await.unwrap();
        assert!(no_cert.is_none());
        // Certificate and key
        let tmpdir = tempdir().unwrap();
        let key_path = tmpdir.path().join("key.pem");
        let cert_path = tmpdir.path().join("cert.pem");
        let custom_crt = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let crt = custom_crt.cert.pem();
        let crt_key = custom_crt.signing_key.serialize_pem();
        tokio::fs::write(&cert_path, crt).await.unwrap();
        tokio::fs::write(&key_path, crt_key).await.unwrap();
        let loaded_cert = try_load_certificate(
            Some(key_path.to_str().unwrap()),
            Some(cert_path.to_str().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        let (loaded_cert, loaded_key) = loaded_cert;
        assert_eq!(loaded_cert.len(), 1);
        assert_eq!(
            loaded_key.secret_der(),
            custom_crt.signing_key.serialize_der(),
        );
        let cert_params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
        let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let custom_crt = cert_params.self_signed(&keypair).unwrap();
        let crt = custom_crt.pem();
        let crt_key = keypair.serialize_pem();
        tokio::fs::write(&cert_path, crt).await.unwrap();
        tokio::fs::write(&key_path, crt_key).await.unwrap();
        let loaded_cert = try_load_certificate(
            Some(key_path.to_str().unwrap()),
            Some(cert_path.to_str().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        let (loaded_cert, loaded_key) = loaded_cert;
        assert_eq!(loaded_cert.len(), 1);
        assert_eq!(loaded_key.secret_der(), keypair.serialize_der());
    }

    #[tokio::test]
    async fn test_server_config() {
        crate::tests::setup_logging();
        let tmpdir = tempdir().unwrap();
        let key_path = tmpdir.path().join("key.pem");
        let cert_path = tmpdir.path().join("cert.pem");
        let custom_crt = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let crt = custom_crt.cert.pem();
        let crt_key = custom_crt.signing_key.serialize_pem();
        tokio::fs::write(&cert_path, crt).await.unwrap();
        tokio::fs::write(&key_path, crt_key).await.unwrap();
        let config = make_server_config(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[tokio::test]
    async fn test_client_config() {
        crate::tests::setup_logging();
        let tmpdir = tempdir().unwrap();
        let ca_path = tmpdir.path().join("ca.pem");
        let custom_ca = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        tokio::fs::write(&ca_path, custom_ca.cert.pem())
            .await
            .unwrap();
        let config = make_client_config(
            None,
            None,
            Some(ca_path.to_str().unwrap()),
            true,
            Some(&crate::tls::TLS_ALPN),
        )
        .await
        .unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[tokio::test]
    #[cfg(feature = "acme")]
    async fn test_make_server_config_from_rcgen_pem() {
        crate::tests::setup_logging();
        let cert_params = CertificateParams::new(vec!["example.com".into()]).unwrap();
        let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let custom_crt = cert_params.self_signed(&keypair).unwrap();
        let crt = custom_crt.pem();

        let result = make_server_config_from_pem(crt, keypair.serialize_pem(), None).await;

        assert!(result.is_ok());
    }
}
