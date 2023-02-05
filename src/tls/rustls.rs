//! TLS-related code for `rustls`.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::Error;
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier, ServerName},
    server::AllowAnyAuthenticatedClient,
    Certificate, ClientConfig, RootCertStore, ServerConfig,
};
use rustls_pemfile::Item;
use std::sync::Arc;

/// Type alias for the inner TLS identity type.
pub type TlsIdentityInner = ServerConfig;

/// Skip TLS verification
pub struct EmptyVerifier;

impl ServerCertVerifier for EmptyVerifier {
    fn verify_server_cert(
        &self,
        _: &Certificate,
        _: &[Certificate],
        _: &ServerName,
        _: &mut dyn Iterator<Item = &[u8]>,
        _: &[u8],
        _: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

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
    // Build config
    let config = ServerConfig::builder().with_safe_defaults();
    let mut config = if let Some(client_ca_path) = client_ca_path {
        let store = load_ca_store(client_ca_path).await?;
        config.with_client_cert_verifier(AllowAnyAuthenticatedClient::new(store))
    } else {
        config.with_no_client_auth()
    }
    .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

pub async fn make_client_config(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    ca_path: Option<&str>,
    tls_skip_verify: bool,
) -> Result<ClientConfig, Error> {
    let config = ClientConfig::builder().with_safe_defaults();
    // Whether there is a custom CA store
    let roots = generate_rustls_rootcertstore(ca_path).await?;
    let client_certificate = try_load_certificate(key_path, cert_path).await?;
    // Whether to skip TLS verification and whether there is a client certificate
    let mut config = match (tls_skip_verify, client_certificate) {
        (true, Some((cert_chain, key_der))) => config
            .with_custom_certificate_verifier(Arc::new(EmptyVerifier {}))
            .with_single_cert(cert_chain, key_der)?,
        (true, None) => config
            .with_custom_certificate_verifier(Arc::new(EmptyVerifier {}))
            .with_no_client_auth(),
        (false, Some((cert_chain, key_der))) => config
            .with_root_certificates(roots)
            .with_single_cert(cert_chain, key_der)?,
        (false, None) => config.with_root_certificates(roots).with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Load system certificates
#[cfg(feature = "rustls-native-roots")]
fn get_system_certs() -> Result<RootCertStore, Error> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        roots.add(&Certificate(cert.0))?;
    }
    Ok(roots)
}
#[cfg(feature = "rustls-webpki-roots")]
#[allow(clippy::unnecessary_wraps)]
fn get_system_certs() -> Result<RootCertStore, Error> {
    let mut roots = RootCertStore::empty();
    roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    Ok(roots)
}

/// Load a CA store from a file.
async fn load_ca_store(ca_path: &str) -> Result<RootCertStore, Error> {
    let mut store = RootCertStore::empty();
    let client_ca = tokio::fs::read(ca_path).await?;
    let client_ca = rustls_pemfile::certs(&mut client_ca.as_ref())?;
    let (new, _) = store.add_parsable_certificates(&client_ca);
    if new == 0 {
        Err(Error::EmptyClientCertStore)
    } else {
        Ok(store)
    }
}

/// Load system certificates or a custom CA store.
async fn generate_rustls_rootcertstore(
    custom_ca_path: Option<&str>,
) -> Result<RootCertStore, Error> {
    // Whether to use a custom CA store.
    if let Some(custom_ca_path) = custom_ca_path {
        load_ca_store(custom_ca_path).await
    } else {
        get_system_certs()
    }
}

/// Load certificate and key if provided.
async fn try_load_certificate(
    tls_key: Option<&str>,
    tls_cert: Option<&str>,
) -> Result<Option<(Vec<Certificate>, rustls::PrivateKey)>, Error> {
    if let (Some(key), Some(cert)) = (tls_key, tls_cert) {
        // Load certificate chain
        let certs = tokio::fs::read(cert).await?;
        let certs = rustls_pemfile::certs(&mut certs.as_ref())?;
        let certs = certs.into_iter().map(Certificate).collect();
        // Load private key
        let key = tokio::fs::read(key).await?;
        let Some(Item::RSAKey(key) | Item::PKCS8Key(key) | Item::ECKey(key)) = rustls_pemfile::read_one(&mut key.as_ref())? else {
            return Err(Error::PrivateKeyNotSupported)
        };
        let key = rustls::PrivateKey(key);
        Ok(Some((certs, key)))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_generate_rustls_rootcertstore() {
        // No custom CA store
        let sys_root = generate_rustls_rootcertstore(None).await.unwrap();
        assert!(!sys_root.is_empty());
        // Custom CA store
        let tmpdir = tempdir().unwrap();
        let ca_path = tmpdir.path().join("ca.pem");
        let custom_ca = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        tokio::fs::write(&ca_path, custom_ca.serialize_pem().unwrap())
            .await
            .unwrap();
        let custom_root = generate_rustls_rootcertstore(Some(ca_path.to_str().unwrap()))
            .await
            .unwrap();
        assert_eq!(custom_root.len(), 1);
    }

    #[tokio::test]
    async fn test_try_load_certificate() {
        // No certificate and key
        let no_cert = try_load_certificate(None, None).await.unwrap();
        assert!(no_cert.is_none());
        // Certificate and key
        let tmpdir = tempdir().unwrap();
        let key_path = tmpdir.path().join("key.pem");
        let cert_path = tmpdir.path().join("cert.pem");
        let custom_crt = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let crt = custom_crt.serialize_pem().unwrap();
        let crt_key = custom_crt.serialize_private_key_pem();
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
        assert_eq!(loaded_key.0, custom_crt.serialize_private_key_der());
        let mut cert_params = rcgen::CertificateParams::new(vec!["example.com".into()]);
        cert_params.alg = &rcgen::PKCS_ED25519;
        let custom_crt = rcgen::Certificate::from_params(cert_params).unwrap();
        let crt = custom_crt.serialize_pem().unwrap();
        let crt_key = custom_crt.serialize_private_key_pem();
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
        assert_eq!(loaded_key.0, custom_crt.serialize_private_key_der());
    }

    #[tokio::test]
    async fn test_server_config() {
        let tmpdir = tempdir().unwrap();
        let key_path = tmpdir.path().join("key.pem");
        let cert_path = tmpdir.path().join("cert.pem");
        let custom_crt = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let crt = custom_crt.serialize_pem().unwrap();
        let crt_key = custom_crt.serialize_private_key_pem();
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
        let tmpdir = tempdir().unwrap();
        let ca_path = tmpdir.path().join("ca.pem");
        let custom_ca = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        tokio::fs::write(&ca_path, custom_ca.serialize_pem().unwrap())
            .await
            .unwrap();
        let config = make_client_config(None, None, Some(ca_path.to_str().unwrap()), true)
            .await
            .unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
}
