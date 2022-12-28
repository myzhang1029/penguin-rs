//! WebSocket connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::proto_version::PROTOCOL_VERSION;
use http::header::HeaderValue;
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    ClientConfig, RootCertStore,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, warn};
use tungstenite::{client::IntoClientRequest, handshake::client::Request};

/// Error type for WebSocket connection.
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to read CA store: {0}")]
    CaStoreIO(#[from] std::io::Error),
    #[error("failed to parse CA store: {0}")]
    CaStoreParse(#[from] webpki::Error),
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("tungstenite error: {0}")]
    Tungstenite(#[from] tungstenite::error::Error),
}

pub struct TlsEmptyVerifier {}

impl ServerCertVerifier for TlsEmptyVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::Certificate,
        _: &[rustls::Certificate],
        _: &rustls::client::ServerName,
        _: &mut dyn Iterator<Item = &[u8]>,
        _: &[u8],
        _: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

/// Load system certificates
#[cfg(feature = "rustls-native-roots")]
fn get_system_certs() -> Result<RootCertStore, Error> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        roots.add(&rustls::Certificate(cert.0))?;
    }
    Ok(roots)
}
#[cfg(all(feature = "rustls-native-roots", not(feature = "rustls-native-roots")))]
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

/// Load system certificates or a custom CA store.
fn generate_rustls_rootcertstore(custom_ca: Option<&str>) -> Result<RootCertStore, Error> {
    // Whether to use a custom CA store.
    if let Some(ca) = custom_ca {
        let mut roots = RootCertStore::empty();
        let mut reader = std::io::BufReader::new(std::fs::File::open(ca)?);
        for cert in rustls_pemfile::certs(&mut reader)? {
            roots.add(&rustls::Certificate(cert))?;
        }
        Ok(roots)
    } else {
        get_system_certs()
    }
}

/// Load client certificate if provided.
fn try_load_client_certificate(
    tls_key: Option<&str>,
    tls_cert: Option<&str>,
) -> Result<Option<(Vec<rustls::Certificate>, rustls::PrivateKey)>, Error> {
    if let (Some(key), Some(cert)) = (tls_key, tls_cert) {
        let mut reader = std::io::BufReader::new(std::fs::File::open(cert)?);
        let certs = rustls_pemfile::certs(&mut reader)?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        let mut reader = std::io::BufReader::new(std::fs::File::open(key)?);
        let keys = rustls_pemfile::rsa_private_keys(&mut reader)?;
        Ok(Some((certs, rustls::PrivateKey(keys[0].clone()))))
    } else {
        Ok(None)
    }
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(level = "debug", skip(extra_headers))]
pub async fn handshake(
    url: crate::arg::ServerUrl,
    ws_psk: Option<HeaderValue>,
    override_hostname: Option<HeaderValue>,
    extra_headers: Vec<crate::arg::Header>,
    tls_ca: Option<&str>,
    tls_key: Option<&str>,
    tls_cert: Option<&str>,
    tls_insecure: bool,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Error> {
    // We already sanitized https URLs to wss
    let is_tls = url.scheme().unwrap().as_str() == "wss";

    // Use a request to allow additional headers
    let mut req: Request = url.0.into_client_request()?;
    let req_headers = req.headers_mut();
    // Add protocol version
    req_headers.insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(PROTOCOL_VERSION),
    );
    // Add PSK
    if let Some(ws_psk) = ws_psk {
        req_headers.insert("x-penguin-psk", ws_psk);
    }
    // Add potentially custom hostname
    if let Some(hostname) = override_hostname {
        req_headers.insert("host", hostname);
    }
    // Now add custom headers
    for header in extra_headers {
        req_headers.insert(header.name, header.value);
    }

    let connector = if is_tls {
        let config_builder = ClientConfig::builder().with_safe_defaults();
        // Whether there is a custom CA store
        let roots = generate_rustls_rootcertstore(tls_ca)?;
        let client_certificate = try_load_client_certificate(tls_key, tls_cert)?;
        // Whether to skip TLS verification and whether there is a client certificate
        let config = match (tls_insecure, client_certificate) {
            (true, Some((cert_chain, key_der))) => config_builder
                .with_custom_certificate_verifier(Arc::new(TlsEmptyVerifier {}))
                .with_single_cert(cert_chain, key_der)?,
            (true, None) => config_builder
                .with_custom_certificate_verifier(Arc::new(TlsEmptyVerifier {}))
                .with_no_client_auth(),
            (false, Some((cert_chain, key_der))) => config_builder
                .with_root_certificates(roots)
                .with_single_cert(cert_chain, key_der)?,
            (false, None) => config_builder
                .with_root_certificates(roots)
                .with_no_client_auth(),
        };
        Connector::Rustls(config.into())
    } else {
        // No TLS
        warn!("Using insecure WebSocket connection");
        Connector::Plain
    };
    let (ws_stream, _response) = connect_async_tls_with_config(req, None, Some(connector)).await?;
    // We don't need to check the response now...
    debug!("WebSocket handshake succeeded");
    Ok(ws_stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use tempfile::tempdir;

    #[test]
    fn test_generate_rustls_rootcertstore() {
        // No custom CA store
        let sys_root = generate_rustls_rootcertstore(None);
        assert!(sys_root.is_ok());
        assert!(!sys_root.unwrap().is_empty());
        // Custom CA store
        let tmpdir = tempdir().unwrap();
        let ca_path = tmpdir.path().join("ca.pem");
        let custom_ca = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        std::fs::write(&ca_path, custom_ca.serialize_pem().unwrap()).unwrap();
        let custom_root = generate_rustls_rootcertstore(Some(ca_path.to_str().unwrap()));
        assert!(custom_root.is_ok());
        assert_eq!(custom_root.unwrap().len(), 1);
    }
}
