//! WebSocket connection.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::arg::ClientArgs;
use crate::proto_version::PROTOCOL_VERSION;
use http::header::{HeaderName, HeaderValue};
use log::debug;
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
use tungstenite::{client::IntoClientRequest, handshake::client::Request};
use url::Url;

/// Error type for WebSocket connection.
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to read CA store")]
    CaStoreIO(#[from] std::io::Error),
    #[error("failed to parse CA store")]
    CaStoreParse(#[from] webpki::Error),
    #[error("rustls error")]
    Rustls(#[from] rustls::Error),
    #[error("tungstenite error")]
    Tungstenite(#[from] tungstenite::error::Error),
    #[error("failed to parse URL")]
    UrlParse(#[from] url::ParseError),
    #[error("incorrect scheme: {0}")]
    IncorrectScheme(String),
    #[error("invalid header value or hostname")]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),
    #[error("invalid header name")]
    InvalidHeaderName(#[from] http::header::InvalidHeaderName),
    #[error("invalid header: {0}")]
    InvalidHeaderFormat(String),
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

/// Load system certificates or a custom CA store.
fn generate_rustls_rootcertstore(custom_ca: &Option<String>) -> Result<RootCertStore, Error> {
    let mut roots = RootCertStore::empty();
    // Whether to use a custom CA store.
    if let Some(ca) = custom_ca {
        let mut reader = std::io::BufReader::new(std::fs::File::open(ca)?);
        for cert in rustls_pemfile::certs(&mut reader)? {
            roots.add(&rustls::Certificate(cert))?;
        }
    } else {
        // TODO: support for webpki_roots
        for cert in rustls_native_certs::load_native_certs()? {
            roots.add(&rustls::Certificate(cert.0))?;
        }
    };
    Ok(roots)
}

/// Load client certificate if provided.
fn try_load_client_certificate(
    tls_key: &Option<String>,
    tls_cert: &Option<String>,
) -> Result<Option<(Vec<rustls::Certificate>, rustls::PrivateKey)>, Error> {
    if let (Some(key), Some(cert)) = (tls_key, tls_cert) {
        let mut reader = std::io::BufReader::new(std::fs::File::open(cert)?);
        let certs = rustls_pemfile::certs(&mut reader)?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        let mut reader = std::io::BufReader::new(std::fs::File::open(key)?);
        // TODO: PKCS?
        let keys = rustls_pemfile::rsa_private_keys(&mut reader)?;
        Ok(Some((certs, rustls::PrivateKey(keys[0].clone()))))
    } else {
        Ok(None)
    }
}

/// Sanitize the URL for WebSocket.
fn sanitize_url(url: &str) -> Result<Url, Error> {
    // Provide a default scheme if none is provided.
    let url = Url::parse(url).or_else(|e| {
        if e == url::ParseError::RelativeUrlWithoutBase {
            Url::parse(&format!("{}{}", "http://", url))
        } else {
            Err(e)
        }
    })?;
    // Convert to a `Url`.
    let url = match url.scheme() {
        "wss" | "ws" => url,
        "https" => {
            let mut url = url;
            url.set_scheme("wss").unwrap();
            url
        }
        "http" => {
            let mut url = url;
            url.set_scheme("ws").unwrap();
            url
        }
        scheme => {
            return Err(Error::IncorrectScheme(scheme.to_string()));
        }
    };
    Ok(url)
}

pub async fn handshake(
    args: &ClientArgs,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Error> {
    let url = sanitize_url(&args.server)?;
    // We already sanitized https URLs to wss
    let is_tls = url.scheme() == "wss";

    // Use a request to allow additional headers
    let mut req: Request = url.into_client_request()?;
    let req_headers = req.headers_mut();
    // Add protocol version
    req_headers.insert(
        "sec-websocket-protocol",
        HeaderValue::from_str(PROTOCOL_VERSION)?,
    );
    // Add PSK
    if let Some(ws_psk) = args.ws_psk.as_ref() {
        req_headers.insert("x-penguin-psk", HeaderValue::from_str(ws_psk)?);
    }
    // Add potentially custom hostname
    if let Some(hostname) = args.hostname.as_ref() {
        req_headers.insert("host", HeaderValue::from_str(hostname)?);
    }
    // Now add custom headers
    for header in &args.header {
        let (name, value) = header
            .split_once(':')
            .ok_or(Error::InvalidHeaderFormat(header.to_string()))?;
        req_headers.insert(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_str(value.trim())?,
        );
    }

    let connector = if is_tls {
        let config_builder = ClientConfig::builder().with_safe_defaults();
        // Whether there is a custom CA store
        let roots = generate_rustls_rootcertstore(&args.tls_ca)?;
        let client_certificate = try_load_client_certificate(&args.tls_key, &args.tls_cert)?;
        // Whether to skip TLS verification and whether there is a client certificate
        let config = match (args.tls_skip_verify, client_certificate) {
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

    #[test]
    fn test_sanitize_url() {
        assert_eq!(
            sanitize_url("wss://example.com").unwrap().as_str(),
            "wss://example.com/"
        );
        assert_eq!(
            sanitize_url("ws://example.com").unwrap().as_str(),
            "ws://example.com/"
        );
        assert_eq!(
            sanitize_url("https://example.com").unwrap().as_str(),
            "wss://example.com/"
        );
        assert_eq!(
            sanitize_url("http://example.com").unwrap().as_str(),
            "ws://example.com/"
        );
        assert!(sanitize_url("ftp://example.com").is_err());
    }
}
