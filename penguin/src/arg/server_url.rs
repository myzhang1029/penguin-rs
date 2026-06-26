//! Specialized URL type for the server address.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::url_common::convert_idn_with_default_scheme;
use http::{
    Uri,
    uri::{Authority, PathAndQuery, Scheme},
};
use std::str::FromStr;

/// Server URL parsing errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to parse the input string as a URL
    #[error("failed to parse server URL: {0}")]
    UrlParse(#[from] http::uri::InvalidUri),
    /// Scheme not one of `ws`, `wss`, `http`, or `https`
    #[error("incorrect scheme in server URL: {0}")]
    IncorrectScheme(Scheme),
    /// Missing host
    #[error("missing host in server URL")]
    MissingHost,
    /// Failed to build an URL
    #[error("cannot build server URL: {0}")]
    BuildUrl(#[from] http::Error),
    /// IDN conversion error
    #[error("invalid IDN in server URL: {0}")]
    IdnConversion(#[from] idna::Errors),
}

/// Server URL
#[derive(Debug, derive_more::Display, Default, derive_more::Deref, Clone, PartialEq, Eq, Hash)]
pub struct ServerUrl(pub Uri);

impl FromStr for ServerUrl {
    type Err = Error;

    /// Sanitize the URL for WebSocket
    fn from_str(url: &str) -> Result<Self, Self::Err> {
        let url = convert_idn_with_default_scheme(url, "ws")?;
        let url_parts = Uri::from_str(&url)?.into_parts();
        let old_scheme = url_parts.scheme.expect(
            "Scheme should be present after `convert_idn_with_default_scheme` (this is a bug)",
        );
        let (new_scheme, default_port) = match old_scheme.as_ref() {
            "http" | "ws" => Ok(("ws", 80)),
            "https" | "wss" => Ok(("wss", 443)),
            _ => Err(Error::IncorrectScheme(old_scheme)),
        }?;
        // If the URL has no port, we set it here to simplify the logic later
        let authority = url_parts.authority.ok_or(Error::MissingHost)?;
        let authority = if authority.port_u16().is_none() {
            // If no port is specified, we set the default port for the scheme
            // A bare IPv6 address without brackets will not be accepted by `Uri::from_str`
            // anyway, so we can safely concatenate the port to the original authority
            Authority::from_str(&format!("{authority}:{default_port}"))?
        } else {
            authority
        };
        // Convert to a `Uri`.
        let url = Uri::builder()
            .scheme(new_scheme)
            .authority(authority)
            .path_and_query(
                url_parts
                    .path_and_query
                    .unwrap_or_else(|| PathAndQuery::from_static("/")),
            )
            .build()?;
        Ok(Self(url))
    }
}

#[cfg(test)]
mod tests {
    use super::ServerUrl;
    use std::str::FromStr;

    #[test]
    fn test_serverurl_fromstr() {
        crate::tests::setup_logging();
        assert_eq!(
            ServerUrl::from_str("example.com").unwrap().to_string(),
            "ws://example.com:80/"
        );
        assert_eq!(
            ServerUrl::from_str("wss://example.com")
                .unwrap()
                .to_string(),
            "wss://example.com:443/"
        );
        assert_eq!(
            ServerUrl::from_str("ws://example.com").unwrap().to_string(),
            "ws://example.com:80/"
        );
        assert_eq!(
            ServerUrl::from_str("https://example.com")
                .unwrap()
                .to_string(),
            "wss://example.com:443/"
        );
        assert_eq!(
            ServerUrl::from_str("http://example.com")
                .unwrap()
                .to_string(),
            "ws://example.com:80/"
        );
        assert_eq!(
            ServerUrl::from_str("https://example.com:8080/foo")
                .unwrap()
                .to_string(),
            "wss://example.com:8080/foo"
        );
        ServerUrl::from_str("ftp://example.com").unwrap_err();
        ServerUrl::from_str("http://").unwrap_err();
        ServerUrl::from_str("://example.com").unwrap_err();
    }
}
