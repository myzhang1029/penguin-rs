//! Server backend URL utilities
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
use super::url_common::convert_idn_with_default_scheme;
use http::uri::{Authority, PathAndQuery, Scheme, Uri};
use std::str::FromStr;

/// Backend URL parsing errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to parse the input string as a URL
    #[error("failed to parse backend URL: {0}")]
    UrlParse(#[from] http::uri::InvalidUri),
    /// Missing authority in the URL
    #[error("missing authority in backend URL")]
    MissingAuthority,
    /// Scheme not one of `http` or `https`
    #[error("invalid backend scheme: {0}")]
    InvalidScheme(Scheme),
    /// IDN conversion error
    #[error("invalid IDN in backend URL: {0}")]
    IdnConversion(#[from] idna::Errors),
}

/// Backend URL
#[derive(Debug, derive_more::Display, Clone, PartialEq, Eq)]
#[display("{scheme}://{authority}{path}")]
pub struct BackendUrl {
    /// URL Scheme, either `http` or `https`
    pub scheme: Scheme,
    /// URL Authority
    pub authority: Authority,
    /// URL Path and Query
    pub path: PathAndQuery,
}

impl FromStr for BackendUrl {
    type Err = Error;

    /// Sanitize the backend URL
    fn from_str(url: &str) -> Result<Self, Self::Err> {
        let url = convert_idn_with_default_scheme(url, "http")?;
        let url_parts = Uri::from_str(&url)?.into_parts();
        let scheme = url_parts.scheme.expect(
            "Scheme should be present after `convert_idn_with_default_scheme` (this is a bug)",
        );
        if scheme != Scheme::HTTP && scheme != Scheme::HTTPS {
            return Err(Error::InvalidScheme(scheme));
        }
        Ok(Self {
            scheme,
            authority: url_parts.authority.ok_or(Error::MissingAuthority)?,
            path: url_parts
                .path_and_query
                .unwrap_or_else(|| PathAndQuery::from_static("/")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::BackendUrl;
    use http::uri::{Authority, PathAndQuery, Scheme};
    use std::str::FromStr;

    #[test]
    fn test_backendurl_fromstr() {
        crate::tests::setup_logging();
        assert_eq!(
            BackendUrl::from_str("https://example.com")
                .unwrap()
                .to_string(),
            "https://example.com/"
        );
        assert_eq!(
            BackendUrl::from_str("http://example.com")
                .unwrap()
                .to_string(),
            "http://example.com/"
        );
        assert_eq!(
            BackendUrl::from_str("https://example.com/foo").unwrap(),
            BackendUrl {
                scheme: Scheme::HTTPS,
                authority: Authority::from_static("example.com"),
                path: PathAndQuery::from_static("/foo"),
            }
        );
        assert_eq!(
            BackendUrl::from_str("http://example.com/foo?bar")
                .unwrap()
                .to_string(),
            "http://example.com/foo?bar"
        );
        BackendUrl::from_str("ftp://example.com").unwrap_err();
        BackendUrl::from_str("http://").unwrap_err();
    }
}
