use http::uri::{Authority, PathAndQuery, Scheme, Uri};
use std::str::FromStr;
use thiserror::Error;

/// Backend URL parsing errors
#[derive(Debug, Error)]
pub enum BackendUrlError {
    /// Failed to parse the input string as a URL
    #[error("failed to parse backend URL: {0}")]
    UrlParse(#[from] http::uri::InvalidUri),
    /// Missing authority in the URL
    #[error("missing authority in backend URL")]
    MissingAuthority,
    /// Scheme not one of `http` or `https`
    #[error("invalid backend scheme: {0}")]
    InvalidScheme(Scheme),
}

/// Backend URL
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendUrl {
    /// URL Scheme, either `http` or `https`
    pub scheme: Scheme,
    /// URL Authority
    pub authority: Authority,
    /// URL Path and Query
    pub path: PathAndQuery,
}

impl FromStr for BackendUrl {
    type Err = BackendUrlError;

    /// Sanitize the backend URL
    fn from_str(url: &str) -> Result<Self, Self::Err> {
        // We don't try as hard to parse the URL as we do for the server URL
        // because the backend URL is on the server side, so we don't need to
        // be as forgiving.
        let url_parts = Uri::from_str(url)?.into_parts();
        let scheme = url_parts.scheme.unwrap_or(Scheme::HTTP);
        if scheme != Scheme::HTTP && scheme != Scheme::HTTPS {
            return Err(BackendUrlError::InvalidScheme(scheme));
        }
        Ok(Self {
            scheme,
            authority: url_parts
                .authority
                .ok_or(BackendUrlError::MissingAuthority)?,
            path: url_parts
                .path_and_query
                .unwrap_or_else(|| PathAndQuery::from_static("/")),
        })
    }
}

impl std::fmt::Display for BackendUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}{}", self.scheme, self.authority, self.path)
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
