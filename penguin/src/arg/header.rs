//! HTTP Header specification on the command line
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use http::header::{HeaderName, HeaderValue};
use std::str::FromStr;

/// HTTP Header parsing errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Header value not valid/acceptable
    #[error("invalid header value or hostname: {0}")]
    Value(#[from] http::header::InvalidHeaderValue),
    /// Header name not valid/acceptable
    #[error("invalid header name: {0}")]
    Name(#[from] http::header::InvalidHeaderName),
    /// Header missing delimiter `:`
    #[error("missing delimiter colon in the specified header `{0}`")]
    MissingDelimiter(String),
}

/// HTTP Header
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Header {
    /// Header name
    pub name: HeaderName,
    /// Header value
    pub value: HeaderValue,
}

impl FromStr for Header {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, value) = s
            .split_once(':')
            .ok_or_else(|| Self::Err::MissingDelimiter(s.to_string()))?;
        let name = HeaderName::from_str(name)?;
        let value = HeaderValue::from_str(value.trim())?;
        Ok(Self { name, value })
    }
}

#[cfg(test)]
mod tests {
    use super::Header;
    use std::str::FromStr;

    #[test]
    fn test_header_parser() {
        crate::tests::setup_logging();
        let header = Header::from_str("X-Test: test").unwrap();
        assert_eq!(header.name.as_str().to_lowercase(), "X-Test".to_lowercase());
        header.value.to_str().unwrap();
        assert_eq!(header.value.to_str().unwrap(), "test");
        Header::from_str("X-Test").unwrap_err();
        // HTTP forbids empty header values, but we allow it
        //assert!(Header::from_str("X-Test:").is_err());
        Header::from_str(": test").unwrap_err();
        let header = Header::from_str("X-Test: test: test").unwrap();
        assert_eq!(header.name.as_str().to_lowercase(), "X-Test".to_lowercase());
        header.value.to_str().unwrap();
        assert_eq!(header.value.to_str().unwrap(), "test: test");
        let header = Header::from_str("X-Test:test").unwrap();
        assert_eq!(header.name.as_str().to_lowercase(), "X-Test".to_lowercase());
        header.value.to_str().unwrap();
        assert_eq!(header.value.to_str().unwrap(), "test");
    }
}
