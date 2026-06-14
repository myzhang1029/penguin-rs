//! HTTP Proxy header manipulation
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use http::{HeaderMap, HeaderName, HeaderValue, header};
use penguin_mux::Dupe;
use std::net::SocketAddr;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

pub fn add_headers(headers: &mut HeaderMap, client_addr: Option<SocketAddr>) {
    let Some(client_addr) = client_addr else {
        return;
    };
    let client_ip = client_addr.ip().to_string();
    if let Some(host) = headers.get(header::HOST) {
        headers.append(X_FORWARDED_HOST, host.dupe());
    }
    headers.append(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
    add_x_forwarded_for(headers, &client_ip);
}

/// Add `X-Forwarded-For` header
#[inline]
fn add_x_forwarded_for(headers: &mut HeaderMap, client_ip: &str) {
    let mut forwarded_hops: Vec<&str> = headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        .flat_map(|hdr| hdr.to_str().unwrap_or("").split(','))
        .map(str::trim)
        .collect();
    forwarded_hops.push(client_ip);
    if let Ok(value) = HeaderValue::from_str(&forwarded_hops.join(", ")) {
        headers.remove(X_FORWARDED_FOR);
        headers.append(X_FORWARDED_FOR, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_headers() {
        let mut hdr = HeaderMap::new();
        add_headers(&mut hdr, None);
        assert_eq!(hdr.len(), 0);
        add_headers(&mut hdr, Some("[2001:db8::1]:0".parse().unwrap()));
        assert_eq!(hdr.get(X_FORWARDED_FOR).unwrap(), "2001:db8::1");
        assert_eq!(hdr.get(X_FORWARDED_PROTO).unwrap(), "http");
        add_headers(&mut hdr, Some("[2001:db8::1]:0".parse().unwrap()));
        assert_eq!(
            hdr.get(X_FORWARDED_FOR).unwrap(),
            "2001:db8::1, 2001:db8::1"
        );
        assert_eq!(hdr.get(X_FORWARDED_PROTO).unwrap(), "http");
        hdr.insert(header::HOST, HeaderValue::from_static("example.com"));
        add_headers(&mut hdr, Some("0.0.0.0:0".parse().unwrap()));
        assert_eq!(
            hdr.remove(X_FORWARDED_FOR).unwrap(),
            "2001:db8::1, 2001:db8::1, 0.0.0.0"
        );
        assert_eq!(hdr.remove(X_FORWARDED_PROTO).unwrap(), "http");
        assert_eq!(
            hdr.remove(X_FORWARDED_HOST).unwrap(),
            HeaderValue::from_static("example.com")
        );
        hdr.remove(header::HOST).unwrap();
        assert_eq!(hdr.len(), 0);
    }
}
