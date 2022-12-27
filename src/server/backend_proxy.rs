//! Penguin server backend proxy.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use tracing::debug;
use warp::filters::path::FullPath;
use warp::http::HeaderMap;
use warp::hyper::body::Bytes;
use warp::{Filter, Rejection};
use warp_reverse_proxy::{
    extract_request_data_filter, proxy_to_and_forward_response, Method, QueryParameters,
};

/// Add a correct `Host` header to the proxied request.
#[allow(clippy::type_complexity)]
async fn add_host_header(
    proxy_address: String,
    base_path: String,
    uri: FullPath,
    params: QueryParameters,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<
    (
        String,
        String,
        FullPath,
        QueryParameters,
        Method,
        HeaderMap,
        Bytes,
    ),
    Rejection,
> {
    let host = proxy_address
        .replace("http://", "")
        .replace("https://", "")
        .replace('/', "");
    debug!("Host: {}", host);
    let mut headers = headers;
    headers.insert("host", host.parse().unwrap());
    Ok((proxy_address, base_path, uri, params, method, headers, body))
}

/// Prepare proxy arguments if there is a backend configured.
fn check_proxy(
    backend: Option<String>,
) -> impl Filter<
    Extract = (
        String,
        String,
        FullPath,
        QueryParameters,
        Method,
        HeaderMap,
        Bytes,
    ),
    Error = Rejection,
> + Clone {
    warp::any()
        .and_then(move || {
            let backend = backend.clone();
            async move {
                if let Some(backend) = backend {
                    Ok((backend, String::new()))
                } else {
                    // No backend configured
                    Err(warp::reject::not_found())
                }
            }
        })
        .untuple_one()
        .and(extract_request_data_filter())
        // Add a correct `Host` header to the proxied request
        .and_then(add_host_header)
        .untuple_one()
}

/// Proxy a request to the backend if there is a backend configured.
/// backend: The backend to proxy to, in NGINX proxy_pass format.
pub fn check_pass_proxy(
    backend: Option<String>,
) -> impl Filter<Extract = (warp::reply::Response,), Error = warp::Rejection> + Clone {
    check_proxy(backend).and_then(proxy_to_and_forward_response)
}

#[cfg(test)]
mod tests {
    use warp::hyper::body::Bytes;
    use warp_reverse_proxy::Method;

    /// Test check_proxy and add_host_header together.
    #[tokio::test]
    async fn test_check_proxy() {
        let backend = Some(String::from("http://proxy:8080/"));
        let proxy = super::check_proxy(backend);
        let request = warp::test::request();
        let (proxy_address, base_path, uri, _params, method, headers, body) =
            request.filter(&proxy).await.unwrap();
        assert_eq!(proxy_address, "http://proxy:8080/");
        assert_eq!(base_path, "");
        assert_eq!(uri.as_str(), "/");
        assert_eq!(method, Method::GET);
        assert_eq!(headers.get("Host").unwrap(), "proxy:8080");
        assert_eq!(body, Bytes::new());

        let backend = Some(String::from("http://proxy:8080"));
        let proxy = super::check_proxy(backend);
        let request = warp::test::request()
            .method("POST")
            .path("/foo/bar")
            .header("host", "localhost:8080")
            .body("Hello, world!");
        let (proxy_address, base_path, uri, _params, method, headers, body) =
            request.filter(&proxy).await.unwrap();
        assert_eq!(proxy_address, "http://proxy:8080");
        assert_eq!(base_path, "");
        assert_eq!(uri.as_str(), "/foo/bar");
        assert_eq!(method, Method::POST);
        assert_eq!(headers.get("host").unwrap(), "proxy:8080");
        assert_eq!(body, Bytes::from_static(b"Hello, world!"));

        let backend = None;
        let proxy = super::check_proxy(backend);
        let request = warp::test::request();
        let result = request.filter(&proxy).await;
        assert!(result.is_err());
    }
}
