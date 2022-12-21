//! Penguin server.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use crate::arg::ServerArgs;
use log::debug;
use warp::Filter;

pub async fn server_main(args: ServerArgs) {
    debug!("Server args: {:?}", args);

    let sockaddr = (
        args.host
            .parse::<std::net::IpAddr>()
            .expect("Invalid listening host"),
        args.port,
    );

    // Match any request and return hello world!
    let routes = warp::any().map(|| "Hello, World!");

    if let Some(tls_key) = args.tls_key {
        let tls_server = warp::serve(routes)
            .tls()
            // clap should ensure that cert and key are both present
            .cert_path(args.tls_cert.unwrap())
            .key_path(tls_key);
        // If a client CA is provided, enable client auth
        if let Some(client_tls_ca) = args.tls_ca {
            tls_server.client_auth_optional_path(client_tls_ca)
        } else {
            tls_server
        }
        .run(sockaddr)
        .await;
    } else {
        warp::serve(routes).run(sockaddr).await;
    }
}
