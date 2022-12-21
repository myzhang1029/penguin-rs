//! Penguin server.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

mod backend_proxy;
mod websocket;

use crate::arg::ServerArgs;
use backend_proxy::check_pass_proxy;
use log::{debug, info};
use warp::Filter;
use websocket::ws_filter;

pub async fn server_main(args: ServerArgs) {
    debug!("Server args: {:?}", args);

    let sockaddr = (
        args.host
            .parse::<std::net::IpAddr>()
            .expect("Invalid listening host"),
        args.port,
    );

    // Upgrade to a websocket if the path is `/ws` and the PSK matches
    // (if required)
    let ws_upgrader = warp::path("ws")
        .and(warp::path::end())
        .and(ws_filter(args.ws_psk));

    // Health and version endpoints if not obfuscating
    let health = warp::path("health")
        .and(warp::path::end())
        .and_then(move || async move {
            if args.obfs {
                Err(warp::reject::not_found())
            } else {
                Ok("OK")
            }
        });

    let version = warp::path("version")
        .and(warp::path::end())
        .and_then(move || async move {
            if args.obfs {
                Err(warp::reject::not_found())
            } else {
                Ok(env!("CARGO_PKG_VERSION"))
            }
        });

    // If there is a backend, pass through to it
    let backend = warp::any().and(check_pass_proxy(args.backend));

    // Catch-it-all handler for 404s
    let not_found = warp::any().map(move || {
        warp::reply::with_status(
            args.not_found_resp.clone(),
            warp::http::StatusCode::NOT_FOUND,
        )
    });

    let routes = ws_upgrader.or(health).or(version).or(backend).or(not_found);

    if let Some(tls_key) = args.tls_key {
        info!("Enabling TLS");
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
