//! TLS-related code for `native-tls`.
//! SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use super::Error;
use native_tls::Identity;

pub async fn make_tls_identity(
    cert_path: &str,
    key_path: &str,
    _client_ca_path: Option<&str>,
) -> Result<Identity, Error> {
    // TODO: support client CA
    let cert = tokio::fs::read(cert_path).await?;
    let key = tokio::fs::read(key_path).await?;
    let identity = native_tls::Identity::from_pkcs8(&cert, &key)?;
    Ok(identity)
}
