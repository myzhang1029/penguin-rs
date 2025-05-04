use std::sync::Arc;
use tokio_tungstenite::Connector;

pub type TlsIdentity = Arc<()>;

#[derive(Clone, Copy, Debug)]
pub struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TLS error")
    }
}
impl std::error::Error for Error {}

pub async fn make_tls_identity(
    _cert_path: &str,
    _key_path: &str,
    _client_ca_path: Option<&str>,
) -> Result<TlsIdentity, Error> {
    Ok(Arc::new(()))
}

pub async fn make_tls_connector(
    _tls_cert: Option<&str>,
    _tls_key: Option<&str>,
    _tls_ca: Option<&str>,
    _tls_insecure: bool,
) -> Result<Connector, Error> {
    Ok(Connector::Plain)
}

pub async fn reload_tls_identity(
    _identity: &TlsIdentity,
    _cert_path: &str,
    _key_path: &str,
    _client_ca_path: Option<&str>,
) -> Result<(), Error> {
    Ok(())
}
