use crate::{
    arg::ServerArgs,
    tls::{make_tls_identity_from_rcgen_pem, reload_tls_identity_from_rcgen_pem, TlsIdentity},
};
use instant_acme::{
    Account, Authorization, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder,
    Order, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::{ffi::OsStr, sync::OnceLock};
use tracing::{debug, error, info};

pub static ACME_CLIENT: OnceLock<Client> = OnceLock::new();

/// How many times to check the order status before giving up
const MAX_ORDER_RETRIES: u32 = 10;

/// Error type for ACME operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    InstantAcme(#[from] instant_acme::Error),
    #[error("Failed to execute challenge helper command: {0}")]
    ChallengeHelperExecution(#[from] std::io::Error),
    #[error("Failed to generate certificates: {0}")]
    CertificateGeneration(#[from] rcgen::Error),
    #[error("Invalid authorization status: {0:?}")]
    AuthInvalid(AuthorizationStatus),
    #[error("Invalid order status: {0:?}")]
    OrderInvalid(OrderStatus),
    #[error("ACME server does not support HTTP-01 challenge")]
    NoHttp01ChallengeSupport,
    #[error("Certificate processing failed: {0}")]
    Tls(#[from] crate::tls::Error),
}

/// Simple ACME Client
pub struct Client {
    account: Account,
    server_args: &'static ServerArgs,
    tls_config: TlsIdentity,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish()
    }
}

impl Client {
    pub async fn populate_or_get(server_args: &'static ServerArgs) -> Result<&'static Self, Error> {
        if let Some(client) = ACME_CLIENT.get() {
            return Ok(client);
        }
        let contact = server_args
            .tls_acme_email
            .as_ref()
            .map_or_else(std::vec::Vec::new, |email| vec![format!("mailto:{email}")]);

        let (account, _cred) = Account::create(
            &NewAccount {
                contact: contact
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<&str>>()
                    .as_slice(),
                terms_of_service_agreed: server_args.tls_acme_accept_tos,
                only_return_existing: false,
            },
            &server_args.tls_acme_url,
            None,
        )
        .await?;
        let (keypair, cert) = issue(&account, server_args).await?;

        let client = Self {
            account,
            server_args,
            tls_config: make_tls_identity_from_rcgen_pem(
                cert,
                keypair,
                server_args.tls_ca.as_deref(), // Optional client CA path
            )
            .await?,
        };
        ACME_CLIENT
            .set(client)
            .expect("Failed to set ACME_CLIENT (this is a bug)");
        Ok(ACME_CLIENT
            .get()
            .expect("ACME_CLIENT should be set (this is a bug)"))
    }

    pub fn get_tls_config_spawn_renewal(&'static self) -> TlsIdentity {
        tokio::spawn(async move {
            // Hard-coding a renewal interval of 30 days
            let interval = std::time::Duration::from_secs(30 * 24 * 60 * 60); // 30 days
            let mut interval = tokio::time::interval(interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the first tick so that we don't immediately renew
            interval.tick().await;
            loop {
                interval.tick().await;
                info!("Renewing ACME certificate...");
                match issue(&self.account, self.server_args).await {
                    Ok((keypair, cert)) => {
                        info!("Certificate renewed successfully.");
                        reload_tls_identity_from_rcgen_pem(
                            &self.tls_config,
                            cert,
                            keypair,
                            self.server_args.tls_ca.as_deref(),
                        )
                        .await
                        .unwrap_or_else(|e| {
                            error!("Cannot reload TLS identity: {e}");
                        });
                    }
                    Err(e) => {
                        error!("Failed to renew certificate: {e}");
                    }
                }
            }
        });
        self.tls_config.clone()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ChallengeFileAction {
    /// Create a new challenge file
    Create,
    /// Remove the challenge file after use
    Remove,
}

impl ChallengeFileAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Remove => "remove",
        }
    }
}

fn call_challenge_helper(
    helper: &OsStr,
    action: ChallengeFileAction,
    key_authorization: &str,
) -> Result<tokio::process::Child, Error> {
    debug!("executing challenge helper: {helper:?} {key_authorization}");
    let cmd = tokio::process::Command::new(helper)
        .arg(action.as_str())
        .arg(key_authorization)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    Ok(cmd)
}

/// Process a single challenge
async fn process_one_challenge<'a>(
    auth: &'a Authorization,
    order: &Order,
    helper: &OsStr,
) -> Result<Option<(String, &'a str)>, Error> {
    // Find the HTTP-01 challenge for each pending authorization
    let http_challenge = match auth.status {
        AuthorizationStatus::Valid => return Ok(None), // Already valid, no need to process
        AuthorizationStatus::Pending => auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or(Error::NoHttp01ChallengeSupport),
        _ => Err(Error::AuthInvalid(auth.status)),
    }?;
    let key_auth = order.key_authorization(http_challenge).as_str().to_string();
    // Execute the challenge helper to create the file
    call_challenge_helper(helper, ChallengeFileAction::Create, &key_auth)?
        .wait()
        .await
        .map_err(Error::ChallengeHelperExecution)?;
    debug!("processing for {key_auth} succeeded");
    Ok(Some((key_auth, &http_challenge.url)))
}

/// Process challenge files for the HTTP-01 challenge
async fn process_challenges(
    authorizations: &[Authorization],
    order: &mut instant_acme::Order,
    helper: &OsStr,
) -> Result<Vec<String>, Error> {
    let mut executed_challenges = Vec::with_capacity(authorizations.len());
    for auth in authorizations {
        match process_one_challenge(auth, order, helper).await {
            Ok(Some((key_auth, challenge_url))) => {
                executed_challenges.push(key_auth);
                // Tell the server we are ready for the challenges
                order.set_challenge_ready(challenge_url).await?;
            }
            Ok(None) => {}
            Err(e) => {
                for key_auth in &executed_challenges {
                    // Clean up any previously created challenge files on error
                    let _ = call_challenge_helper(helper, ChallengeFileAction::Remove, key_auth);
                }
                error!("Failed to process challenge: {e}");
                return Err(e);
            }
        }
    }
    Ok(executed_challenges)
}

/// Issues a new certificate using the ACME protocol.
/// Returns (KeyPair, String) where KeyPair is the private key and String is the certificate chain in PEM format.
async fn issue(account: &Account, server_args: &ServerArgs) -> Result<(KeyPair, String), Error> {
    // `expect`: challenge helper verified by `clap`
    let helper = server_args
        .tls_acme_challenge_helper
        .as_ref()
        .expect("Challenge helper missing (this is a bug)");
    let idents = server_args
        .tls_domain
        .iter()
        .map(|domain| Identifier::Dns(domain.clone()))
        .collect::<Vec<_>>();
    let new_order = NewOrder {
        identifiers: idents.as_slice(),
    };
    let mut order = account.new_order(&new_order).await?;
    let authorizations = order.authorizations().await?;
    let keyauths = process_challenges(&authorizations, &mut order, helper).await?;
    // Back off until the order becomes ready or invalid
    let mut backoff = crate::backoff::Backoff::new(
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(60),
        2,
        MAX_ORDER_RETRIES,
    );
    let order_cleanup = || {
        for key_auth in &keyauths {
            let _ = call_challenge_helper(helper, ChallengeFileAction::Remove, key_auth);
        }
    };
    while order.state().status != OrderStatus::Ready {
        info!("Waiting for order to be ready...");
        order.refresh().await?;
        let status = order.state().status;
        debug!("order status: {status:?}");
        if status == OrderStatus::Invalid {
            error!("Order became invalid");
            order_cleanup();
            return Err(Error::OrderInvalid(OrderStatus::Invalid));
        }
        if let Some(sleep) = backoff.advance() {
            info!("Order not ready, sleeping for {sleep:?}");
            tokio::time::sleep(sleep).await;
        } else {
            error!("Order did not become ready after 10 attempts");
            order_cleanup();
            return Err(Error::OrderInvalid(status));
        }
    }
    // All code paths should result in Ready
    assert_eq!(
        order.state().status,
        OrderStatus::Ready,
        "Order not ready (this is a bug)"
    );
    let names = server_args.tls_domain.clone();
    let mut params: CertificateParams = CertificateParams::new(names.clone())?;
    params.distinguished_name = DistinguishedName::new();
    let private_key = KeyPair::generate()?;
    let csr = params.serialize_request(&private_key)?;
    order.finalize(csr.der()).await?;
    let cert_chain_pem = loop {
        match order.certificate().await? {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    };
    order_cleanup();
    Ok((private_key, cert_chain_pem))
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "tests-acme-has-pebble")]
    use bytes::Bytes;
    #[cfg(feature = "tests-acme-has-pebble")]
    use http_body_util::BodyExt;
    use tempfile::tempdir;
    use tokio::io::AsyncReadExt;
    #[cfg(feature = "tests-acme-has-pebble")]
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    const TEST_KEY_AUTH: &str =
        "f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY";
    const TEST_TOKEN: &str = "f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY";
    #[cfg(feature = "tests-acme-has-pebble")]
    const TEST_PEBBLE_URL: &str = "https://localhost:14000/dir";

    #[cfg(feature = "tests-acme-has-pebble")]
    #[derive(Clone, Debug)]
    struct IgnoreTlsHttpClient(reqwest::Client);
    #[cfg(feature = "tests-acme-has-pebble")]
    impl IgnoreTlsHttpClient {
        fn new() -> Self {
            Self(
                reqwest::ClientBuilder::new()
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap(),
            )
        }
    }
    #[cfg(feature = "tests-acme-has-pebble")]
    impl instant_acme::HttpClient for IgnoreTlsHttpClient {
        fn request(
            &self,
            req: http::Request<http_body_util::Full<Bytes>>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<instant_acme::BytesResponse, instant_acme::Error>,
                    > + Send,
            >,
        > {
            let (reqwest_req, body) = req.into_parts();
            let new_self = self.clone();
            Box::pin(async move {
                let mut req = reqwest::Request::new(
                    reqwest::Method::from_bytes(reqwest_req.method.as_str().as_bytes()).unwrap(),
                    reqwest::Url::parse(reqwest_req.uri.to_string().as_str()).unwrap(),
                );
                let body_bytes = body
                    .collect()
                    .await
                    .map_or_else(|_| Bytes::new(), http_body_util::Collected::to_bytes);
                *req.headers_mut() = reqwest_req.headers;
                *req.body_mut() = Some(reqwest::Body::from(body_bytes));
                let resp = new_self.0.execute(req).await.unwrap();
                let http_resp: http::Response<reqwest::Body> = resp.into();
                let (parts, body) = http_resp.into_parts();
                let collected_body = body
                    .collect()
                    .await
                    .map_or_else(|_| Bytes::new(), http_body_util::Collected::to_bytes);
                Ok(instant_acme::BytesResponse {
                    parts,
                    body: Box::new(collected_body),
                })
            })
        }
    }
    #[tokio::test]
    async fn test_call_challenge_helper_simple() {
        let expected_out1 = "create f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY\n";
        let result = call_challenge_helper(
            OsStr::new("echo"),
            ChallengeFileAction::Create,
            TEST_KEY_AUTH,
        );
        let child = result.unwrap();
        let out = child.wait_with_output().await.unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(stdout, expected_out1);
        let expected_out2 = "remove f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY\n";
        let result = call_challenge_helper(
            OsStr::new("echo"),
            ChallengeFileAction::Remove,
            TEST_KEY_AUTH,
        );
        let child = result.unwrap();
        let out = child.wait_with_output().await.unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(stdout, expected_out2);
    }

    #[tokio::test]
    #[cfg(not(target_os = "windows"))]
    async fn test_call_challenge_helper_example() {
        let script_path = format!(
            "{}/.github/workflows/http01_helper_for_test.sh",
            env!("CARGO_MANIFEST_DIR")
        );
        let tmpdir = tempdir().unwrap();
        let actual_path = tmpdir.path().join("http01_helper");
        tokio::fs::copy(&script_path, &actual_path).await.unwrap();
        call_challenge_helper(
            actual_path.as_os_str(),
            ChallengeFileAction::Create,
            TEST_KEY_AUTH,
        )
        .unwrap()
        .wait()
        .await
        .unwrap();
        let expected_out = tmpdir
            .path()
            .join(".well-known/acme-challenge")
            .join(TEST_TOKEN);
        assert!(expected_out.exists(), "Challenge file was not created");
        let mut content = String::new();
        tokio::fs::File::open(&expected_out)
            .await
            .unwrap()
            .read_to_string(&mut content)
            .await
            .unwrap();
        assert_eq!(content.trim(), TEST_KEY_AUTH);

        call_challenge_helper(
            actual_path.as_os_str(),
            ChallengeFileAction::Remove,
            TEST_KEY_AUTH,
        )
        .unwrap()
        .wait()
        .await
        .unwrap();
        assert!(!expected_out.exists(), "Challenge file was not removed");
    }

    #[cfg(feature = "tests-acme-has-pebble")]
    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn test_process_one_challenge() {
        let script_path = format!(
            "{}/.github/workflows/http01_helper_for_test.sh",
            env!("CARGO_MANIFEST_DIR")
        );
        let tmpdir = tempdir().unwrap();
        let actual_path = tmpdir.path().join("http01_helper");
        tokio::fs::copy(&script_path, &actual_path).await.unwrap();
        let (account, _cred) = Account::create_with_http(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            TEST_PEBBLE_URL,
            None,
            Box::new(IgnoreTlsHttpClient::new()),
        )
        .await
        .unwrap();
        let identifier = Identifier::Dns("a.example.com".to_string());
        let new_order = NewOrder {
            identifiers: &[identifier],
        };
        let mut order = account.new_order(&new_order).await.unwrap();
        let authorizations = order.authorizations().await.unwrap();
        let first_auth = authorizations.first().unwrap();
        assert!(
            first_auth.status == AuthorizationStatus::Pending,
            "temporary error in test setup: auth status is {:?} instead of Pending",
            first_auth.status
        );
        let first_auth_challenge = first_auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .unwrap();
        let expected_key_auth = order
            .key_authorization(first_auth_challenge)
            .as_str()
            .to_string();
        let (keyauth, _url) = process_one_challenge(first_auth, &order, actual_path.as_os_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(keyauth, expected_key_auth);
        let token = expected_key_auth.split('.').next().unwrap();
        let verify_location = tmpdir.path().join(".well-known/acme-challenge").join(token);
        assert!(
            verify_location.exists(),
            "Challenge file was not created at expected location"
        );
        let mut content = String::new();
        tokio::fs::File::open(&verify_location)
            .await
            .unwrap()
            .read_to_string(&mut content)
            .await
            .unwrap();
        assert_eq!(content.trim(), expected_key_auth);
    }

    #[cfg(feature = "tests-acme-has-pebble")]
    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn test_process_challenges() {
        let script_path = format!(
            "{}/.github/workflows/http01_helper_for_test.sh",
            env!("CARGO_MANIFEST_DIR")
        );
        let tmpdir = tempdir().unwrap();
        let actual_path = tmpdir.path().join("http01_helper");
        tokio::fs::copy(&script_path, &actual_path).await.unwrap();
        let (account, _cred) = Account::create_with_http(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            TEST_PEBBLE_URL,
            None,
            Box::new(IgnoreTlsHttpClient::new()),
        )
        .await
        .unwrap();
        let identifiers = vec![
            Identifier::Dns("a.example.com".to_string()),
            Identifier::Dns("b.example.com".to_string()),
            Identifier::Dns("c.example.com".to_string()),
        ];
        let new_order = NewOrder {
            identifiers: &identifiers,
        };
        let mut order = account.new_order(&new_order).await.unwrap();
        let authorizations = order.authorizations().await.unwrap();
        assert_eq!(authorizations.len(), 3);
        let expected_key_auths = authorizations
            .iter()
            .filter_map(|auth| {
                if auth.status == AuthorizationStatus::Pending {
                    let http_challenge = auth
                        .challenges
                        .iter()
                        .find(|c| c.r#type == ChallengeType::Http01);
                    http_challenge.map(|c| order.key_authorization(c).as_str().to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        // Process the challenges
        let keyauths = process_challenges(&authorizations, &mut order, actual_path.as_os_str())
            .await
            .unwrap();
        for expected_key_auth in &expected_key_auths {
            assert!(keyauths.contains(expected_key_auth));
        }
        for keyauth in &keyauths {
            let token = keyauth.split('.').next().unwrap();
            let verify_location = tmpdir.path().join(".well-known/acme-challenge").join(token);
            assert!(verify_location.exists());
            let mut content = String::new();
            tokio::fs::File::open(&verify_location)
                .await
                .unwrap()
                .read_to_string(&mut content)
                .await
                .unwrap();
            assert_eq!(content.trim(), *keyauth);
        }
    }

    #[cfg(feature = "tests-acme-has-pebble")]
    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn test_issue() {
        let script_path = format!(
            "{}/.github/workflows/http01_helper_for_test.sh",
            env!("CARGO_MANIFEST_DIR")
        );
        let tmpdir = tempdir().unwrap();
        let actual_path = tmpdir.path().join("http01_helper");
        tokio::fs::copy(&script_path, &actual_path).await.unwrap();
        let http_server_task = tokio::spawn(async move {
            let listener = TcpListener::bind("localhost:5002").await.unwrap();
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0; 1024];
                let n = socket.read(&mut buf).await.unwrap();
                let request = String::from_utf8_lossy(&buf[..n]);
                // Extract path from the request
                if let Some(path) = request.split_whitespace().nth(1) {
                    let full_path = tmpdir.path().join(path.strip_prefix('/').unwrap_or(path));
                    if full_path.exists() {
                        let content = tokio::fs::read_to_string(&full_path)
                            .await
                            .unwrap_or_default();
                        let response = format!("HTTP/1.0 200 OK\r\n\r\n{content}");
                        socket.write_all(response.as_bytes()).await.unwrap();
                    } else {
                        socket
                            .write_all(b"HTTP/1.0 404 Not Found\r\n\r\n")
                            .await
                            .unwrap();
                    }
                } else {
                    error!("Failed to parse request: {request}");
                    socket
                        .write_all(b"HTTP/1.0 400 Bad Request\r\n\r\n")
                        .await
                        .unwrap();
                }
            }
        });

        let server_args = ServerArgs {
            tls_domain: vec!["localhost".to_string()],
            tls_acme_accept_tos: true,
            tls_acme_url: TEST_PEBBLE_URL.to_string(),
            tls_acme_challenge_helper: Some(actual_path.into_os_string()),
            ..Default::default()
        };
        let (account, _cred) = Account::create_with_http(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            TEST_PEBBLE_URL,
            None,
            Box::new(IgnoreTlsHttpClient::new()),
        )
        .await
        .unwrap();
        let (keypair, cert) = issue(&account, &server_args).await.unwrap();
        assert!(!cert.is_empty());
        assert!(!keypair.serialize_pem().is_empty());
        http_server_task.abort();
    }
}
