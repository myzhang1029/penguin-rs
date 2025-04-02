use crate::{
    arg::ServerArgs,
    tls::{make_tls_identity_from_rcgen_pem, reload_tls_identity_from_rcgen_pem, TlsIdentity},
};
use instant_acme::{
    Account, Authorization, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, Order, OrderStatus
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::sync::OnceLock;
use tracing::{debug, error, info};

pub static ACME_CLIENT: OnceLock<Client> = OnceLock::new();

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
    helper: &str,
    action: ChallengeFileAction,
    key_authorization: &str,
) -> Result<tokio::process::Child, Error> {
    debug!("Executing challenge helper: {helper} {key_authorization}");
    let cmd = tokio::process::Command::new(helper)
        .arg(action.as_str())
        .arg(key_authorization)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    Ok(cmd)
}

/// Process a single challenge
async fn process_one_challenge<'a>(
    auth: &'a Authorization,
    helper: &str,
    order: &Order,
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
    helper: &str,
    order: &mut instant_acme::Order,
) -> Result<Vec<String>, Error> {
    let mut executed_challenges = Vec::with_capacity(authorizations.len());
    for auth in authorizations {
        match process_one_challenge(auth, helper, order).await {
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
async fn issue(
    account: &Account,
    server_args: &'static ServerArgs,
) -> Result<(KeyPair, String), Error> {
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
    let keyauths = process_challenges(&authorizations, helper, &mut order).await?;
    // Back off until the order becomes ready or invalid
    let mut backoff = crate::backoff::Backoff::new(
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(60),
        2,
        10,
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
    use std::env;
    use tempfile::tempdir;
    use tokio::io::AsyncReadExt;

    const TEST_KEY_AUTH: &str =
        "f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY";
    const TEST_TOKEN: &str = "f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY";

    #[tokio::test]
    async fn test_call_challenge_helper_simple() {
        let expected_out1 = "create f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY\n";
        let result = call_challenge_helper("echo", ChallengeFileAction::Create, TEST_KEY_AUTH);
        let child = result.unwrap();
        let out = child.wait_with_output().await.unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(stdout, expected_out1);
        let expected_out2 = "remove f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY\n";
        let result = call_challenge_helper("echo", ChallengeFileAction::Remove, TEST_KEY_AUTH);
        let child = result.unwrap();
        let out = child.wait_with_output().await.unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(stdout, expected_out2);
    }

    #[tokio::test]
    #[cfg(not(target_os = "windows"))]
    async fn test_call_challenge_helper_example() {
        let script_path = format!("{}/tools/http01_helper", env!("CARGO_MANIFEST_DIR"));
        let tmpdir = tempdir().unwrap();
        temp_env::with_var("WEBROOT", Some(tmpdir.path().as_os_str()), || {
            call_challenge_helper(&script_path, ChallengeFileAction::Create, TEST_KEY_AUTH).unwrap()
        })
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

        temp_env::with_var("WEBROOT", Some(tmpdir.path().as_os_str()), || {
            call_challenge_helper(&script_path, ChallengeFileAction::Remove, TEST_KEY_AUTH).unwrap()
        })
        .wait()
        .await
        .unwrap();
        assert!(!expected_out.exists(), "Challenge file was not removed");
    }
}
