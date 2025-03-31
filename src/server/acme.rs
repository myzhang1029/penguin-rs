use crate::{
    arg::ServerArgs,
    tls::{make_tls_identity_from_rcgen_pem, reload_tls_identity_from_rcgen_pem, TlsIdentity},
};
use instant_acme::{
    Account, Authorization, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder,
    OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::sync::OnceLock;
use tokio::{io::AsyncWriteExt, process::Child};
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
    #[error("Order became invalid")]
    OrderInvalid,
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

fn create_challenge_file(
    token: &str,
    key_authorization: &str,
    server_args: &'static ServerArgs,
) -> Result<tokio::process::Child, Error> {
    // `expect`: challenge helper verified by `clap`
    let helper = server_args
        .tls_acme_challenge_helper
        .as_ref()
        .expect("Challenge helper missing (this is a bug)");
    debug!("Executing challenge helper: {helper} {token} {key_authorization}");
    let cmd = tokio::process::Command::new(helper)
        .arg(token)
        .arg(key_authorization)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    Ok(cmd)
}

/// Process challenge files for the HTTP-01 challenge.
async fn process_challenges(
    authorizations: &[Authorization],
    server_args: &'static ServerArgs,
    order: &mut instant_acme::Order,
) -> Result<Vec<Child>, Error> {
    // Save the commands to terminate them after we are done
    let mut cmds: Vec<Child> = Vec::with_capacity(authorizations.len());
    for auth in authorizations {
        match auth.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => {
                error!("Invalid authorization status: {:?}", auth.status);
                return Err(Error::OrderInvalid);
            }
        }
        // Find the HTTP-01 challenge
        let http_challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or(Error::NoHttp01ChallengeSupport)?;

        // Execute the challenge helper to create the file
        let key_auth = order.key_authorization(http_challenge);
        let cmd = create_challenge_file(&http_challenge.token, key_auth.as_str(), server_args)?;
        cmds.push(cmd);
        // Tell the server we are ready for the challenges
        order
            .set_challenge_ready(&http_challenge.url)
            .await
            .unwrap();
    }
    Ok(cmds)
}

/// Issues a new certificate using the ACME protocol.
/// Returns (KeyPair, String) where KeyPair is the private key and String is the certificate chain in PEM format.
async fn issue(
    account: &Account,
    server_args: &'static ServerArgs,
) -> Result<(KeyPair, String), Error> {
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
    let cmds = process_challenges(&authorizations, server_args, &mut order).await?;
    let order_cleanup = async {
        // Clean up the challenge files by sending a newline and closing stdin
        for mut cmd in cmds {
            let stdin = cmd.stdin.take();
            if let Some(mut stdin) = stdin {
                let _ = stdin.write(b"\n").await.ok();
                stdin.flush().await.ok();
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };
    // Back off until the order becomes ready or invalid
    let mut backoff = crate::backoff::Backoff::new(
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(60),
        2,
        10,
    );
    while order.state().status != OrderStatus::Ready {
        info!("Waiting for order to be ready...");
        order.refresh().await?;
        if order.state().status == OrderStatus::Invalid {
            error!("Order became invalid");
            order_cleanup.await;
            return Err(Error::OrderInvalid);
        }
        if let Some(sleep) = backoff.advance() {
            info!("Order not ready, sleeping for {sleep:?}");
            tokio::time::sleep(sleep).await;
        } else {
            error!("Order did not become ready after 10 attempts");
            order_cleanup.await;
            return Err(Error::OrderInvalid);
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
    order_cleanup.await;
    Ok((private_key, cert_chain_pem))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::arg;
    use std::sync::LazyLock;

    #[tokio::test]
    async fn test_create_challenge_file() {
        static SERVER_ARGS: LazyLock<arg::ServerArgs> = LazyLock::new(|| arg::ServerArgs {
            tls_acme_challenge_helper: Some("echo".to_string()),
            ..Default::default()
        });
        let test_token = "f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY";
        let test_key_auth = "f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY";
        let expected_out = "f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY\n";
        let result = create_challenge_file(test_token, test_key_auth, &SERVER_ARGS);
        let child = result.unwrap();
        let out = child.wait_with_output().await.unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(stdout, expected_out);
    }
}
