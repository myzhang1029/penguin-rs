use crate::{
    arg::ServerArgs,
    tls::{make_tls_identity_from_rcgen_pem, reload_tls_identity_from_rcgen_pem, TlsIdentity},
};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::sync::OnceLock;
use tokio::process::Child;
use tracing::{error, info};

pub static ACME_CLIENT: OnceLock<Client> = OnceLock::new();

/// Error type for ACME operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    InstantAcme(#[from] instant_acme::Error),
    #[error("Failed to execute challenge helper command: {0}")]
    ChallengeHelperExecution(#[from] std::io::Error),
    #[error("Invalid challenge key from server: {0}")]
    InvalidChallengeKey(String),
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
        let contact = if let Some(email) = &server_args.tls_acme_email {
            vec![format!("mailto:{}", email)]
        } else {
            vec![]
        };

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

        let client = Client {
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
    key: &str,
    server_args: &'static ServerArgs,
) -> Result<tokio::process::Child, Error> {
    let token = key
        .split('.')
        .next()
        .ok_or_else(|| Error::InvalidChallengeKey(format!("Invalid key format: {key}")))?;
    // `expect`: challenge helper verified by `clap`
    let helper = server_args
        .tls_acme_challenge_helper
        .as_ref()
        .expect("Challenge helper missing (this is a bug)");
    let cmd = tokio::process::Command::new(helper)
        .arg(token)
        .arg(key)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    Ok(cmd)
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
    assert!(matches!(order.state().status, OrderStatus::Pending));
    let authorizations = order.authorizations().await?;
    // Save the commands to terminate them after we are done
    let mut cmd_url: Vec<(Child, &String)> = Vec::with_capacity(authorizations.len());
    for auth in &authorizations {
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
        let cmd = create_challenge_file(&http_challenge.token, server_args)?;
        cmd_url.push((cmd, &http_challenge.url));
    }
    // Tell the server we are ready for the challenges
    for (_, url) in &cmd_url {
        order.set_challenge_ready(url).await.unwrap();
    }
    // Back off until the order becomes ready or invalid
    let mut wait_time = 5;
    let mut tries = 0;
    while tries < 10 {
        tries += 1;
        info!("Waiting for order to be ready (attempt {tries}/10)...");
        order.refresh().await?;
        match order.state().status {
            OrderStatus::Ready => break,
            OrderStatus::Invalid => {
                error!("Order became invalid");
                return Err(Error::OrderInvalid);
            }
            _ => {
                info!("Order status: {:?}", order.state().status);
                tokio::time::sleep(tokio::time::Duration::from_secs(wait_time)).await;
                wait_time = std::cmp::min(wait_time * 2, 60); // Exponential backoff
            }
        }
    }
    if order.state().status != OrderStatus::Ready {
        error!("Order did not become ready after 10 attempts");
        return Err(Error::OrderInvalid);
    }
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
    // Clean up the challenge files by closing their stdin
    for (mut cmd, _) in cmd_url {
        let _ = cmd.stdin.take();
    }
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
        let test_key = "f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY";
        let expected_out = "f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY\n";
        let result = create_challenge_file(test_key, &SERVER_ARGS);
        let child = result.unwrap();
        let out = child.wait_with_output().await.unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(stdout, expected_out);
    }
}
