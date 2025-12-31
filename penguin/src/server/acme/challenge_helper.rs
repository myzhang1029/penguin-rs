use super::Error;
use instant_acme::{AuthorizationHandle, ChallengeType};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use tracing::{debug, error};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Create a new challenge file
    Create,
    /// Remove the challenge file after use
    Remove,
}

impl Action {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Remove => "remove",
        }
    }
}

/// An external command to create or remove a challenge file for ACME validation
#[derive(Clone)]
pub struct ChallengeHelper(OsString);

impl std::fmt::Debug for ChallengeHelper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<OsString> for ChallengeHelper {
    fn from(path: OsString) -> Self {
        Self(path)
    }
}

impl From<PathBuf> for ChallengeHelper {
    fn from(path: PathBuf) -> Self {
        Self(path.into_os_string())
    }
}

impl AsRef<OsStr> for ChallengeHelper {
    fn as_ref(&self) -> &OsStr {
        &self.0
    }
}

impl ChallengeHelper {
    /// Create or remove a challenge file using the helper command
    pub fn call(
        &self,
        action: Action,
        key_authorization: &str,
    ) -> Result<tokio::process::Child, Error> {
        debug!("executing challenge helper: {self:?} {key_authorization}");
        let cmd = tokio::process::Command::new(self)
            .arg(action.as_str())
            .arg(key_authorization)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(Error::ChallengeHelperExecution)?;
        Ok(cmd)
    }

    /// Process a single challenge
    pub async fn one_challenge(&self, mut auth: AuthorizationHandle<'_>) -> Result<String, Error> {
        // Find the HTTP-01 challenge for each pending authorization
        let mut http_challenge = auth
            .challenge(ChallengeType::Http01)
            .ok_or(Error::NoHttp01ChallengeSupport)?;
        let key_auth = http_challenge.key_authorization().as_str().to_string();
        // Execute the challenge helper to create the file
        self.call(Action::Create, &key_auth)?
            .wait()
            .await
            .map_err(Error::ChallengeHelperExecution)?;
        debug!("processing for {key_auth} succeeded");
        http_challenge.set_ready().await?;
        Ok(key_auth)
    }

    /// Process challenge files for the HTTP-01 challenge
    pub async fn process_challenges(
        &self,
        order: &mut instant_acme::Order,
    ) -> Result<Vec<String>, Error> {
        let mut autorizations = order.authorizations();
        let mut executed_challenges = Vec::new();
        while let Some(auth) = autorizations.next().await {
            match auth {
                Ok(auth) => {
                    match self.one_challenge(auth).await {
                        Ok(key_auth) => executed_challenges.push(key_auth),
                        Err(e) => {
                            for key_auth in &executed_challenges {
                                // Clean up any previously created challenge files on error
                                let _ = self.call(Action::Remove, key_auth);
                            }
                            error!("Failed to process challenge: {e}");
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get authorization: {e}");
                    for key_auth in &executed_challenges {
                        // Clean up any previously created challenge files on error
                        let _ = self.call(Action::Remove, key_auth);
                    }
                    return Err(e.into());
                }
            }
        }
        Ok(executed_challenges)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    #[cfg(feature = "tests-acme-has-pebble")]
    use super::super::tests_need_pebble::*;
    use super::*;
    #[cfg(feature = "tests-acme-has-pebble")]
    use instant_acme::{Account, Identifier, NewAccount, NewOrder};
    use tempfile::tempdir;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_call_challenge_helper_simple() {
        crate::tests::setup_logging();
        let expected_out1 = "create f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY\n";
        let helper = ChallengeHelper(OsString::from("echo"));
        let result = helper.call(Action::Create, TEST_KEY_AUTH);
        let child = result.unwrap();
        let out = child.wait_with_output().await.unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(stdout, expected_out1);
        let expected_out2 = "remove f86oS4UZR6kX5U31VVc05dhOa-GMEvU3RL1Q64fVaKY.tvg9X8xCoUuU_vK9qNR1d2RyGSGVfq3VYDJ-O81nnyY\n";
        let result = helper.call(Action::Remove, TEST_KEY_AUTH);
        let child = result.unwrap();
        let out = child.wait_with_output().await.unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(stdout, expected_out2);
    }

    #[tokio::test]
    #[cfg(not(target_os = "windows"))]
    async fn test_call_challenge_helper_example() {
        crate::tests::setup_logging();
        let script_path = format!(
            "{}/../.github/workflows/http01_helper_for_test.sh",
            env!("CARGO_MANIFEST_DIR")
        );
        let tmpdir = tempdir().unwrap();
        let actual_path = tmpdir.path().join("http01_helper.sh");
        tokio::fs::copy(&script_path, &actual_path).await.unwrap();
        // Wait until the file is ready (for Linux CI runs)
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let helper = ChallengeHelper::from(actual_path);
        helper
            .call(Action::Create, TEST_KEY_AUTH)
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

        helper
            .call(Action::Remove, TEST_KEY_AUTH)
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
        crate::tests::setup_logging();
        let script_path = format!(
            "{}/../.github/workflows/http01_helper_for_test.sh",
            env!("CARGO_MANIFEST_DIR")
        );
        let tmpdir = tempdir().unwrap();
        let actual_path = tmpdir.path().join("http01_helper.sh");
        tokio::fs::copy(&script_path, &actual_path).await.unwrap();
        // Wait until the file is ready (for Linux CI runs)
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let helper = ChallengeHelper::from(actual_path);
        let (account, _cred) =
            Account::builder_with_http(Box::new(IgnoreTlsHttpClient::new().await))
                .create(
                    &NewAccount {
                        contact: &[],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    TEST_PEBBLE_URL.to_string(),
                    None,
                )
                .await
                .unwrap();
        let identifiers = [Identifier::Dns("a.example.com".to_string())];
        let new_order = NewOrder::new(&identifiers);
        let mut order = account.new_order(&new_order).await.unwrap();
        let mut authorizations = order.authorizations();
        let mut first_auth = authorizations.next().await.unwrap().unwrap();
        let expected_key_auth = first_auth
            .challenge(ChallengeType::Http01)
            .unwrap()
            .key_authorization()
            .as_str()
            .to_string();
        let mut authorizations = order.authorizations();
        let first_auth = authorizations.next().await.unwrap().unwrap();
        let keyauth = helper.one_challenge(first_auth).await.unwrap();
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
        crate::tests::setup_logging();
        let script_path = format!(
            "{}/../.github/workflows/http01_helper_for_test.sh",
            env!("CARGO_MANIFEST_DIR")
        );
        let tmpdir = tempdir().unwrap();
        let actual_path = tmpdir.path().join("http01_helper.sh");
        tokio::fs::copy(&script_path, &actual_path).await.unwrap();
        // Wait until the file is ready (for Linux CI runs)
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let helper = ChallengeHelper::from(actual_path);
        let (account, _cred) =
            Account::builder_with_http(Box::new(IgnoreTlsHttpClient::new().await))
                .create(
                    &NewAccount {
                        contact: &[],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    TEST_PEBBLE_URL.to_string(),
                    None,
                )
                .await
                .unwrap();
        let identifiers = vec![
            Identifier::Dns("a.example.com".to_string()),
            Identifier::Dns("b.example.com".to_string()),
            Identifier::Dns("c.example.com".to_string()),
        ];
        let new_order = NewOrder::new(&identifiers);
        let mut order = account.new_order(&new_order).await.unwrap();
        let mut authorizations = order.authorizations();

        let mut expected_key_auths = Vec::new();
        while let Some(auth) = authorizations.next().await {
            let mut auth = auth.unwrap();
            let challenge = auth.challenge(ChallengeType::Http01).unwrap();
            let keyauth = challenge.key_authorization().as_str().to_string();
            expected_key_auths.push(keyauth);
        }
        assert_eq!(expected_key_auths.len(), 3);
        // Process the challenges
        let keyauths = helper.process_challenges(&mut order).await.unwrap();
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
}
