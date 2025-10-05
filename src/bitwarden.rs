use bitwarden::{
    Client, ClientSettings,
    auth::login::AccessTokenLoginRequest,
    secrets_manager::{ClientSecretsExt, secrets::SecretsGetRequest},
};
use error_stack::{Report, ResultExt};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
#[error("bitwarden client create error")]
pub struct Error;

type Result<T> = std::result::Result<T, Report<Error>>;

pub struct BitwardenSecret {
    client: Client,
    secret_ids: Vec<Uuid>,
}

impl BitwardenSecret {
    pub async fn new(token: &str, secret_ids: Vec<Uuid>) -> Result<Self> {
        let setting = ClientSettings::default();
        let client = Client::new(Some(setting));

        let token = AccessTokenLoginRequest {
            access_token: String::from(token),
            state_file: None,
        };
        client
            .auth()
            .login_access_token(&token)
            .await
            .change_context(Error)
            .attach("failed to login to Bitwarden")?;

        Ok(Self { client, secret_ids })
    }

    pub async fn get_secrets(&self) -> Result<Vec<String>> {
        let input = SecretsGetRequest {
            ids: self.secret_ids.clone(),
        };
        let secrets = self
            .client
            .secrets()
            .get_by_ids(input)
            .await
            .change_context(Error)
            .attach(format!(
                "failed to get secrets from Bitwarden for ids: {:?}",
                self.secret_ids
            ))?;
        let secrets = secrets.data.into_iter().map(|s| s.value).collect();
        Ok(secrets)
    }
}
