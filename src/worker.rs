use std::sync::Arc;

use error_stack::{Report, ResultExt};
use thiserror::Error;
use tracing::{Level, event, instrument};
use url::Url;
use vaultrs::{
    client::{VaultClient, VaultClientSettingsBuilder},
    sys::ServerStatus,
};

use crate::{bitwarden::BitwardenSecret, shoutdown::Shutdown};

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Error)]
pub enum Error {
    #[error("vault client error")]
    ClientError,
    #[error("vault setting error")]
    ClientSettingError,
    #[error("unseal error")]
    UnsealError,
}

pub type Result<T> = std::result::Result<T, Report<Error>>;

pub struct UnsealWorker {
    client: VaultClient,
    bitwarden_client: Arc<BitwardenSecret>,
    host: Url,
    interval: u64,
    shoutdown: Arc<Shutdown>,
}

impl UnsealWorker {
    pub fn new(
        host: &Url,
        interval: u64,
        bitwarden_client: Arc<BitwardenSecret>,
        shoutdown: Arc<Shutdown>,
    ) -> Result<Self> {
        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(host)
                .build()
                .change_context(Error::ClientSettingError)?,
        )
        .change_context(Error::ClientError)?;

        Ok(Self {
            client,
            bitwarden_client,
            host: host.clone(),
            interval,
            shoutdown,
        })
    }

    async fn get_keys(&self) -> Result<Vec<String>> {
        let keys = self
            .bitwarden_client
            .get_secrets()
            .await
            .change_context(Error::UnsealError)?;

        if keys.is_empty() {
            event!(Level::WARN, "no unseal keys found from bitwarden");
            let report =
                Report::new(Error::UnsealError).attach("no unseal keys found from bitwarden");
            return Err(report);
        }

        Ok(keys)
    }

    #[instrument(name = "worker::unseal", skip(self), fields(host = %self.host))]
    async fn unseal(&self) -> Result<()> {
        let keys = self.get_keys().await?;

        let last_key = keys.last().unwrap().clone();
        for key in keys.iter().take(keys.len() - 1) {
            let res = vaultrs::sys::unseal(&self.client, Some(key.clone()), None, None)
                .await
                .change_context(Error::ClientError)?;

            if res.threshold > keys.len() as u64 {
                let report =
                    Report::new(Error::UnsealError).attach("not enough keys to unseal the vault");
                return Err(report);
            }

            if !res.sealed {
                event!(Level::INFO, "vault at {} is unsealed", self.host);
                return Ok(());
            }
        }

        let res = vaultrs::sys::unseal(&self.client, Some(last_key), None, None)
            .await
            .change_context(Error::ClientError)?;

        if res.sealed {
            let report = Report::new(Error::UnsealError)
                .attach(format!("failed to unseal the vaule node: {}", self.host));
            return Err(report);
        }

        event!(Level::INFO, "vault at {} is unsealed", self.host);

        Ok(())
    }

    #[instrument(name = "worker::run", skip(self), fields(host = %self.host))]
    pub async fn run(self) {
        event!(
            Level::INFO,
            "starting unseal worker for vault at {}",
            self.host
        );

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(self.interval));

        loop {
            tokio::select! {
                _ = self.shoutdown.wait_for_shutdown() => {
                    break;
                }
                _ = interval.tick() => {
                    match vaultrs::sys::status(&self.client).await {
                        Ok(status) => match status {
                            ServerStatus::STANDBY | ServerStatus::OK => {
                                event!(Level::DEBUG,"vault at {} is in standby/ok mode, skipping unseal",self.host);
                                continue;
                            }
                            ServerStatus::SEALED => {
                                event!(Level::INFO, "vault at {} is sealed, starting unseal", self.host);
                            }
                            _ => {
                                event!(Level::WARN, "vault at {} is not ready, state: {:?}", self.host, status);
                                continue;
                            }
                        },
                        Err(e) => {
                            let report = Report::from(e).change_context(Error::ClientError)
                             .attach(format!("failed to check if vault at {}", self.host));
                            event!(Level::ERROR, "{report:?}");
                            continue;
                        }
                    }

                    match self.unseal().await {
                        Ok(_) => { }
                        Err(e) => {
                            let report = e.change_context(Error::UnsealError)
                             .attach(format!("failed to unseal vault at {}", self.host));
                            // use valuable::Valuable;
                            // use serde_json::json;
                            // let error_stack = json!(report);
                            // event!(Level::ERROR,  error_stack = error_stack.as_value());
                            event!(Level::ERROR,  "{report:?}" );
                            continue;
                        }
                    }
                }
            }
        }
    }
}
