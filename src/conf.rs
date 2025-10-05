use std::{path::PathBuf, str::FromStr};

use clap::{Args, ValueEnum};
use error_stack::{Report, ResultExt};
use figment::{Figment, providers::*};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::Level;
use url::Url;
use uuid::Uuid;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
#[error("config error")]
pub enum Error {
    #[error("figment error")]
    FigmentError,
    #[error("invalid vault node url")]
    InvalidVaultNodeUrl,
    #[error("missing bitwarden configuration")]
    MissingBitwardenConfig,
}

type Result<T> = std::result::Result<T, Report<Error>>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VaultNode {
    pub host: Url,
}

impl FromStr for VaultNode {
    type Err = Report<Error>;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(VaultNode {
            host: Url::parse(s).change_context(Error::InvalidVaultNodeUrl)?,
        })
    }
}

#[derive(Debug, Args, Clone, Deserialize, Serialize)]
pub struct ExternalBitwarden {
    /// bitwarden host
    #[clap(long = "bw-host")]
    #[serde(rename = "host")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bw_host: Option<Url>,
    /// bitwarden token
    #[clap(long = "bw-token")]
    #[serde(rename = "token")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bw_token: Option<String>,
    /// bitwarden secret ids
    #[clap(long = "bw-secret-ids", use_value_delimiter = true)]
    #[serde(rename = "secret_ids")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bw_secret_ids: Option<Vec<Uuid>>,
}

#[derive(Debug, Args, Clone, Deserialize, Serialize)]
pub struct Bitwarden {
    pub host: Url,
    pub token: String,
    pub secret_ids: Vec<Uuid>,
}

#[derive(Debug, Args, Clone, Serialize, Deserialize)]
pub struct ExternalLog {
    /// log level default: info
    #[arg(long = "log-level")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<LogLevel>,
    /// log in json format
    #[arg(long = "log-json")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<bool>,
}

#[derive(Debug, Clone, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Warn,
    Debug,
    Error,
    Trace,
}

impl From<LogLevel> for Level {
    fn from(log: LogLevel) -> Self {
        match log {
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Error => Level::ERROR,
            LogLevel::Trace => Level::TRACE,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub level: LogLevel,
    pub json: bool,
}

#[derive(Debug, Args, Clone, Deserialize, Serialize)]
pub struct ExternalConfig {
    /// vault nodes url
    #[arg(long = "vault-nodes", num_args = 0..)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_nodes: Option<Vec<VaultNode>>,
    #[command(flatten)]
    pub bitwarden: ExternalBitwarden,
    /// check unseal interval
    #[arg(long = "check-interval")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_interval: Option<u64>,
    #[command(flatten)]
    pub log: ExternalLog,
}

impl Default for ExternalConfig {
    fn default() -> Self {
        Self {
            vault_nodes: None,
            bitwarden: ExternalBitwarden {
                bw_host: Some(Url::parse("https://vault.bitwarden.com").unwrap()),
                bw_token: None,
                bw_secret_ids: None,
            },
            check_interval: Some(10),
            log: ExternalLog {
                level: Some(LogLevel::Info),
                json: Some(false),
            },
        }
    }
}

impl ExternalConfig {
    // Create config from multiple sources
    // Override priority (low to high): default < file < env < cli
    pub fn figment(path: &[PathBuf], cfg: Option<&ExternalConfig>) -> Result<Self> {
        let _ = dotenvy::dotenv();

        let config = Figment::new();

        // 1. merge default config values
        let mut config = config.merge(Serialized::defaults(&ExternalConfig::default()));

        // 2. load config from files
        // 2.1 - toml
        for path in path
            .iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
        {
            config = config.merge(Toml::file(path));
        }

        // 2.2 - yaml
        for path in path.iter().filter(|p| {
            p.extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        }) {
            config = config.merge(Yaml::file(path));
        }

        // 2.3 - json
        for path in path
            .iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        {
            config = config.merge(Json::file(path));
        }

        // 3. load config from env with prefix UNSEAL__
        let mut config = config.merge(Env::prefixed("UNSEAL__").split("__"));

        // 4. load config from cli args
        if let Some(cfg) = cfg {
            config = config.merge(Serialized::defaults(cfg));
        }

        let config = config.extract().change_context(Error::FigmentError)?;
        Ok(config)
    }
}

#[derive(Debug, Clone)]
pub struct InternalConfig {
    pub vault_nodes: Vec<VaultNode>,
    pub bitwarden: Bitwarden,
    pub check_interval: u64,
    pub log: Log,
}

impl TryFrom<ExternalConfig> for InternalConfig {
    type Error = Report<Error>;

    fn try_from(config: ExternalConfig) -> std::result::Result<Self, Self::Error> {
        let vault_nodes = config.vault_nodes;

        if vault_nodes.is_none() || vault_nodes.as_ref().unwrap().is_empty() {
            let report = Report::new(Error::InvalidVaultNodeUrl)
                .attach("at least one vault node must be specified");
            return Err(report);
        }

        let bitwarden = match (
            config.bitwarden.bw_host,
            config.bitwarden.bw_token,
            config.bitwarden.bw_secret_ids,
        ) {
            (Some(host), Some(token), Some(secret_ids)) => Bitwarden {
                host,
                token,
                secret_ids,
            },
            (Some(_), _, Some(secret_ids)) => {
                if secret_ids.is_empty() {
                    let report = Report::new(Error::MissingBitwardenConfig)
                        .attach("bitwarden secret ids cannot be empty");
                    return Err(report);
                }
                let report = Report::new(Error::MissingBitwardenConfig)
                    .attach("bitwarden token must be specified");
                return Err(report);
            }
            (Some(_), Some(_), None) => {
                let report = Report::new(Error::MissingBitwardenConfig)
                    .attach("bitwarden secret ids must be specified");
                return Err(report);
            }
            _ => unreachable!(),
        };

        Ok(Self {
            vault_nodes: vault_nodes.unwrap_or_default(),
            bitwarden,
            check_interval: config.check_interval.unwrap(),
            log: Log {
                level: config.log.level.unwrap(),
                json: config.log.json.unwrap(),
            },
        })
    }
}
