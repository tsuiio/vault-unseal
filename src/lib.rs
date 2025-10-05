mod bitwarden;
mod conf;
mod error;
mod shoutdown;
mod worker;

pub mod cli;

use std::path::PathBuf;
use std::sync::Arc;

use error_stack::ResultExt;
use futures::future;
use tracing::{Level, event, level_filters::LevelFilter};
use tracing_subscriber::{filter, prelude::*};

use crate::{
    bitwarden::BitwardenSecret,
    cli::Cli,
    conf::{ExternalConfig, InternalConfig},
    error::{Error, Result},
    shoutdown::Shutdown,
    worker::UnsealWorker,
};

pub async fn unseal(cfg: InternalConfig) -> Result<()> {
    event!(Level::INFO, "starting vault-unseal");

    event!(
        Level::DEBUG,
        "starting vault-unseal with config: {:#?}",
        cfg
    );

    let bitwarden_client = Arc::new(
        BitwardenSecret::new(&cfg.bitwarden.token, cfg.bitwarden.secret_ids.clone())
            .await
            .change_context(Error::BitwardenError)?,
    );
    let shutdown = Arc::new(Shutdown::new());

    let mut handles = Vec::new();
    for node in cfg.vault_nodes {
        let worker = UnsealWorker::new(
            &node.host,
            cfg.check_interval,
            bitwarden_client.clone(),
            shutdown.clone(),
        )
        .change_context(Error::WorkerError)?;

        let handle = async move {
            worker.run().await;
        };

        handles.push(handle);
    }

    future::join_all(handles).await;
    Ok(())
}

pub fn init_log(cfg: InternalConfig) -> Result<()> {
    let level: Level = cfg.log.level.into();
    let fmt = tracing_subscriber::fmt::format()
        .with_line_number(true)
        .with_ansi(true)
        .with_target(true);

    let fmt_layer = if cfg.log.json {
        tracing_subscriber::fmt::layer()
            .event_format(fmt)
            .json()
            .boxed()
    } else {
        tracing_subscriber::fmt::layer().event_format(fmt).boxed()
    };

    let filter_layer = filter::Targets::new()
        .with_target("rustify::client", LevelFilter::OFF)
        .with_target("vaultrs::api", LevelFilter::OFF)
        .with_target("rustify::endpoint", LevelFilter::OFF)
        .with_default(level);

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(filter_layer)
        .init();

    Ok(())
}

pub fn init_cfg(cli: Cli) -> Result<InternalConfig> {
    let conf_paths: Vec<PathBuf> = {
        let mut paths = Vec::new();
        if let Some(dir) = &cli.conf_dir {
            paths.extend(
                std::fs::read_dir(dir)
                    .change_context(Error::ConfigError)?
                    .filter_map(|entry| {
                        let entry = entry.unwrap();
                        if entry.path().is_file() {
                            Some(entry.path())
                        } else {
                            None
                        }
                    }),
            );
        } else {
            paths.push(cli.conf_path);
        }
        paths
    };

    let cfg: InternalConfig = ExternalConfig::figment(&conf_paths, Some(&cli.config))
        .change_context(Error::ConfigError)?
        .try_into()
        .change_context(Error::ConfigError)?;
    Ok(cfg)
}
