use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};

use crate::conf::ExternalConfig;

#[derive(Parser, Debug, Serialize, Deserialize)]
#[command(author, version, about ,long_about = None)]
pub struct Cli {
    /// config path
    #[arg(short, long, default_value = "./unseal.toml", group = "config")]
    pub conf_path: PathBuf,
    /// config dir
    #[arg(short = 'd', long, group = "config")]
    pub conf_dir: Option<PathBuf>,
    #[command(flatten)]
    pub config: ExternalConfig,
}
