use error_stack::Report;
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error")]
    ConfigError,

    #[error("bitwarden error")]
    BitwardenError,

    #[error("worker error")]
    WorkerError,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Report<Error>>;
