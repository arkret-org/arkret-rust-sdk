use thiserror::Error;

use crate::model::ErrorEnvelope;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid Contrix identifier: {0}")]
    InvalidId(String),

    #[error("conflicting bytes for idempotent object {0}")]
    IdempotencyConflict(String),

    #[error("canonical JSON does not allow floating point or ambiguous numbers")]
    NonCanonicalNumber,

    #[error("canonical JSON serialization failed: {0}")]
    CanonicalJson(#[from] serde_json::Error),

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[cfg(feature = "client")]
    #[error("invalid service URL: {0}")]
    Url(#[from] url::ParseError),

    #[cfg(feature = "client")]
    #[error("insecure service URL is not allowed by default: {0}")]
    InsecureUrl(String),

    #[cfg(feature = "client")]
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[cfg(feature = "mls")]
    #[error("MLS operation failed: {0}")]
    Mls(String),

    #[error("Contrix API returned {status}: {error}")]
    Api { status: u16, error: ErrorEnvelope },

    #[error("protocol error: {0}")]
    Protocol(String),
}
