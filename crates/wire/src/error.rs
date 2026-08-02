use thiserror::Error;

pub type Result<T> = std::result::Result<T, WireError>;

/// Errors produced while constructing or validating base wire shapes.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WireError {
    #[error("wire validation failed: {0}")]
    Protocol(String),

    #[error(transparent)]
    Canonical(#[from] arkret_canonical::CanonicalError),

    #[error(transparent)]
    Identifier(#[from] arkret_identifiers::IdentifierError),

    #[error("wire JSON conversion failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP message content is {actual} bytes, exceeding the v1 maximum of {limit} bytes")]
    BodyWireBytesExceeded { actual: usize, limit: usize },

    #[error(
        "{body_class} canonical body is {actual} bytes, exceeding the v1 maximum of {limit} bytes"
    )]
    BodyCanonicalBytesExceeded {
        body_class: &'static str,
        actual: usize,
        limit: usize,
    },
}

pub type Error = WireError;
