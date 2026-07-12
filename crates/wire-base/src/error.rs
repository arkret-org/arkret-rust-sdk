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
}

pub type Error = WireError;
