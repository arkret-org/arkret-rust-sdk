//! Auth-layer error contract.
//!
//! This crate owns its boundary error. The enum stays thin: typed passthrough
//! for the data / signature-layer errors this crate propagates, plus
//! `Protocol` / `Crypto` for the violations it raises itself.

pub type Result<T> = std::result::Result<T, AuthError>;

/// Auth-layer error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// Auth-protocol violation carrying the reason message verbatim.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Cryptographic primitive failure (password hashing, signature or key
    /// material breakage).
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error(transparent)]
    Wire(#[from] arkret_wire::WireError),

    #[error(transparent)]
    Canonical(#[from] arkret_canonical::CanonicalError),

    #[error(transparent)]
    Identifier(#[from] arkret_wire::IdentifierError),

    #[error(transparent)]
    Signature(#[from] arkret_signatures::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
