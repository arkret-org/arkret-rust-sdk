//! Signature-layer error contract.
//!
//! This crate owns its boundary error. The enum stays thin: typed passthrough
//! for the data-layer errors this crate propagates, plus `Protocol` / `Crypto`
//! for the violations it raises itself.

pub type Result<T> = std::result::Result<T, Error>;

/// Signature-layer error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Signature-protocol violation carrying the reason message verbatim.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Cryptographic primitive failure (bad key material, signing or
    /// verification breakage).
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error(transparent)]
    Wire(#[from] arkret_wire::WireError),

    #[error(transparent)]
    Canonical(#[from] arkret_canonical::CanonicalError),

    #[error(transparent)]
    Identifier(#[from] arkret_wire::IdentifierError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
