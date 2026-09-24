//! Identity-layer error contract.
//!
//! This crate owns its boundary error. The enum stays thin: typed passthrough
//! for the data / signature-layer errors this crate propagates, plus
//! `Protocol` / `Crypto` for the violations it raises itself.

pub type Result<T> = std::result::Result<T, IdentityError>;

/// Identity-layer error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// Identity-protocol violation carrying the reason message verbatim.
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
    Signature(#[from] arkret_signatures::Error),

    /// KeyStore-backed persistence failure. Added in batch 4c when the service
    /// identity bundle backends (which wrap a `KeyStore`) moved from
    /// the `arkret` umbrella into this crate.
    #[error(transparent)]
    KeyStore(#[from] arkret_keystore::KeyStoreError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl IdentityError {
    /// Stable protocol error code when this failure carries one.
    #[must_use]
    pub const fn error_code(&self) -> Option<arkret_wire::ErrorCode> {
        match self {
            Self::Wire(error) => error.error_code(),
            _ => None,
        }
    }
}
