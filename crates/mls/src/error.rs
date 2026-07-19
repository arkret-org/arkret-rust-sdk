//! MLS behavior-layer boundary error.
//!
//! `arkret-mls` owns the OpenMLS isolation boundary, so it defines its own
//! error surface instead of leaning on the SDK facade `Error`. `Protocol` and
//! `Crypto` carry spec-level and cryptographic-primitive violations verbatim;
//! `Mls` wraps opaque OpenMLS / TLS-codec failures. The `#[from]` bridges keep
//! `?` ergonomic over the wire / canonical / identifier / JSON layers this
//! crate builds on. Downstream (`arkret-core`) keeps a `From<MlsError>` bridge
//! into its facade `Error` so existing call sites are unaffected.

use arkret_canonical::CanonicalError;
use arkret_identifiers::IdentifierError;
use arkret_wire::WireError;
use thiserror::Error;

/// Result alias for this crate's fallible MLS operations.
pub type Result<T> = std::result::Result<T, MlsError>;

/// MLS behavior-layer error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MlsError {
    /// Spec-level MLS-protocol violation carrying the reason message verbatim.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Cryptographic primitive failure (bad key material, AEAD / KDF / RNG).
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    /// Opaque OpenMLS / TLS-codec failure surfaced at the isolation boundary.
    #[error("MLS operation failed: {0}")]
    Mls(String),

    #[error(transparent)]
    Wire(#[from] WireError),

    #[error(transparent)]
    Canonical(#[from] CanonicalError),

    #[error(transparent)]
    Identifier(#[from] IdentifierError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

// The crypto crate's boundary error is flattened into this layer's surface
// (mirroring `arkret-core`'s facade bridge): typed AEAD / KDF failures collapse
// to `Protocol` / `Crypto` while the shared wire / canonical / identifier / JSON
// carriers are preserved.
impl From<arkret_crypto::Error> for MlsError {
    fn from(error: arkret_crypto::Error) -> Self {
        match error {
            arkret_crypto::Error::Protocol(message) => Self::Protocol(message),
            arkret_crypto::Error::Crypto(message) => Self::Crypto(message),
            arkret_crypto::Error::Wire(error) => Self::Wire(error),
            arkret_crypto::Error::Canonical(error) => Self::Canonical(error),
            arkret_crypto::Error::Identifier(error) => Self::Identifier(error),
            arkret_crypto::Error::Json(error) => Self::Json(error),
            other => Self::Protocol(other.to_string()),
        }
    }
}
