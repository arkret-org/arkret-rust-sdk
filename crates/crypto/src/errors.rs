//! Crypto-machine validation errors and shared validation bounds/helpers.

use cokret_core::{Error, Result};

/// Typed crypto-machine validation errors.
///
/// Round 2 (post-improve): introduced so call sites can branch on the
/// specific validation failure (bounds vs replay vs key mismatch)
/// instead of inspecting the free-form `Error::Protocol` string. The
/// `From<CryptoError> for cokret_core::Error` impl below preserves
/// the existing wire surface — every `CryptoError` still renders as
/// `Error::Protocol(<message>)` for callers that haven't migrated.
///
/// New code SHOULD return `CryptoError` directly; bridge to
/// `cokret_core::Error` only at the protocol-boundary using `?` or
/// `Into::into`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Generic validation failure with a free-form message. Prefer one
    /// of the typed variants when the failure has structure.
    #[error("crypto validation failed: {0}")]
    Validation(String),
    /// Two values that should be identical (e.g. a binding's
    /// `verification_method` and the PSK kid it references) disagreed.
    #[error("crypto key mismatch")]
    KeyMismatch,
    /// A message-index / generation / nonce that should be strictly
    /// monotonic was observed at or below the high-water mark.
    #[error("crypto replay detected")]
    ReplayDetected,
    /// A string or collection field exceeded its declared maximum.
    #[error("crypto bound exceeded for {field}: limit {limit}")]
    BoundsExceeded {
        /// Name of the field that overflowed.
        field: String,
        /// The maximum the field is allowed to take.
        limit: usize,
    },
}

impl From<CryptoError> for Error {
    fn from(err: CryptoError) -> Self {
        // Preserve the v1 wire surface — every typed crypto error still
        // renders as `Error::Protocol(<message>)` for callers that
        // haven't migrated to matching on `CryptoError` directly.
        Self::Protocol(err.to_string())
    }
}

/// Maximum length (bytes) for serialized device/cross-signing public keys and
/// signature values. 4 KiB comfortably covers any RFC-defined public key /
/// signature format the v1 crypto suite emits.
pub const MAX_KEY_FIELD_LEN: usize = 4096;

/// Maximum length (bytes) for short identifier strings (kid, algorithm,
/// reason codes, transaction ids).
pub const MAX_IDENTIFIER_LEN: usize = 256;

/// Maximum length (bytes) for a free-form reason or label string.
pub const MAX_REASON_LEN: usize = 1024;

/// Maximum length (bytes) for an algorithm-name map key (e.g. `ed25519`).
pub const MAX_ALGORITHM_NAME_LEN: usize = 64;

/// Maximum length (bytes) for an algorithm-map value (parameter string).
pub const MAX_ALGORITHM_VALUE_LEN: usize = 256;

/// Maximum number of algorithm entries inside a single `DeviceKeyBundle`.
pub const MAX_ALGORITHMS_PER_BUNDLE: usize = 32;

/// Maximum number of one-time keys a single `OneTimeKeyClaim` may request.
/// Protects the server claim path from unbounded per-claim allocation.
pub const MAX_ONE_TIME_KEY_CLAIM_COUNT: u32 = 1000;

/// Maximum number of verification-method names attached to a single
/// `DeviceVerificationStrand`.
pub const MAX_VERIFICATION_METHODS: usize = 32;

/// Maximum number of device-quorum signatures attached to a single
/// `CrossSigningResetProof::DeviceQuorum`.
pub const MAX_DEVICE_QUORUM_SIGNATURES: usize = 256;

/// Helper: reject empty / whitespace-only key strings with a uniform error.
pub(crate) fn validate_nonempty_key(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Protocol(format!("{field} must not be empty")));
    }
    Ok(())
}

/// Helper: reject string fields above a per-field byte ceiling.
pub(crate) fn validate_max_length(field: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        return Err(Error::Protocol(format!(
            "{field} length {} exceeds {}",
            value.len(),
            max
        )));
    }
    Ok(())
}

// Note: `validate_nonempty_key` / `validate_max_length` are `pub(crate)` (they
// were file-private fns before this split) so the sibling `cross_signing`,
// `device`, and `session` modules can call them via `crate::errors::...`.
// They are intentionally NOT re-exported at crate root, preserving their
// crate-internal status.
