//! Crypto-machine boundary error, validation errors, and shared validation
//! bounds/helpers.

/// Result alias over the crate-boundary [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Crypto-machine boundary error.
///
/// This crate owns its boundary error. The enum stays thin: typed passthrough
/// for the lower layers this crate propagates, plus `Protocol` / `Crypto` for
/// the violations it raises itself.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Crypto-protocol violation carrying the reason message verbatim.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Cryptographic primitive failure (bad key material, AEAD / KDF / RNG
    /// breakage).
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error(transparent)]
    Signature(#[from] arkret_signatures::Error),

    #[error(transparent)]
    Wire(#[from] arkret_wire::WireError),

    #[error(transparent)]
    Canonical(#[from] arkret_canonical::CanonicalError),

    #[error(transparent)]
    Identifier(#[from] arkret_wire::IdentifierError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Typed crypto-machine validation errors.
///
/// Round 2 (post-improve): introduced so call sites can branch on the
/// specific validation failure (bounds vs replay vs key mismatch)
/// instead of inspecting the free-form `Error::Protocol` string. The
/// `From<CryptoError> for Error` impl below preserves the existing wire
/// surface — every `CryptoError` still renders as
/// `Error::Protocol(<message>)` for callers that haven't migrated.
///
/// New code SHOULD return `CryptoError` directly; bridge to [`Error`]
/// only at the crate boundary using `?` or `Into::into`.
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

/// Typed key-backup / vault errors (SDK-HYG-01).
///
/// `backup.rs` previously returned `anyhow::Result` across its public API,
/// which forced downstream (SDK / FFI) to inspect free-form strings to classify
/// a failure. This enum lets callers branch on the concrete cause (KDF vs AEAD
/// vs input validation vs envelope construction) and map deterministically to
/// `FfiErrorCode` / fail-closed handling, and aligns backup with the
/// `thiserror`-based error model used by `arkret-signatures`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyBackupError {
    /// A random-number-generator call failed while filling salt / nonce / key
    /// material.
    #[error("key backup RNG failure: {0}")]
    Rng(String),
    /// Argon2 / HKDF key-derivation failure (bad params or hashing error).
    #[error("key backup key-derivation failure: {0}")]
    Kdf(String),
    /// XChaCha20-Poly1305 AEAD encrypt/decrypt failure (includes a failed
    /// authentication tag on decrypt — wrong passphrase or corrupt ciphertext).
    #[error("key backup AEAD failure: {0}")]
    Aead(String),
    /// A base64url field could not be decoded, or had the wrong decoded length.
    #[error("key backup encoding failure: {0}")]
    Encoding(String),
    /// Canonical-JSON serialization of a binding / transcript / envelope failed.
    #[error("key backup canonicalization failure: {0}")]
    Canonical(String),
    /// Caller-supplied input violated an envelope invariant (e.g. wrong
    /// `backup_kind`, malformed `backup_version`, empty `frontier_ref`).
    #[error("key backup invalid input: {0}")]
    InvalidInput(String),
}

impl From<KeyBackupError> for Error {
    fn from(err: KeyBackupError) -> Self {
        // Same boundary contract as `CryptoError`: typed at the crate edge,
        // collapses to `Error::Protocol(<message>)` at the protocol boundary.
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
