use thiserror::Error;

use crate::models::ErrorEnvelope;

pub type Result<T> = std::result::Result<T, Error>;

/// Unified SDK error type.
///
/// `#[non_exhaustive]`: spec evolution (new registry codes, new failure
/// surfaces) adds variants in minor releases; downstream `match` expressions
/// MUST carry a `_` arm and treat unrecognised variants fail-closed (as an
/// error, never as success).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid Arkret identifier: {0}")]
    InvalidId(String),

    #[error("conflicting bytes for idempotent object {0}")]
    IdempotencyConflict(String),

    #[error(
        "canonical JSON does not allow floating point or ambiguous numbers (encoding.md \
         §3.2: only integer-typed values may appear in signing inputs)"
    )]
    NonCanonicalNumber,

    #[error(
        "canonical JSON integer is outside the JSON safe-integer range \
         [-9007199254740991, 9007199254740991] (encoding.md §2): values beyond this range \
         MUST be encoded as an explicitly-formatted string, not a JSON number"
    )]
    NumberOutOfSafeRange,

    #[error(
        "canonical JSON object contains duplicate key {0:?} (encoding.md §2: duplicate keys MUST be rejected)"
    )]
    DuplicateObjectKey(String),

    #[error(
        "canonical JSON contains a forbidden U+FEFF / UTF-8 BOM (encoding.md §2: any U+FEFF, \
         at stream start or inside a string value, MUST be rejected as schema_violation): {0}"
    )]
    NonCanonicalString(String),

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

    // Transport-agnostic HTTP failure. arkret-core is the wire-model /
    // canonical layer and deliberately has no dependency on a concrete HTTP
    // stack; transport adapters (arkret-http-client and any alternative
    // binding) wrap their stack-specific errors into this variant at the
    // boundary.
    #[cfg(feature = "client")]
    #[error("HTTP request failed: {0}")]
    Http(String),

    #[cfg(feature = "mls")]
    #[error("MLS operation failed: {0}")]
    Mls(String),

    #[error("Arkret API returned {status}: {error}")]
    Api {
        status: u16,
        error: Box<ErrorEnvelope>,
    },

    // Not a transport failure: the account-subscribe stream delivered a
    // `dropped` / `resync_required` / `unauthorized` control frame
    // (client-sync.md §2.2). Transports surface it through the error
    // channel so cursor-owning sync loops can reconcile (adjust/clear the
    // cursor, honor `reconnect_after_ms`) instead of silently consuming
    // past a known data loss.
    #[error("account stream interrupted: {0:?}")]
    AccountStreamInterrupt(crate::models::AccountStreamInterrupt),

    #[error("key-store error: {0}")]
    KeyStore(#[source] crate::keystore::KeyStoreError),

    #[error("protocol error: {0}")]
    Protocol(String),
}

impl Error {
    /// Return the structured key-store error when this error originated at a
    /// [`crate::keystore::KeyStore`] boundary.
    pub fn as_key_store_error(&self) -> Option<&crate::keystore::KeyStoreError> {
        match self {
            Self::KeyStore(err) => Some(err),
            _ => None,
        }
    }

    /// True when this error is a typed key-store miss.
    pub fn is_key_store_not_found(&self) -> bool {
        matches!(
            self.as_key_store_error(),
            Some(crate::keystore::KeyStoreError::NotFound { .. })
        )
    }
}

impl From<crate::keystore::KeyStoreError> for Error {
    fn from(err: crate::keystore::KeyStoreError) -> Self {
        Error::KeyStore(err)
    }
}

impl From<arkret_identifiers::IdentifierError> for Error {
    fn from(error: arkret_identifiers::IdentifierError) -> Self {
        match error {
            arkret_identifiers::IdentifierError::InvalidId(value) => Self::InvalidId(value),
            arkret_identifiers::IdentifierError::Random(error) => Self::Crypto(error),
            arkret_identifiers::IdentifierError::Protocol(message) => Self::Protocol(message),
        }
    }
}

impl From<arkret_hlc::HlcError> for Error {
    fn from(error: arkret_hlc::HlcError) -> Self {
        match error {
            arkret_hlc::HlcError::Protocol(message) => Self::Protocol(message),
            arkret_hlc::HlcError::Identifier(error) => error.into(),
            arkret_hlc::HlcError::Canonical(error) => error.into(),
        }
    }
}

impl From<arkret_event_draft::EventDraftError> for Error {
    fn from(error: arkret_event_draft::EventDraftError) -> Self {
        match error {
            arkret_event_draft::EventDraftError::Protocol(message) => Self::Protocol(message),
            arkret_event_draft::EventDraftError::Wire(error) => error.into(),
            arkret_event_draft::EventDraftError::Canonical(error) => error.into(),
            arkret_event_draft::EventDraftError::Identifier(error) => error.into(),
            arkret_event_draft::EventDraftError::Json(error) => Self::CanonicalJson(error),
        }
    }
}

impl From<arkret_canonical::CanonicalError> for Error {
    fn from(error: arkret_canonical::CanonicalError) -> Self {
        match error {
            arkret_canonical::CanonicalError::NonCanonicalNumber => Self::NonCanonicalNumber,
            arkret_canonical::CanonicalError::NumberOutOfSafeRange => Self::NumberOutOfSafeRange,
            arkret_canonical::CanonicalError::DuplicateObjectKey(key) => {
                Self::DuplicateObjectKey(key)
            }
            arkret_canonical::CanonicalError::NonCanonicalString(message) => {
                Self::NonCanonicalString(message)
            }
            arkret_canonical::CanonicalError::CanonicalJson(error) => Self::CanonicalJson(error),
            arkret_canonical::CanonicalError::Protocol(message) => Self::Protocol(message),
            _ => Self::Protocol(error.to_string()),
        }
    }
}

impl From<arkret_wire::WireError> for Error {
    fn from(error: arkret_wire::WireError) -> Self {
        match error {
            arkret_wire::WireError::Protocol(message) => Self::Protocol(message),
            arkret_wire::WireError::Canonical(error) => error.into(),
            arkret_wire::WireError::Identifier(error) => error.into(),
            arkret_wire::WireError::Json(error) => Self::CanonicalJson(error),
            _ => Self::Protocol(error.to_string()),
        }
    }
}

impl From<arkret_signatures::Error> for Error {
    fn from(error: arkret_signatures::Error) -> Self {
        match error {
            arkret_signatures::Error::Protocol(message) => Self::Protocol(message),
            arkret_signatures::Error::Crypto(message) => Self::Crypto(message),
            arkret_signatures::Error::Wire(error) => error.into(),
            arkret_signatures::Error::Canonical(error) => error.into(),
            arkret_signatures::Error::Identifier(error) => error.into(),
            arkret_signatures::Error::Json(error) => Self::CanonicalJson(error),
            _ => Self::Protocol(error.to_string()),
        }
    }
}

impl From<arkret_crypto::Error> for Error {
    fn from(error: arkret_crypto::Error) -> Self {
        match error {
            arkret_crypto::Error::Protocol(message) => Self::Protocol(message),
            arkret_crypto::Error::Crypto(message) => Self::Crypto(message),
            arkret_crypto::Error::Signature(error) => error.into(),
            arkret_crypto::Error::Wire(error) => error.into(),
            arkret_crypto::Error::Canonical(error) => error.into(),
            arkret_crypto::Error::Identifier(error) => error.into(),
            arkret_crypto::Error::Json(error) => Self::CanonicalJson(error),
            _ => Self::Protocol(error.to_string()),
        }
    }
}

impl From<arkret_crypto::CryptoError> for Error {
    fn from(error: arkret_crypto::CryptoError) -> Self {
        // Preserve the v1 wire surface: typed crypto-machine errors still
        // collapse to `Error::Protocol(<message>)` at the protocol boundary.
        Self::Protocol(error.to_string())
    }
}

impl From<arkret_crypto::KeyBackupError> for Error {
    fn from(error: arkret_crypto::KeyBackupError) -> Self {
        // Same boundary contract as `CryptoError`.
        Self::Protocol(error.to_string())
    }
}

#[cfg(feature = "mls")]
impl From<arkret_mls::MlsError> for Error {
    fn from(error: arkret_mls::MlsError) -> Self {
        match error {
            arkret_mls::MlsError::Protocol(message) => Self::Protocol(message),
            arkret_mls::MlsError::Crypto(message) => Self::Crypto(message),
            arkret_mls::MlsError::Mls(message) => Self::Mls(message),
            arkret_mls::MlsError::Wire(error) => error.into(),
            arkret_mls::MlsError::Canonical(error) => error.into(),
            arkret_mls::MlsError::Identifier(error) => error.into(),
            arkret_mls::MlsError::Json(error) => Self::CanonicalJson(error),
            _ => Self::Protocol(error.to_string()),
        }
    }
}

impl From<arkret_identity::IdentityError> for Error {
    fn from(error: arkret_identity::IdentityError) -> Self {
        match error {
            arkret_identity::IdentityError::Protocol(message) => Self::Protocol(message),
            arkret_identity::IdentityError::Crypto(message) => Self::Crypto(message),
            arkret_identity::IdentityError::Wire(error) => error.into(),
            arkret_identity::IdentityError::Canonical(error) => error.into(),
            arkret_identity::IdentityError::Identifier(error) => error.into(),
            arkret_identity::IdentityError::Signature(error) => error.into(),
            arkret_identity::IdentityError::Json(error) => Self::CanonicalJson(error),
            _ => Self::Protocol(error.to_string()),
        }
    }
}

impl From<arkret_auth::AuthError> for Error {
    fn from(error: arkret_auth::AuthError) -> Self {
        match error {
            arkret_auth::AuthError::Protocol(message) => Self::Protocol(message),
            arkret_auth::AuthError::Crypto(message) => Self::Crypto(message),
            arkret_auth::AuthError::Wire(error) => error.into(),
            arkret_auth::AuthError::Canonical(error) => error.into(),
            arkret_auth::AuthError::Identifier(error) => error.into(),
            arkret_auth::AuthError::Signature(error) => error.into(),
            arkret_auth::AuthError::Json(error) => Self::CanonicalJson(error),
            _ => Self::Protocol(error.to_string()),
        }
    }
}

impl From<arkret_schema::SchemaError> for Error {
    fn from(error: arkret_schema::SchemaError) -> Self {
        match error {
            arkret_schema::SchemaError::Protocol(message) => Self::Protocol(message),
            _ => Self::Protocol(error.to_string()),
        }
    }
}
