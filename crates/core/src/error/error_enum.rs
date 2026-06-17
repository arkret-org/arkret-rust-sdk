use thiserror::Error;

use crate::models::ErrorEnvelope;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid Cokret identifier: {0}")]
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

    // Transport-agnostic HTTP failure. cokret-core is the wire-model /
    // canonical layer and deliberately has no dependency on a concrete HTTP
    // stack; transport adapters (cokret-http-client and any alternative
    // binding) wrap their stack-specific errors into this variant at the
    // boundary.
    #[cfg(feature = "client")]
    #[error("HTTP request failed: {0}")]
    Http(String),

    #[cfg(feature = "mls")]
    #[error("MLS operation failed: {0}")]
    Mls(String),

    #[error("Cokret API returned {status}: {error}")]
    Api {
        status: u16,
        error: Box<ErrorEnvelope>,
    },

    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<cokret_identifiers::IdentifierError> for Error {
    fn from(error: cokret_identifiers::IdentifierError) -> Self {
        match error {
            cokret_identifiers::IdentifierError::InvalidId(value) => Self::InvalidId(value),
            cokret_identifiers::IdentifierError::Random(error) => Self::Crypto(error),
        }
    }
}
