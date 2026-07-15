use thiserror::Error;

pub type Result<T> = std::result::Result<T, CanonicalError>;

/// Failures produced by canonical encoding and digest primitives.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CanonicalError {
    #[error(
        "canonical JSON does not allow floating point or ambiguous numbers (encoding.md §3.2: only integer-typed values may appear in signing inputs)"
    )]
    NonCanonicalNumber,

    #[error(
        "canonical JSON integer is outside the JSON safe-integer range [-9007199254740991, 9007199254740991] (encoding.md §2)"
    )]
    NumberOutOfSafeRange,

    #[error(
        "canonical JSON object contains duplicate key {0:?} (encoding.md §2: duplicate keys MUST be rejected)"
    )]
    DuplicateObjectKey(String),

    #[error("canonical JSON contains a forbidden U+FEFF / UTF-8 BOM (encoding.md §2): {0}")]
    NonCanonicalString(String),

    #[error("canonical JSON serialization failed: {0}")]
    CanonicalJson(#[from] serde_json::Error),

    #[error("canonical encoding error: {0}")]
    Protocol(String),
}
