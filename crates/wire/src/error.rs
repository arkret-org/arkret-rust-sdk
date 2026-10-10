use thiserror::Error;

use crate::error_codes::ErrorCode;

pub type Result<T> = std::result::Result<T, WireError>;

/// Errors produced while constructing or validating base wire shapes.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WireError {
    /// A readable stream has an unexplained forward position jump. This is
    /// a local validation error, not a service problem or a new wire shape.
    #[error("stream {stream_ref:?} skipped readable position {expected}; received {actual}")]
    StreamPositionGap {
        stream_ref: crate::CommitStreamRef,
        expected: u64,
        actual: u64,
    },
    #[error("wire validation failed: {0}")]
    Protocol(String),

    /// Protocol rejection with a stable machine-readable code. Callers must
    /// dispatch on `code`, never on the human-facing `message`.
    #[error("wire validation failed [{code}]: {message}")]
    ProtocolCode { code: ErrorCode, message: String },

    #[error("event payload kind mismatch: expected {expected}, got {actual}")]
    PayloadKindMismatch {
        expected: &'static str,
        actual: String,
    },

    #[error("event payload for {kind} is invalid: {reason}")]
    PayloadInvalid { kind: &'static str, reason: String },

    #[error(transparent)]
    Canonical(#[from] arkret_canonical::CanonicalError),

    #[error(transparent)]
    Identifier(#[from] arkret_identifiers::IdentifierError),

    #[error("wire JSON conversion failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP message content is {actual} bytes, exceeding the v1 maximum of {limit} bytes")]
    BodyWireBytesExceeded { actual: usize, limit: usize },

    #[error(
        "{body_class} canonical body is {actual} bytes, exceeding the v1 maximum of {limit} bytes"
    )]
    BodyCanonicalBytesExceeded {
        body_class: &'static str,
        actual: usize,
        limit: usize,
    },
}

impl WireError {
    /// Stable error code when this validation failure defines one.
    pub const fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::ProtocolCode { code, .. } => Some(*code),
            _ => None,
        }
    }
}
