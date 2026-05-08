use thiserror::Error;

use crate::model::ErrorEnvelope;

pub type Result<T> = std::result::Result<T, Error>;

// ── Canonical error codes (mirror of `error-code-registry.json` v2026-05-03) ─
//
// Use these constants when populating `ErrorEnvelope.code` so the wire form
// stays in sync with the canonical registry. `error_code_http_status` returns
// the registered HTTP status binding for HTTP/JSON deployments.
pub const ERROR_CODE_BAD_JSON: &str = "bad_json";
pub const ERROR_CODE_BAD_QUERY: &str = "bad_query";
pub const ERROR_CODE_SCHEMA_VIOLATION: &str = "schema_violation";
pub const ERROR_CODE_MISSING_PARAM: &str = "missing_param";
pub const ERROR_CODE_INVALID_PARAM: &str = "invalid_param";
pub const ERROR_CODE_UNAUTHENTICATED: &str = "unauthenticated";
pub const ERROR_CODE_AUTH_EXPIRED: &str = "auth_expired";
pub const ERROR_CODE_SOFT_LOGGED_OUT: &str = "soft_logged_out";
pub const ERROR_CODE_INVALID_SIGNATURE: &str = "invalid_signature";
pub const ERROR_CODE_CAPABILITY_DENIED: &str = "capability_denied";
pub const ERROR_CODE_SPACE_FROZEN: &str = "space_frozen";
pub const ERROR_CODE_CLAIM_REQUIRED: &str = "claim_required";
pub const ERROR_CODE_NOT_FOUND: &str = "not_found";
pub const ERROR_CODE_UNRECOGNIZED_ENDPOINT: &str = "unrecognized_endpoint";
pub const ERROR_CODE_METHOD_NOT_ALLOWED: &str = "method_not_allowed";
pub const ERROR_CODE_CONFLICT: &str = "conflict";
pub const ERROR_CODE_CAS_CONFLICT: &str = "cas_conflict";
pub const ERROR_CODE_CAUSAL_CONFLICT: &str = "causal_conflict";
pub const ERROR_CODE_DEPENDENCY_MISSING: &str = "dependency_missing";
pub const ERROR_CODE_DISCUSSION_TRACK_DISABLED: &str = "discussion_track_disabled";
pub const ERROR_CODE_EPOCH_MISMATCH: &str = "epoch_mismatch";
pub const ERROR_CODE_DUPLICATE_CONFLICT: &str = "duplicate_conflict";
pub const ERROR_CODE_RANK_EXHAUSTED: &str = "rank_exhausted";
pub const ERROR_CODE_HLC_LOGICAL_OVERFLOW: &str = "hlc_logical_overflow";
pub const ERROR_CODE_PAYLOAD_TOO_LARGE: &str = "payload_too_large";
pub const ERROR_CODE_DIGEST_MISMATCH: &str = "digest_mismatch";
pub const ERROR_CODE_AAD_DIGEST_MISMATCH: &str = "aad_digest_mismatch";
pub const ERROR_CODE_PAYLOAD_DIGEST_MISMATCH: &str = "payload_digest_mismatch";
pub const ERROR_CODE_KEY_UNAVAILABLE: &str = "key_unavailable";
pub const ERROR_CODE_STATE_MISMATCH: &str = "state_mismatch";
pub const ERROR_CODE_AUDIT_RECEIPT_INVALIDATED: &str = "audit_receipt_invalidated";
pub const ERROR_CODE_UNKNOWN_DID: &str = "unknown_did";
pub const ERROR_CODE_QUOTA_EXCEEDED: &str = "quota_exceeded";
pub const ERROR_CODE_RATE_LIMITED: &str = "rate_limited";
pub const ERROR_CODE_TIMEOUT: &str = "timeout";
pub const ERROR_CODE_STALE_FRONTIER: &str = "stale_frontier";
pub const ERROR_CODE_SYNC_TOKEN_EXPIRED: &str = "sync_token_expired";
pub const ERROR_CODE_UNSUPPORTED_FEATURE: &str = "unsupported_feature";
pub const ERROR_CODE_UNSUPPORTED_EVENT_KIND: &str = "unsupported_event_kind";
pub const ERROR_CODE_PROJECTION_INCOMPLETE: &str = "projection_incomplete";
pub const ERROR_CODE_INTERNAL_ERROR: &str = "internal_error";
pub const ERROR_CODE_TEMPORARILY_UNAVAILABLE: &str = "temporarily_unavailable";

/// All canonical error codes recognised by the registry. The order matches
/// `error-code-registry.json`. Use [`is_known_error_code`] before populating
/// `ErrorEnvelope.code` from arbitrary input.
pub const KNOWN_ERROR_CODES: &[&str] = &[
    ERROR_CODE_BAD_JSON,
    ERROR_CODE_BAD_QUERY,
    ERROR_CODE_SCHEMA_VIOLATION,
    ERROR_CODE_MISSING_PARAM,
    ERROR_CODE_INVALID_PARAM,
    ERROR_CODE_UNAUTHENTICATED,
    ERROR_CODE_AUTH_EXPIRED,
    ERROR_CODE_SOFT_LOGGED_OUT,
    ERROR_CODE_INVALID_SIGNATURE,
    ERROR_CODE_CAPABILITY_DENIED,
    ERROR_CODE_SPACE_FROZEN,
    ERROR_CODE_CLAIM_REQUIRED,
    ERROR_CODE_NOT_FOUND,
    ERROR_CODE_UNRECOGNIZED_ENDPOINT,
    ERROR_CODE_METHOD_NOT_ALLOWED,
    ERROR_CODE_CONFLICT,
    ERROR_CODE_CAS_CONFLICT,
    ERROR_CODE_CAUSAL_CONFLICT,
    ERROR_CODE_DEPENDENCY_MISSING,
    ERROR_CODE_DISCUSSION_TRACK_DISABLED,
    ERROR_CODE_EPOCH_MISMATCH,
    ERROR_CODE_DUPLICATE_CONFLICT,
    ERROR_CODE_RANK_EXHAUSTED,
    ERROR_CODE_HLC_LOGICAL_OVERFLOW,
    ERROR_CODE_PAYLOAD_TOO_LARGE,
    ERROR_CODE_DIGEST_MISMATCH,
    ERROR_CODE_AAD_DIGEST_MISMATCH,
    ERROR_CODE_PAYLOAD_DIGEST_MISMATCH,
    ERROR_CODE_KEY_UNAVAILABLE,
    ERROR_CODE_STATE_MISMATCH,
    ERROR_CODE_AUDIT_RECEIPT_INVALIDATED,
    ERROR_CODE_UNKNOWN_DID,
    ERROR_CODE_QUOTA_EXCEEDED,
    ERROR_CODE_RATE_LIMITED,
    ERROR_CODE_TIMEOUT,
    ERROR_CODE_STALE_FRONTIER,
    ERROR_CODE_SYNC_TOKEN_EXPIRED,
    ERROR_CODE_UNSUPPORTED_FEATURE,
    ERROR_CODE_UNSUPPORTED_EVENT_KIND,
    ERROR_CODE_PROJECTION_INCOMPLETE,
    ERROR_CODE_INTERNAL_ERROR,
    ERROR_CODE_TEMPORARILY_UNAVAILABLE,
];

/// Return `true` when `code` is a registered canonical error code.
pub fn is_known_error_code(code: &str) -> bool {
    KNOWN_ERROR_CODES.contains(&code)
}

/// Return the HTTP status binding for `code` per `error-code-registry.json`.
/// `None` when `code` is not registered (callers SHOULD reject the response).
pub fn error_code_http_status(code: &str) -> Option<u16> {
    Some(match code {
        ERROR_CODE_BAD_JSON
        | ERROR_CODE_BAD_QUERY
        | ERROR_CODE_MISSING_PARAM
        | ERROR_CODE_INVALID_PARAM => 400,
        ERROR_CODE_UNAUTHENTICATED
        | ERROR_CODE_AUTH_EXPIRED
        | ERROR_CODE_SOFT_LOGGED_OUT
        | ERROR_CODE_INVALID_SIGNATURE => 401,
        ERROR_CODE_CAPABILITY_DENIED
        | ERROR_CODE_SPACE_FROZEN
        | ERROR_CODE_CLAIM_REQUIRED
        | ERROR_CODE_QUOTA_EXCEEDED => 403,
        ERROR_CODE_NOT_FOUND | ERROR_CODE_UNRECOGNIZED_ENDPOINT => 404,
        ERROR_CODE_METHOD_NOT_ALLOWED => 405,
        ERROR_CODE_CONFLICT
        | ERROR_CODE_CAS_CONFLICT
        | ERROR_CODE_CAUSAL_CONFLICT
        | ERROR_CODE_DEPENDENCY_MISSING
        | ERROR_CODE_DISCUSSION_TRACK_DISABLED
        | ERROR_CODE_EPOCH_MISMATCH
        | ERROR_CODE_DUPLICATE_CONFLICT
        | ERROR_CODE_RANK_EXHAUSTED
        | ERROR_CODE_KEY_UNAVAILABLE
        | ERROR_CODE_STATE_MISMATCH
        | ERROR_CODE_AUDIT_RECEIPT_INVALIDATED
        | ERROR_CODE_STALE_FRONTIER
        | ERROR_CODE_PROJECTION_INCOMPLETE => 409,
        ERROR_CODE_SYNC_TOKEN_EXPIRED => 410,
        ERROR_CODE_PAYLOAD_TOO_LARGE => 413,
        ERROR_CODE_SCHEMA_VIOLATION
        | ERROR_CODE_DIGEST_MISMATCH
        | ERROR_CODE_AAD_DIGEST_MISMATCH
        | ERROR_CODE_PAYLOAD_DIGEST_MISMATCH
        | ERROR_CODE_UNKNOWN_DID => 422,
        ERROR_CODE_RATE_LIMITED => 429,
        ERROR_CODE_INTERNAL_ERROR => 500,
        ERROR_CODE_HLC_LOGICAL_OVERFLOW | ERROR_CODE_TEMPORARILY_UNAVAILABLE => 503,
        ERROR_CODE_TIMEOUT => 504,
        ERROR_CODE_UNSUPPORTED_FEATURE | ERROR_CODE_UNSUPPORTED_EVENT_KIND => 501,
        _ => return None,
    })
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid Contrix identifier: {0}")]
    InvalidId(String),

    #[error("conflicting bytes for idempotent object {0}")]
    IdempotencyConflict(String),

    #[error(
        "canonical JSON does not allow floating point or ambiguous numbers (encoding.md \
         §3.2: only integer-typed values may appear in signing inputs)"
    )]
    NonCanonicalNumber,

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

    #[cfg(feature = "client")]
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[cfg(feature = "mls")]
    #[error("MLS operation failed: {0}")]
    Mls(String),

    #[error("Contrix API returned {status}: {error}")]
    Api { status: u16, error: ErrorEnvelope },

    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<contrix_identifiers::IdentifierError> for Error {
    fn from(error: contrix_identifiers::IdentifierError) -> Self {
        match error {
            contrix_identifiers::IdentifierError::InvalidId(value) => Self::InvalidId(value),
            contrix_identifiers::IdentifierError::Random(error) => Self::Crypto(error),
        }
    }
}
