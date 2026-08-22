use arkret_models_collaboration::sync_frames::account_subscribe::AccountStreamInterrupt;
use arkret_models_collaboration::sync_frames::stream_trace::StreamTraceError;
use arkret_wire::ErrorEnvelope;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Error boundary for the umbrella `arkret` SDK.
///
/// Domain crates expose their own owner errors. This aggregate exists only at
/// the top-level SDK boundary for applications that opt into the umbrella.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid Arkret identifier: {0}")]
    InvalidId(String),

    #[error("conflicting bytes for idempotent object {0}")]
    IdempotencyConflict(String),

    #[error("canonical JSON does not allow floating point or ambiguous numbers")]
    NonCanonicalNumber,

    #[error("canonical JSON integer is outside the JSON safe-integer range")]
    NumberOutOfSafeRange,

    #[error("canonical JSON object contains duplicate key {0:?}")]
    DuplicateObjectKey(String),

    #[error("canonical JSON contains a forbidden U+FEFF / UTF-8 BOM: {0}")]
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

    #[error("account stream interrupted: {0:?}")]
    AccountStreamInterrupt(AccountStreamInterrupt),

    #[error("key-store error: {0}")]
    KeyStore(#[source] arkret_keystore::KeyStoreError),

    #[error("protocol error: {0}")]
    Protocol(String),
}

impl Error {
    pub fn is_invalid_cursor(&self) -> bool {
        let Self::Api { error, .. } = self else {
            return false;
        };

        const INVALID_CURSOR_CODES: &[&str] = &[
            "cursor_expired",
            "cursor_integrity_invalid",
            "cursor_unrecognized",
            "cursor_invalid",
            "invalid_cursor",
        ];

        let code = error.error.code.as_str();
        if INVALID_CURSOR_CODES.contains(&code) {
            return true;
        }
        if code != "param_invalid" {
            return false;
        }
        if error
            .error
            .details
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|reason| INVALID_CURSOR_CODES.contains(&reason))
        {
            return true;
        }

        let message = error.error.message.to_ascii_lowercase();
        message.contains("cursor")
            && [
                "invalid",
                "malformed",
                "expired",
                "integrity",
                "unrecognized",
            ]
            .iter()
            .any(|marker| message.contains(marker))
    }
}

impl From<arkret_keystore::KeyStoreError> for Error {
    fn from(error: arkret_keystore::KeyStoreError) -> Self {
        Self::KeyStore(error)
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
        Self::Protocol(error.to_string())
    }
}

impl From<arkret_crypto::KeyBackupError> for Error {
    fn from(error: arkret_crypto::KeyBackupError) -> Self {
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

impl From<StreamTraceError> for Error {
    fn from(error: StreamTraceError) -> Self {
        Self::Protocol(format!("stream trace {}: {error}", error.violation()))
    }
}

#[cfg(feature = "client")]
impl From<arkret_http_client::Error> for Error {
    fn from(error: arkret_http_client::Error) -> Self {
        match error {
            arkret_http_client::Error::Api { status, error } => Self::Api { status, error },
            arkret_http_client::Error::Http(message) => Self::Http(message),
            arkret_http_client::Error::InsecureUrl(message) => Self::InsecureUrl(message),
            arkret_http_client::Error::AccountStreamInterrupt(interrupt) => {
                Self::AccountStreamInterrupt(interrupt)
            }
            arkret_http_client::Error::Protocol(message) => Self::Protocol(message),
            arkret_http_client::Error::Url(source) => Self::Url(source),
            arkret_http_client::Error::Wire(source) => source.into(),
            arkret_http_client::Error::Canonical(source) => source.into(),
            arkret_http_client::Error::Signature(source) => source.into(),
            arkret_http_client::Error::Identifier(source) => source.into(),
            arkret_http_client::Error::Json(source) => source.into(),
            arkret_http_client::Error::StreamTrace(source) => source.into(),
            #[cfg(not(target_arch = "wasm32"))]
            arkret_http_client::Error::Identity(source) => source.into(),
            _ => Self::Protocol(error.to_string()),
        }
    }
}
