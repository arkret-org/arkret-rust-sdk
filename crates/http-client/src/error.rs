//! Transport-layer error and result types for the Arkret HTTP client.
//!
//! `arkret-http-client` owns the transport boundary `Error`; callers preserve
//! its structured variants instead of routing failures through a shared
//! facade.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Unified transport error for the Arkret v1 HTTP client.
///
/// `#[non_exhaustive]`: transport / protocol evolution adds variants in minor
/// releases; downstream `match` expressions MUST carry a `_` arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The service returned a non-success status with a structured
    /// problem-details envelope.
    #[error("Arkret API returned {status}: {error}")]
    Api {
        status: u16,
        error: Box<arkret_wire::ErrorEnvelope>,
    },

    /// Transport-stack failure (connect / TLS / timeout / body). The concrete
    /// stack error is stringified at the boundary.
    #[error("HTTP request failed: {0}")]
    Http(String),

    /// A service URL was rejected because it is not transport-secure and the
    /// client is configured fail-closed.
    #[error("insecure service URL is not allowed by default: {0}")]
    InsecureUrl(String),

    /// Not a transport failure: the account-subscribe stream delivered a
    /// `dropped` / `resync_required` / `unauthorized` control frame
    /// (client-sync.md §2.2). Surfaced through the error channel so
    /// cursor-owning sync loops can reconcile.
    #[error("account stream interrupted: {0:?}")]
    AccountStreamInterrupt(
        arkret_models_collaboration::sync_frames::account_subscribe::AccountStreamInterrupt,
    ),

    /// Protocol-level violation detected client-side (bad frame ordering,
    /// missing cursor, response invariant breach).
    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("invalid service URL: {0}")]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    Wire(#[from] arkret_wire::WireError),

    #[error(transparent)]
    Canonical(#[from] arkret_canonical::CanonicalError),

    #[error(transparent)]
    Signature(#[from] arkret_signatures::Error),

    #[error(transparent)]
    Identifier(#[from] arkret_wire::IdentifierError),

    #[error("JSON conversion failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    StreamTrace(#[from] arkret_models_collaboration::sync_frames::stream_trace::StreamTraceError),

    /// DID resolution failure raised by the native `HttpDidResolver`
    /// (`arkret-identity` is a native-only dependency of this crate).
    #[cfg(not(target_arch = "wasm32"))]
    #[error(transparent)]
    Identity(#[from] arkret_identity::IdentityError),
}
