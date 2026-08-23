//! Auth-layer error contract.
//!
//! This crate owns its boundary error. The enum stays thin: typed passthrough
//! for the wire and canonical errors this crate propagates, plus `Protocol`
//! for the violations it raises itself.

pub type Result<T> = std::result::Result<T, AuthError>;

/// Auth-layer error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// Auth-protocol violation carrying the reason message verbatim.
    #[error("protocol error: {0}")]
    Protocol(String),

    #[error(transparent)]
    Wire(#[from] arkret_wire::WireError),

    #[error(transparent)]
    Canonical(#[from] arkret_canonical::CanonicalError),

    #[error(transparent)]
    Identifier(#[from] arkret_wire::IdentifierError),
}
