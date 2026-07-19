//! Clock- and entropy-backed Arkret v1 protocol value generators.
//!
//! Home of the protocol values whose *construction* needs a wall clock or
//! an OS RNG while their *wire form* stays a plain validated string:
//!
//! - [`HlcGenerator`] — the monotonic Hybrid Logical Clock generator with future-drift tiers and
//!   Realm-scoped pseudonymous node ids. The stateless HLC value helpers (parse/compare/validate)
//!   live next to the validated `Hlc` newtype in `arkret_identifiers::hlc`.
//! - [`cursor::Cursor`] — the issuing-service mint/validate surface for `ak:cursor:` tokens (fresh
//!   ≥128-bit handles, TTL caps, clock-skew checks).

pub mod cursor;
pub mod generator;

pub use cursor::{
    CURSOR_HANDLE_MIN_LEN, Cursor, CursorPurpose, RealmSyncPosition, SyncPositions,
    generate_cursor_handle,
};
pub use generator::HlcGenerator;

/// Result alias for this crate's fallible generator and cursor operations.
pub type Result<T> = std::result::Result<T, HlcError>;

/// Errors surfaced by the HLC generator and cursor mint/validate surface.
#[derive(Debug, thiserror::Error)]
pub enum HlcError {
    /// Spec-level violation carrying the wire reason-code message verbatim
    /// (e.g. `hlc_logical_overflow: ...`, `cursor has expired`).
    #[error("{0}")]
    Protocol(String),

    #[error(transparent)]
    Identifier(#[from] arkret_identifiers::IdentifierError),

    #[error(transparent)]
    Canonical(#[from] arkret_canonical::CanonicalError),
}
