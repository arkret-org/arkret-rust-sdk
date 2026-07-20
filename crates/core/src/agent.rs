//! Agent key-pairing canonical binding helpers.
//!
//! The canonical binding-digest helpers migrated to the `arkret-signatures`
//! behavior crate ([`arkret_signatures::agent`]); this module re-exports them
//! verbatim so the historical `arkret_core::agent::*` path stays stable until
//! the phase-5 shim sweep.
pub use arkret_signatures::agent::*;
