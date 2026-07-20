//! Federation trust-domain message-signature helpers.
//!
//! The RFC 9421 transcript-fragment helper migrated to the `arkret-signatures`
//! behavior crate ([`arkret_signatures::federation`]); this module re-exports
//! it so the historical `arkret_core::` path stays stable.
pub use arkret_signatures::federation::*;
