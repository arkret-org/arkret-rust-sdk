//! Arkret v1 state-resolution and snapshot runtime.
//!
//! Wire models and canonical encoding live in `arkret-core`. This crate owns
//! mutable Move/Seal reducers, in-memory stores, compaction, and snapshot
//! construction and verification.

use arkret_core::*;

pub mod snapshot;
pub mod state;

pub use snapshot::*;
pub use state::*;
