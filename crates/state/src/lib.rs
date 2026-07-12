//! Arkret v1 state-resolution and snapshot runtime.
//!
//! Wire models and canonical encoding live in leaf crates. This crate owns
//! mutable Move/Seal reducers, in-memory stores, compaction, and snapshot
//! construction and verification.

use arkret_wire_base::*;

mod base64url {
    pub use arkret_canonical::base64url::*;
}
mod canonical {
    pub use arkret_canonical::canonical::*;
}
mod error {
    pub use arkret_wire_base::error_codes::*;
}
mod models {
    pub use arkret_wire_base::primitives::*;
}

pub mod lattice;
pub mod snapshot;
pub mod state;

pub use lattice::*;
pub use snapshot::*;
pub use state::*;
