//! Arkret v1 state-resolution and snapshot runtime.
//!
//! Wire models and canonical encoding live in leaf crates. This crate owns
//! the mutable Control Move / Seal reducers, in-memory stores, compaction, and
//! snapshot construction and verification.
//!
//! The registry-driven projection that turns an Event's `kind + payload` into
//! cell writes lives in `arkret-schema`, one layer above; every reducer entry
//! point here takes it as an injected callback rather than importing it.

// Object-model and reducer-payload vocabulary the state resolver reduces
// over. These are pure data types owned by `arkret-models-collaboration`
// (an allowed state -> models-collaboration edge); re-imported at the crate
// root so the resolver submodules can keep referring to them via `crate::`.
use arkret_identifiers::Hlc;
use arkret_models_collaboration::objects::profiles::{
    Morph, MorphMetadata, STRAND_TRACK_NAME_DISCUSSION, STRAND_TRACK_NAME_SYNTHESIS, StrandTrack,
};
use arkret_models_collaboration::objects::relation::Relation;
use arkret_models_collaboration::objects::space::Space;
use arkret_models_collaboration::objects::strand::Strand;
use arkret_wire::*;

mod base64url {
    pub use arkret_canonical::base64url::*;
}
mod canonical {
    pub use arkret_canonical::canonical::*;
}
mod generated;
mod error {
    pub use arkret_wire::error_codes::*;
}
mod models {
    pub use arkret_wire::primitives::*;
}

pub mod consent;
pub mod direct_traversal;
pub mod lattice;
pub mod mls_cells;
pub mod mls_governance_proof;
pub mod resolver;
pub mod snapshot;
pub mod state;

pub use lattice::*;
pub use snapshot::*;
pub use state::*;
