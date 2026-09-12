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

mod canonical {
    pub use arkret_canonical::canonical::*;
}
mod generated;
mod error {
    pub use arkret_wire::error_codes::*;
}

pub mod consent;
pub mod direct_traversal;
pub mod history_authorization;
pub mod history_backup;
pub mod history_store;
pub mod mls_cells;
pub mod mls_governance_proof;
pub mod ordinary_history;
pub mod realm_state_snapshot;
pub mod resolver;
pub mod state;
pub mod state_model;

pub use realm_state_snapshot::*;
pub use state::*;
pub use state_model::*;
