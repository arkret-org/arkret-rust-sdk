//! Arkret v1 state-resolution and snapshot runtime.
//!
//! Wire models and canonical encoding live in leaf crates. This crate owns
//! mutable Move/Seal reducers, in-memory stores, compaction, and snapshot
//! construction and verification.

// Object-model and reducer-payload vocabulary the state resolver reduces
// over. These are pure data types owned by `arkret-models-collaboration`
// (an allowed state -> models-collaboration edge); re-imported at the crate
// root so the resolver submodules can keep referring to them via `crate::`.
use arkret_identifiers::Hlc;
use arkret_models_collaboration::objects::profiles::{
    Morph, MorphMetadata, STRAND_TRACK_NAME_SYNTHESIS, StrandTrackConfig,
    validate_strand_track_name,
};
use arkret_models_collaboration::objects::relation::Relation;
use arkret_models_collaboration::objects::space::Space;
use arkret_models_collaboration::objects::strand::{Strand, StrandMetadata};
use arkret_wire::constants::{MORPH_SCHEMA, SPACE_SCHEMA, STRAND_SCHEMA};
use arkret_wire::*;

mod base64url {
    pub use arkret_canonical::base64url::*;
}
mod canonical {
    pub use arkret_canonical::canonical::*;
}
mod error {
    pub use arkret_wire::error_codes::*;
}
mod models {
    pub use arkret_wire::primitives::*;
}

pub mod lattice;
pub mod resolver;
pub mod snapshot;
pub mod state;

pub use lattice::*;
pub use snapshot::*;
pub use state::*;
