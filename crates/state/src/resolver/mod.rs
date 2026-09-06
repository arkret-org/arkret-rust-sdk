//! State resolution and event reduction.
//!
//! This module implements the Arkret v1 state resolution algorithm:
//! - Event reduction to compute current state
//! - Conflict resolution using HLC ordering
//! - Tombstone handling
//! - State snapshots

use std::collections::{BTreeMap, BTreeSet};

// `ResolvedStateEvent` is pure data owned by `arkret-models-collaboration`
// (read by both this reducer runtime and `arkret-policy`), re-exported here
// for the reducer's own callers.
pub use arkret_models_collaboration::ResolvedStateEvent;
use arkret_wire::CORE_REDUCER_PROFILE;
use serde_json::Value;

use crate::{
    Event, EventId, Morph, RealmId, Relation, RelationId, Result, Space, SpaceId, Strand, WireError,
};

mod resolved_values;
mod state;
#[cfg(test)]
mod tests;

pub use resolved_values::*;
pub use state::*;
