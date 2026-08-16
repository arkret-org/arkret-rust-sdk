//! State resolution and event reduction.
//!
//! This module implements the Arkret v1 state resolution algorithm:
//! - Event reduction to compute current state
//! - Conflict resolution using HLC ordering
//! - Tombstone handling
//! - State snapshots

use std::collections::{BTreeMap, BTreeSet};

// `ResolvedStateEvent` is pure data owned by `arkret-models-collaboration`
// (read by both this reducer runtime and `arkret-policy`). Re-exported here
// so the historical `arkret_state::resolver::ResolvedStateEvent` path — and
// the SDK shim over it — stays stable.
pub use arkret_models_collaboration::ResolvedStateEvent;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{canonical_json_bytes, canonical_sha256, sha256_digest};
use crate::{
    Audience, Error, Event, EventId, Morph, RealmId, Relation, RelationId, Result, Space, SpaceId,
    Strand,
};

pub const REDUCER_SNAPSHOT_SCHEMA: &str = "org.arkret.sdk.reducer_snapshot.v1";
pub use arkret_wire::CORE_REDUCER_PROFILE as REDUCER_SNAPSHOT_PROFILE;

mod snapshot;
mod state;
#[cfg(test)]
mod tests;

pub use snapshot::*;
pub use state::*;
