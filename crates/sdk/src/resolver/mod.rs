//! State resolution and event reduction.
//!
//! This module implements the Arkret v1 state resolution algorithm:
//! - Event reduction to compute current state
//! - Conflict resolution using HLC ordering
//! - Tombstone handling
//! - State snapshots

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{canonical_json_bytes, canonical_sha256, sha256_digest};
use crate::models::{
    OP_CONTAINER_MOVE_ITEM, OP_MORPH_ARCHIVE, OP_MORPH_CREATE, OP_MORPH_RESTORE, OP_MORPH_UPDATE,
    OP_RELATION_CREATE, OP_RELATION_TOMBSTONE, OP_SPACE_ARCHIVE, OP_SPACE_CREATE, OP_SPACE_PARENT,
    OP_SPACE_RESTORE, OP_SPACE_TOMBSTONE, OP_SPACE_UPDATE, OP_STRAND_ARCHIVE, OP_STRAND_CREATE,
    OP_STRAND_MOVE, OP_STRAND_REORDER, OP_STRAND_RESTORE, OP_STRAND_UPDATE, OP_VIEW_CREATE,
    OP_VIEW_RECONCILE, OP_VIEW_UPDATE,
};
use crate::{
    Audience, Did, Error, Event, EventId, Morph, RealmId, Relation, RelationId, Result, Space,
    SpaceId, Strand,
};

pub const REDUCER_SNAPSHOT_SCHEMA: &str = "ak.schema.reducer_snapshot.v1";
pub const REDUCER_SNAPSHOT_PROFILE: &str = "ak.reducer.v1";

mod snapshot;
mod state;
#[cfg(test)]
mod tests;

pub use snapshot::*;
pub use state::*;
