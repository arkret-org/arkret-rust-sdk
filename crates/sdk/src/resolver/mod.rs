//! State resolution and event reduction.
//!
//! This module implements the Contrix v1 state resolution algorithm:
//! - Event reduction to compute current state
//! - Conflict resolution using HLC ordering
//! - Tombstone handling
//! - State snapshots

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Audience, Did, Error, Event, EventId, Flow, FlowId, Morph, MorphId, Place, PlaceId, Relation,
    RelationId, Result, SpaceId,
    canonical::{canonical_json_bytes, canonical_sha256, sha256_digest},
    model::{
        OP_CONTAINER_MOVE_ITEM, OP_FLOW_ARCHIVE, OP_FLOW_CREATE, OP_FLOW_MOVE, OP_FLOW_REORDER,
        OP_FLOW_RESTORE, OP_FLOW_UPDATE, OP_MORPH_ARCHIVE, OP_MORPH_CREATE, OP_MORPH_RESTORE,
        OP_MORPH_UPDATE, OP_PLACE_ARCHIVE, OP_PLACE_CREATE, OP_PLACE_PARENT, OP_PLACE_RESTORE,
        OP_PLACE_TOMBSTONE, OP_PLACE_UPDATE, OP_RELATION_CREATE, OP_RELATION_DELETE,
        OP_SPACE_CHILD, OP_SPACE_CREATE, OP_SPACE_ORGANIZATION, OP_SPACE_UPDATE, OP_VIEW_CREATE,
        OP_VIEW_RECONCILE, OP_VIEW_UPDATE,
    },
};

pub const REDUCER_SNAPSHOT_SCHEMA: &str = "cx.schema.reducer_snapshot.v1";
pub const REDUCER_SNAPSHOT_PROFILE: &str = "cx.reducer.v1";

mod snapshot;
mod state;
#[cfg(test)]
mod tests;

pub use snapshot::*;
pub use state::*;
