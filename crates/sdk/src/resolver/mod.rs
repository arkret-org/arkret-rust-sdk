//! State resolution and event reduction.
//!
//! This module implements the Cokret v1 state resolution algorithm:
//! - Event reduction to compute current state
//! - Conflict resolution using HLC ordering
//! - Tombstone handling
//! - State snapshots

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Audience, Did, Error, Event, EventId, Flow, FlowId, Morph, MorphId, Place, RealmId, Relation,
    RelationId, Result,
    canonical::{canonical_json_bytes, canonical_sha256, sha256_digest},
    model::{
        OP_CONTAINER_MOVE_ITEM, OP_FLOW_ARCHIVE, OP_FLOW_CREATE, OP_FLOW_MOVE, OP_FLOW_REORDER,
        OP_FLOW_RESTORE, OP_FLOW_UPDATE, OP_MORPH_ARCHIVE, OP_MORPH_CREATE, OP_MORPH_RESTORE,
        OP_MORPH_UPDATE, OP_RELATION_CREATE, OP_RELATION_TOMBSTONE, OP_SPACE_ARCHIVE,
        OP_SPACE_CREATE, OP_SPACE_PARENT, OP_SPACE_RESTORE, OP_SPACE_TOMBSTONE, OP_SPACE_UPDATE,
        OP_VIEW_CREATE, OP_VIEW_RECONCILE, OP_VIEW_UPDATE,
    },
};

pub const REDUCER_SNAPSHOT_SCHEMA: &str = "ck.schema.reducer_snapshot.v1";
pub const REDUCER_SNAPSHOT_PROFILE: &str = "ck.reducer.v1";

mod snapshot;
mod state;
#[cfg(test)]
mod tests;

pub use snapshot::*;
pub use state::*;
