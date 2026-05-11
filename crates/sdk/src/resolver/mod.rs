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
    Audience, Did, Entity, EntityFacets, EntityId, Error, Event, EventId, Flow, FlowId, FlowKind,
    Relation, RelationId, Result, SpaceId,
    canonical::{canonical_json_bytes, canonical_sha256, sha256_digest},
    model::{
        OP_CONTAINER_MOVE_ITEM, OP_ENTITY_CREATE, OP_ENTITY_DELETE, OP_ENTITY_REDACT,
        OP_ENTITY_RESTORE, OP_ENTITY_UPDATE, OP_FIELD_POSITION_MOVE, OP_FIELD_POSITION_REORDER,
        OP_FLOW_ARCHIVE, OP_FLOW_CONVERT, OP_FLOW_CREATE, OP_FLOW_LINK_SURFACE, OP_FLOW_MOVE,
        OP_FLOW_REORDER, OP_FLOW_RESTORE, OP_FLOW_SET_PRIMARY_SURFACE, OP_FLOW_UNLINK_SURFACE,
        OP_FLOW_UPDATE, OP_RELATION_CREATE, OP_RELATION_DELETE, OP_SPACE_CHILD, OP_SPACE_CREATE,
        OP_SPACE_ORGANIZATION, OP_SPACE_UPDATE, OP_TASK_CREATE, OP_TASK_UPDATE, OP_VIEW_CREATE,
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
