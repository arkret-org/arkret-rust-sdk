//! Object lifecycle event payloads and cell-subject helpers.
//!
//! The `arkret` umbrella re-exports these owner-defined shapes at its root.

use arkret_wire::{SemanticRef, SpaceId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Space lifecycle payloads ────────────────────────────────────────────

/// Typed payload for `ak.space.archive` and `ak.space.restore`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceStateTransitionPayload {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
}

/// Typed payload for `ak.space.tombstone`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceObjectTombstonePayload {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_event_id: Option<SemanticRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
}
