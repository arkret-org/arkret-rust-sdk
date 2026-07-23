//! Object lifecycle event payloads and cell-subject helpers.
//!
//! The `arkret` umbrella re-exports these owner-defined shapes at its root.

use arkret_wire::{EventRef, SpaceId, StrandId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Space lifecycle payloads ────────────────────────────────────────────

/// Typed payload for `ak.space.archive` and `ak.space.restore`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SpaceStateTransitionPayload {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub effective_at: Option<DateTime<Utc>>,
}

/// Typed payload for `ak.space.tombstone`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SpaceObjectTombstonePayload {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_space: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_event: Option<EventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub effective_at: Option<DateTime<Utc>>,
}

/// Cell family for `ak.strand.update` / `ak.strand.tracks.update`
/// CAS-register cells. `bottom=reject` semantics — concurrent writes
/// to the same cell are not joinable (CAS contention).
pub const STRAND_FIELDS_CELL_FAMILY: &str = "ak.component.strand.metadata.v1";

/// Round 4 — build the cell_subject for `ak.strand.update`.
/// `(family=STRAND_FIELDS_CELL_FAMILY, subject=strand_id)`, CAS-register
/// semantics, bottom=reject.
pub fn strand_update_cell_subject(strand_id: &StrandId) -> String {
    strand_id.as_str().to_owned()
}

/// Round 4 — build the cell_subject for `ak.strand.tracks_patch`. Same
/// cell family and bottom semantics as [`strand_update_cell_subject`];
/// the two events share the cell so they compete via CAS rather than
/// silently overwriting each other.
pub fn strand_tracks_patch_cell_subject(strand_id: &StrandId) -> String {
    strand_id.as_str().to_owned()
}
