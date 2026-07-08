//! Object lifecycle event payloads and cell-subject helpers.

use super::*;

// ── Space lifecycle payloads ────────────────────────────────────────────

/// Typed payload for `ck.space.archive` and `ck.space.restore`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SpaceStateTransitionPayload {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
}

/// Typed payload for `ck.space.tombstone`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    pub effective_at: Option<DateTime<Utc>>,
}

/// Cell family for `ck.strand.update` / `ck.strand.tracks.update`
/// CAS-register cells. `bottom=reject` semantics — concurrent writes
/// to the same cell are not joinable (CAS contention).
pub const STRAND_FIELDS_CELL_FAMILY: &str = "ck.component.strand.metadata.v1";

/// Round 4 — build the cell_subject for `ck.strand.update`.
/// `(family=STRAND_FIELDS_CELL_FAMILY, subject=strand_id)`, CAS-register
/// semantics, bottom=reject.
pub fn strand_update_cell_subject(strand_id: &StrandId) -> String {
    strand_id.as_str().to_owned()
}

/// Round 4 — build the cell_subject for `ck.strand.tracks_patch`. Same
/// cell family and bottom semantics as [`strand_update_cell_subject`];
/// the two events share the cell so they compete via CAS rather than
/// silently overwriting each other.
pub fn strand_tracks_patch_cell_subject(strand_id: &StrandId) -> String {
    strand_id.as_str().to_owned()
}
