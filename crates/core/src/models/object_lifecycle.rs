//! Object lifecycle event payloads and cell-subject helpers.

use super::*;

// ── Space lifecycle payloads ────────────────────────────────────────────

/// Round 4 (commit 369f544) — typed payload for
/// `ck.space.archive` and `ck.space.restore`.
///
/// Reducers MUST reject the legacy top-level `target_ref` form with
/// `schema_violation` and consume this shape exclusively.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpaceStateTransitionPayload {
    pub space_id: SpaceId,
    /// New ObjectState; reducers reject any transition not in the
    /// allowed FSM (see `models::primitives::ObjectState`).
    pub new_state: ObjectState,
    /// Optional human-readable reason for the audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Round 4 — typed payload for `ck.space.tombstone`. Marks the Space
/// permanently deleted; receivers MUST surface the
/// `tombstone_event_id` to the user before purging local state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpaceObjectTombstonePayload {
    pub space_id: SpaceId,
    pub tombstone_reason: String,
    /// Optional successor space id, if migration is offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_space_id: Option<SpaceId>,
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
