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
    pub space_id: RealmId,
    /// New ObjectState; reducers reject any transition not in the
    /// allowed FSM (see `model::primitives::ObjectState`).
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
    pub space_id: RealmId,
    pub tombstone_reason: String,
    /// Optional successor space id, if migration is offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_space_id: Option<RealmId>,
}

/// Cell family for `ck.flow.update` / `ck.flow.tracks.update`
/// CAS-register cells. `bottom=reject` semantics — concurrent writes
/// to the same cell are not joinable (CAS contention).
pub const FLOW_FIELDS_CELL_FAMILY: &str = "ck.component.flow.metadata.v1";

/// Round 4 — build the cell_subject for `ck.flow.update`.
/// `(family=FLOW_FIELDS_CELL_FAMILY, subject=flow_id)`, CAS-register
/// semantics, bottom=reject.
pub fn flow_update_cell_subject(flow_id: &FlowId) -> String {
    flow_id.as_str().to_owned()
}

/// Round 4 — build the cell_subject for `ck.flow.tracks_patch`. Same
/// cell family and bottom semantics as [`flow_update_cell_subject`];
/// the two events share the cell so they compete via CAS rather than
/// silently overwriting each other.
pub fn flow_tracks_patch_cell_subject(flow_id: &FlowId) -> String {
    flow_id.as_str().to_owned()
}
