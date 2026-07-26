//! List-order event payloads.

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/list_reorder_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReorderPayloadExpectedPosition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<RelationId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReorderPayload {
    pub board_space_id: SpaceId,
    pub space_id: SpaceId,
    pub rank: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_position: Option<ListReorderPayloadExpectedPosition>,
}

// `membership_payload` now has a strong type:
// `models::operation_payloads::MembershipPayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration; carries the
// `MembershipPayloadState` enum and enforces the join/routable conditional
// required fields).
