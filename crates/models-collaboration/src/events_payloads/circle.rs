//! Circle event payloads.

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_seal_commit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleSealCommitPayload {
    pub circle_id: CircleId,
    pub sub_seal_head_digest: Hash,
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_seals_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub committed_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleCreatePayload {
    pub object: Circle,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_member_state_payload`.
///
/// The CAS guard is tri-state per `zh/models/circle.md` §9.1: omission applies
/// no CAS and leaves legality to the transition guard, null asserts that the
/// actor has no membership record yet, and a concrete state asserts that exact
/// current membership.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleMemberStatePayload {
    pub circle_id: CircleId,
    pub actor_id: Did,
    pub membership: MembershipState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "WirePresence::is_missing")]
    pub expected_membership: WirePresence<MembershipState>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_patch_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CirclePatchPayload {
    pub circle_id: CircleId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

#[cfg(test)]
mod presence_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn circle_membership_cas_preserves_missing_null_and_value() {
        let base = json!({
            "circle_id": "ak:circle:0196419b-0000-7000-8000-000000000000",
            "actor_id": "did:web:alice.example",
            "membership": "join"
        });
        let missing: CircleMemberStatePayload = serde_json::from_value(base.clone()).unwrap();
        let mut explicit_null = base.clone();
        explicit_null["expected_membership"] = Value::Null;
        let null: CircleMemberStatePayload = serde_json::from_value(explicit_null).unwrap();
        let mut explicit_value = base;
        explicit_value["expected_membership"] = json!("invite");
        let value: CircleMemberStatePayload = serde_json::from_value(explicit_value).unwrap();

        assert_eq!(missing.expected_membership, WirePresence::Missing);
        assert_eq!(null.expected_membership, WirePresence::Null);
        assert_eq!(
            value.expected_membership,
            WirePresence::Value(MembershipState::Invite)
        );
        assert!(
            serde_json::to_value(missing)
                .unwrap()
                .get("expected_membership")
                .is_none()
        );
        assert_eq!(
            serde_json::to_value(null).unwrap()["expected_membership"],
            Value::Null
        );
    }
}
