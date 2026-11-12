// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e57f2773764165f5a2e6047ae5491cdf152476deb73c83b2f6c14fff58925305
//
// Input: schemas/account-operations.schema.json
// sha256=0ae0fec5fd63dca4b9df9293eb71936cf73a3eeeae13b2268dc99699c1ed7607
//
// Bindings: tools/closed-model-bindings.json
// sha256=ba1e9867d9c38f8d402c9e6bcf11c24593e800ed0ccefe6ced03bcd0bf4272ba

/// Counterpart: `event-payload.schema.json#/$defs/profile_realm_override_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/profile_realm_override_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRealmOverridePayload {
    pub actor_profile_id: ActorProfileId,
    pub target_realm_id: RealmId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub expected_state_digest: Option<Hash>,
}
