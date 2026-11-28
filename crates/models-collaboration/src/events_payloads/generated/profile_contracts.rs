// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e0be2f1fb17026ba287817056b18f05dfad07ad78d0eaccde983f0860be8db95
//
// Input: schemas/account-operations.schema.json
// sha256=694f553340eeccd86deab4c0bb637d741e62e4babab325d516ffa30352ceb03d
//
// Bindings: tools/closed-model-bindings.json
// sha256=90e21e77dae771f2c5ed933d3a57a684de6d47d3e4b73f568536e81a8e4fb8b9

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
