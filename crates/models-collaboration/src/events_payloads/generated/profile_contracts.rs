// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=6c0740fab50fcb796331bad41ee632e0602de445969cee69c4962e45dab65b27
//
// Input: schemas/account-operations.schema.json
// sha256=5b7dba680c2083d0bebc26ad32e7d37293d150cece8f2298a40bf382e7f31405
//
// Bindings: tools/closed-model-bindings.json
// sha256=d200bd3e6d76abd1b6154781fb5e54f11fbbc834638cdc29554f83590127fdfa

/// Counterpart: `event-payload.schema.json#/$defs/profile_realm_override_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/profile_realm_override_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRealmOverridePayload {
    pub target_ref: String,
    pub target_realm_id: RealmId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub expected_state_digest: Option<Hash>,
}
