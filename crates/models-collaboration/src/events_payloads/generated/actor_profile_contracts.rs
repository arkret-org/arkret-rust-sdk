// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=74e26ef25ba5846ba74149c301a7ff5c7f1afc507f2cfd207cfe0edc060507bf
//
// Input: schemas/account-operations.schema.json
// sha256=78c6503698cd43571f2b25543013f9036927ef9bfd005e71377ad3006f4a64d4
//
// Input: schemas/current-state.schema.json
// sha256=feba0ff19e227c276a3792aaed506b6534bf9ff8ce6c2e91a0ab36c04777785f
//
// Bindings: tools/closed-model-bindings.json
// sha256=9ae24a86bf06fbbb34b7c213750ec967f236063bb554064280a2c76cb825acb6

/// Counterpart: `event-payload.schema.json#/$defs/actor_profile_create_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/actor_profile_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorProfileCreatePayload {
    pub object: ActorProfileDefinition,
}

/// Counterpart: `event-payload.schema.json#/$defs/actor_profile_update_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/actor_profile_update_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorProfileUpdatePayload {
    pub target_ref: ActorProfileId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub expected_state_digest: Option<Hash>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<CurrentRevision>,
}
