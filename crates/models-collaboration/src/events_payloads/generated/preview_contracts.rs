// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=b42ab7eb500df851ff7e7c4ad9383751d8e8dd62ccae338246d81a59bf646259
//
// Bindings: tools/closed-model-bindings.json
// sha256=14ce06e703487b8afdca6c0a5335ef346a965acc5f9443d89af8470d63109b0f

/// Counterpart:
/// `event-payload.schema.json#/$defs/preview_policy_payload/properties/value/properties/history`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/preview_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValueHistory {
    pub range: String,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub max_events: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub include_member_events: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub sender_profile: Option<String>,
}
