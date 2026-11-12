// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e57f2773764165f5a2e6047ae5491cdf152476deb73c83b2f6c14fff58925305
//
// Bindings: tools/closed-model-bindings.json
// sha256=ba1e9867d9c38f8d402c9e6bcf11c24593e800ed0ccefe6ced03bcd0bf4272ba

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
    pub max_event_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub include_member_events: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub sender_profile: Option<String>,
}
