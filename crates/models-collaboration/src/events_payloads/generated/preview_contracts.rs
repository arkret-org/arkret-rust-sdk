// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=db43f4934d4601ea90be4c1dd25628271e264c7fd7058283c6b765e30217463c
//
// Bindings: tools/closed-model-bindings.json
// sha256=af762bea6b5c7998721f966a440cccf3d905502ca61a6fb56cd69e1fd9203800

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
