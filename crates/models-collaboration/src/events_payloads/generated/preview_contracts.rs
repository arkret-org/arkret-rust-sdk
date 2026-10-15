// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=bbfbef39757a86226a800089a927b95e33f25c63437c6e17c5e1abfea16072ac
//
// Bindings: tools/closed-model-bindings.json
// sha256=08dd3be10645b0c4e133fe72a1a0f80596e47ca0c707a290dcd23d1116f56607

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
