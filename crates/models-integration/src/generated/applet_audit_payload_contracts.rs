// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=2b2d0ce9fa804d2ae258c0145cea673b09dfe7ee09e445fcfb07e6c9b23559d9
//
// Bindings: tools/closed-model-bindings.json
// sha256=c47c2cf65d6369093f5d7c6c29aaabfd64872c6277db759f4cd74b82db0a8236

/// Counterpart: `event-payload.schema.json#/$defs/applet_bridge_error_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/applet_bridge_error_payload`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletBridgeErrorPayload {
    pub applet_id: AppletId,
    pub realm_id: RealmId,
    pub failed_transaction_ref: String,
    pub error_class: AppletBridgeErrorClass,
    pub error_code: NonEmptyString,
    pub retriable: bool,
    pub visibility_scope: AppletBridgeVisibilityScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub external_ref: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub retry_after_ms: Option<u64>,
}
