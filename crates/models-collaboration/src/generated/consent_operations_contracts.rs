// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/typed-current-result.schema.json
// sha256=bfee8c04c7b3d9e76727652feaa2e49488bb443f0bb99670a13dd07f2be02fe3
//
// Bindings: tools/closed-model-bindings.json
// sha256=af762bea6b5c7998721f966a440cccf3d905502ca61a6fb56cd69e1fd9203800

/// Counterpart: `typed-current-result.schema.json#/$defs/consent_value`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
/// Closed `typed-current-result.schema.json#/$defs/consent_value`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentValue {
    pub permissions: Vec<crate::events_payloads::consent::ConsentPermission>,
}
