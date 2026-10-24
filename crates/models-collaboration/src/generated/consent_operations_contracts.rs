// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=7f7c4f2664ee79f2bda622abea13f8bbb119a2387d89cbe4eeb9af4f3c087428
//
// Bindings: tools/closed-model-bindings.json
// sha256=7ef2bac74ff32b9de78cac5bb9318e8c3d600fb7d2d320e1f3fd2fa3d5a5493c

/// Counterpart: `current-state.schema.json#/$defs/consent_value`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
/// Closed `current-state.schema.json#/$defs/consent_value`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentValue {
    pub permissions: Vec<crate::events_payloads::consent::ConsentPermission>,
}
