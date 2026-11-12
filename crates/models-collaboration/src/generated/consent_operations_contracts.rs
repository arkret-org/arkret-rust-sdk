// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=b9b2fcecf87470a1def1e55bf536bdb637b04f0e6f42083d5ed9962a80b14c61
//
// Bindings: tools/closed-model-bindings.json
// sha256=e1457ee62d38c96bf19ebec5a494f5b8b0ff175b3fda2ac3be4ca317967625e0

/// Counterpart: `current-state.schema.json#/$defs/consent_value`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
/// Closed `current-state.schema.json#/$defs/consent_value`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentValue {
    pub permissions: Vec<crate::events_payloads::consent::ConsentPermission>,
}
