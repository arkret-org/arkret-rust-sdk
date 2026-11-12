// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=106ec4b74fb996d95cfd8631d60e22c1c72cc1f7d16232bebf10f21a62ff1d47
//
// Bindings: tools/closed-model-bindings.json
// sha256=14d7f312a6557af02e4e1a8496c76be3e3c902a74c9d7d175190d30caaf07567

/// Counterpart: `current-state.schema.json#/$defs/consent_value`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
/// Closed `current-state.schema.json#/$defs/consent_value`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentValue {
    pub permissions: Vec<crate::events_payloads::consent::ConsentPermission>,
}
