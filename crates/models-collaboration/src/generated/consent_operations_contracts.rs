// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=b3cb719af901c84d50427c0d94de8900dfb1572ee60d81cd331187225388756d
//
// Bindings: tools/closed-model-bindings.json
// sha256=dd0891cd81e0fc2caaf499fd178468a13da86ea101d8780b59ca3e5c661eeecd

/// Counterpart: `current-state.schema.json#/$defs/consent_value`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
/// Closed `current-state.schema.json#/$defs/consent_value`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentValue {
    pub permissions: Vec<crate::events_payloads::consent::ConsentPermission>,
}
