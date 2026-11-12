// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=8cab7974d8b7e149d6140a0f5b999ae7b95908d5b46f034cb36ce6580ba737cf
//
// Bindings: tools/closed-model-bindings.json
// sha256=db527b364017054646ca12898f9051885245c63852c0c52b9960a568cc897f0f

/// Counterpart: `current-state.schema.json#/$defs/consent_value`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
/// Closed `current-state.schema.json#/$defs/consent_value`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentValue {
    pub permissions: Vec<crate::events_payloads::consent::ConsentPermission>,
}
