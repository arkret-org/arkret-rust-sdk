// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e57f2773764165f5a2e6047ae5491cdf152476deb73c83b2f6c14fff58925305
//
// Bindings: tools/closed-model-bindings.json
// sha256=db527b364017054646ca12898f9051885245c63852c0c52b9960a568cc897f0f

/// Counterpart:
/// `event-payload.schema.json#/$defs/mimi_room_binding_payload/properties/binding_scope`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mimi_room_binding_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRoomBindingPayloadBindingScope {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
}
