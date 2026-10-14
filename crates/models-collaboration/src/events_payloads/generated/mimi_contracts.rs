// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=caf95541bdb218a86932033eb9da3dac2142fafa32579d115ae1f55f5f4397eb
//
// Bindings: tools/closed-model-bindings.json
// sha256=1651c7a364d583147739726313af4bcf4b1346ca585e5a19e90e50705f09898d

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
