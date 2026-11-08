// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=ad0a6afcb615a15924cab022e1c499da750e70b2f9c1bcc0cc6b25a3de3e450e
//
// Bindings: tools/closed-model-bindings.json
// sha256=c118dc80d3979cf43e74a8ebd793a80ebb67f13c08db276c8d2c87279bae1b20

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
