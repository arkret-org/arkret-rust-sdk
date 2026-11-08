// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=c1b7f6c9f9f4ceb88c4b7c2924da91d09b11c7dd9ef63fe1e1097a133c1d6fe0
//
// Bindings: tools/closed-model-bindings.json
// sha256=f277aac30f4b23b2e663aeb5c59ddf9a6e2b3af9eb64854335f03d715718292a

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
