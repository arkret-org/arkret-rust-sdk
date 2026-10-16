// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=bbfbef39757a86226a800089a927b95e33f25c63437c6e17c5e1abfea16072ac
//
// Bindings: tools/closed-model-bindings.json
// sha256=a815d160b11bd278cacb26a2d096a99bf7042e5f84772a439fcda2a7f9dedf7c

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
