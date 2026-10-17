// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=32238f873daa77303a2e6cc8484e057a69a03e6735d7562183346041a6bfdcaf
//
// Bindings: tools/closed-model-bindings.json
// sha256=6fcfadb0c7e06a31e4528be5ebd9b087cda5b2394c144df9292de9b946c7d7a8

/// Counterpart: `service-operation-dtos.schema.json#/$defs/SessionGrantDeviceBinding`.
/// Authorization state committed into a standard human-device grant.
///
/// The Account Authority populates it from a Station-local revocation
/// admission record, which is the only source of the origin-derived
/// authorization Event and generation. That record deliberately carries no
/// RealmCommit witness, so this binding names the authorization Event alone —
/// it is not a `CommittedEventRef` and MUST NOT be taken from client input, a
/// local cache or a private lookup.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantDeviceBinding {
    pub device_id: DeviceId,
    pub authorization_event_id: EventId,
    pub model_generation_ref: u64,
}
