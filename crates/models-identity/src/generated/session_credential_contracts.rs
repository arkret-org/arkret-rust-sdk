// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=54d17f55b547b2252e2405b51debd065b89fdcc79e3fa00317bfa88d05a69f96
//
// Bindings: tools/closed-model-bindings.json
// sha256=3d8286ffa86f9dd01d3c540d77924093bfc6e9642d4effb361307f36e3ffd625

/// Counterpart: `service-operation-dtos.schema.json#/$defs/SessionGrantDeviceBinding`.
/// Authorization state committed into a standard human-device grant.
///
/// The Account Authority populates it from a Station-local revocation
/// admission record, which is the only source of the origin-derived
/// authorization Event and generation. That record deliberately carries no
/// RealmCommit witness, so this binding names the authorization Event alone â€”
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
