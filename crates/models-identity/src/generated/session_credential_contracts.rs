// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=ff3723be2839fd0ebb89296b6e3a61a209be5e24d0bbbd37b21870dd55799a39
//
// Bindings: tools/closed-model-bindings.json
// sha256=b381c96b67ab466bbb82afb539a5bf9f04c5809ca15139346195d6a0eed4e539

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
