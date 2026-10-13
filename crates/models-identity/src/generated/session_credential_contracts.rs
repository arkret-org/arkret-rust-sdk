// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-operation-dtos.schema.json
// sha256=5c5856c68cec0bf71147d31b680eb5b1516432dcd093216dee11fc05a89fcc8b
//
// Bindings: tools/closed-model-bindings.json
// sha256=c5c717d42040392233cf38e4f3236cfeed2d38c2b642d4cf765ba04cf371a3ee

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
