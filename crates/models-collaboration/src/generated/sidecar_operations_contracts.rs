// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/principal-operations.schema.json
// sha256=d20daf5798bec9d03e5c36c21b63f77844c021e545c55d3d7f85ddb2377d2217
//
// Bindings: tools/closed-model-bindings.json
// sha256=90e21e77dae771f2c5ed933d3a57a684de6d47d3e4b73f568536e81a8e4fb8b9

/// Counterpart: `principal-operations.schema.json#/$defs/sidecar_stream_head`.
/// Accepted refs of one Sidecar's control stream. Only committed refs from that stream are
/// accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarStreamHead {
    pub create_event_ref: EventId,
    pub authority_refs: Vec<EventId>,
}
