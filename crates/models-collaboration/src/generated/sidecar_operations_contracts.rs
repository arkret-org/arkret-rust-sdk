// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/principal-operations.schema.json
// sha256=1a2386903398e423357f8871b00e4f242f446f6aa695af4a6df200455dc4a69b
//
// Bindings: tools/closed-model-bindings.json
// sha256=9ae24a86bf06fbbb34b7c213750ec967f236063bb554064280a2c76cb825acb6

/// Counterpart: `principal-operations.schema.json#/$defs/sidecar_stream_head`.
/// Accepted refs of one Sidecar's control stream. Circle membership and Sidecar
/// selection refs are forbidden here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarStreamHead {
    pub create_event_ref: EventId,
    pub authority_refs: Vec<EventId>,
}
