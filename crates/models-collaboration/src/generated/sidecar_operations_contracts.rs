// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/principal-operations.schema.json
// sha256=51276d41d5ca6dde5257d686a51b678c57467c4377417653060861c8ec8fb854
//
// Bindings: tools/closed-model-bindings.json
// sha256=13aff1fc7ba8bd04dc6586b917faf46593a6d0e4beeadb69db75284c9e17a6f7

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
