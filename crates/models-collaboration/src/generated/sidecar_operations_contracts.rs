// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/principal-operations.schema.json
// sha256=51276d41d5ca6dde5257d686a51b678c57467c4377417653060861c8ec8fb854
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc92c416f466a595bc16d56fbbae216e8c660c38914459081d8340c5b55ebb2d

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
