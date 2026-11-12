// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-describe.schema.json
// sha256=5fea362d38889958f5f0e6e3e9ea52452b410367e467c479a4fc5138cfa0080d
//
// Bindings: tools/closed-model-bindings.json
// sha256=bb8c3350621b1f35ac031f7e6919326951b3576cd3c52db20323ba3e6e740687

/// Counterpart: `service-describe.schema.json#/properties/interop_surfaces/items`.
/// Wire-level entry in
/// [`ServiceDescribe::interop_surfaces`]. Mirrors
/// `service-describe.schema.json#/properties/interop_surfaces/items`:
/// `name` + `kind` are required and `kind` is restricted to a closed
/// enum so receivers can fast-path the dispatch.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteropSurfaceEntry {
    pub name: String,
    pub kind: InteropSurfaceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub notes: Option<String>,
}
