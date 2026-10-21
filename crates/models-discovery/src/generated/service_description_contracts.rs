// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-describe.schema.json
// sha256=d2171ac3fc63b68bba01830d7615c2424e656e39e9d84d803dd07626d994d6f7
//
// Bindings: tools/closed-model-bindings.json
// sha256=af762bea6b5c7998721f966a440cccf3d905502ca61a6fb56cd69e1fd9203800

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
