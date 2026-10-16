// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/service-describe.schema.json
// sha256=bcc1151a7c5c0f754205f3ee6b71876e3ea091905e83543b1ea5c9c8840ae6d7
//
// Bindings: tools/closed-model-bindings.json
// sha256=a815d160b11bd278cacb26a2d096a99bf7042e5f84772a439fcda2a7f9dedf7c

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
