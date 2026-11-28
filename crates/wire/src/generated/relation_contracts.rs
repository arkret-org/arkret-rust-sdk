// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/relation.schema.json
// sha256=77aff8a642fa16313c365d604fb71f1633766593cacf33d882c8ce7be72ed2e0
//
// Input: schemas/event-envelope.schema.json
// sha256=63e18909fb55d3e68142f95c276b58ef538eea7902b9158312c89f8e8aef2365
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

/// Counterpart: `relation.schema.json#/$defs/relation_definition`.
/// Closed authoring input for `ak.relation.create`.
///
/// Materialized object identity, Realm binding, effective scope, lifecycle,
/// and audit timestamps are reducer-owned and intentionally absent.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationDefinition {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub relation_kind: RelationKind,
    pub from_ref: RelationEndpoint,
    pub to_ref: RelationEndpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
}
