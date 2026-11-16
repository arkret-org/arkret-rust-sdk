// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/relation.schema.json
// sha256=70545ff21fc729e799002ff573e2cf03f7c6e2096ae97437583e5fbc51b981a4
//
// Input: schemas/common-ids.schema.json
// sha256=81b18acd21f4382860d5cab2384d9bb78ee5dbc23629752a6cc74ce384186149
//
// Input: schemas/event-envelope.schema.json
// sha256=2a3f8d112bfec45b9ba80a8a1dc4d6c4dbf336c02a866133f84530da585a52a1
//
// Bindings: tools/closed-model-bindings.json
// sha256=3bfe22afd0deee9b00a0fd4b2c1e2c7eee318ee6752681d944e4cc4b38492100

/// Counterpart: `relation.schema.json#/$defs/relation_definition`.
/// Closed authoring input for `ak.relation.create`.
///
/// Materialized object identity, Realm binding, effective scope, lifecycle,
/// and audit timestamps are reducer-owned and intentionally absent.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub scope_circle_id: Option<CircleId>,
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
