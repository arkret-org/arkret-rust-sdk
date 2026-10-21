// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/relation.schema.json
// sha256=b9ea3ff011ef017dd52b4644d5a9e1b2c87ca4a227313475a5d6f02641917290
//
// Input: schemas/common-ids.schema.json
// sha256=14226f0ac83e4d06639ad791cc0e52e0eb1c3b128cd4c8c12308a99b795141e4
//
// Input: schemas/event-envelope.schema.json
// sha256=d2dd6d96615985bcd2130d5b87903a314e8920acdbf826c7bea54638bb291b01
//
// Bindings: tools/closed-model-bindings.json
// sha256=8f43ab7f7fe4be59fd38447b7690378c53af63212ce0eb1df8f8d25fa2a14315

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
