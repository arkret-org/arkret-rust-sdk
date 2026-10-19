// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/relation.schema.json
// sha256=b9ea3ff011ef017dd52b4644d5a9e1b2c87ca4a227313475a5d6f02641917290
//
// Input: schemas/common-ids.schema.json
// sha256=668d983321918e5b1522715d1f70774665adf7d4bfacf0e61df914f3404f6ccf
//
// Input: schemas/event-envelope.schema.json
// sha256=1f79a625c4877509174d93ec6d3090a6b322518759c978dc2c9a9b5d4f6c925c
//
// Bindings: tools/closed-model-bindings.json
// sha256=3c0dd616b73cb58355247f04ec903123c52cd61b038fe2b7df35029d0b6802c1

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
