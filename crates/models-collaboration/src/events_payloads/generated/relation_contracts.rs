// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=36cd224e905e42c33740bf6c3c3d893497e38b5305cadc8d0fb51c1cfdba9c0d
//
// Bindings: tools/closed-model-bindings.json
// sha256=b257098f22d86bc6df1aedba2505bb77e493706f81c77fbf48be9755e324fe59

/// Counterpart: `event-payload.schema.json#/$defs/relation_create_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_create_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationCreatePayload {
    pub primary_conflict_domain: RelationPrimaryConflictDomain,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub expected_revision: Option<CurrentRevision>,
    pub relation: RelationDefinition,
}

/// Counterpart: `event-payload.schema.json#/$defs/relation_update_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_update_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationUpdatePayload {
    pub primary_conflict_domain: RelationPrimaryConflictDomain,
    pub expected_revision: CurrentRevision,
    pub patch: Patch,
    pub relation_id: RelationId,
}

/// Counterpart: `event-payload.schema.json#/$defs/relation_tombstone_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_tombstone_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationTombstonePayload {
    pub primary_conflict_domain: RelationPrimaryConflictDomain,
    pub expected_revision: CurrentRevision,
    pub relation_id: RelationId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<NonEmptyString>,
}
