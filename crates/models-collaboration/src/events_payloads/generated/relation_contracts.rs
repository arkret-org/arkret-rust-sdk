// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=9ef2ffb9153fc0557bf79eed03e5208c50205883014166111bfaded0e52c9651
//
// Bindings: tools/closed-model-bindings.json
// sha256=3d8286ffa86f9dd01d3c540d77924093bfc6e9642d4effb361307f36e3ffd625

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
