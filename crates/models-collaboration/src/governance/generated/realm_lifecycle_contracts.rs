// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=e0be2f1fb17026ba287817056b18f05dfad07ad78d0eaccde983f0860be8db95
//
// Input: schemas/account-operations.schema.json
// sha256=694f553340eeccd86deab4c0bb637d741e62e4babab325d516ffa30352ceb03d
//
// Input: schemas/realm.schema.json
// sha256=6c54f96fef6152f72c4f69985d7e35acaaba6677e45fee5172c3e8a96138ffc7
//
// Bindings: tools/closed-model-bindings.json
// sha256=a78e63d1f3a48c87115a3e40e578dc4aeb5f619833613e5eb9fae1be319bff29

/// Counterpart: `event-payload.schema.json#/$defs/realm_join_rule_payload`.
/// Strong payload for `ak.realm.join_rule`, whose wire schema is
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_join_rule_payload`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinRulePayload {
    pub value: RealmJoinRuleValue,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_discovery_payload`.
/// Strong payload for `ak.realm.discovery`, whose wire schema is
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_discovery_payload`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDiscoveryPayload {
    pub value: RealmDiscoveryValue,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_archive_payload`.
/// Strong type for `ak.realm.archive` payloads
/// (`event-payload.schema.json#/$defs/realm_archive_payload`).
///
/// Shared closed payload for explicit archive/restore operations.
/// The registered Event kind determines the state change.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmArchivePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_tombstone_payload`.
/// Strong type for `ak.realm.tombstone` payloads
/// (`event-payload.schema.json#/$defs/realm_tombstone_payload`).
///
/// Terminal lifecycle event pointing at a successor Realm. `reason` and
/// `successor_realm_id` are both required by spec; callers without a successor
/// must use [`RealmDestroyPayload`] instead. `additionalProperties:false`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmTombstonePayload {
    pub reason: String,
    pub successor_realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub replacement_event_id: Option<ObjectRef>,
}

/// Counterpart: `event-payload.schema.json#/$defs/realm_destroy_payload`.
/// Strong type for `ak.realm.destroy` payloads
/// (`event-payload.schema.json#/$defs/realm_destroy_payload`).
///
/// Terminal lifecycle event with no successor. `reason` is required;
/// `verification_stub_required` defaults to `true` (omitted on the wire when
/// unset so the reducer applies its default). `additionalProperties:false`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDestroyPayload {
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub retention_policy_id: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub verification_stub_required: Option<bool>,
}

/// Counterpart: `event-payload.schema.json#/$defs/object_lifecycle_payload`.
/// Strong type for `object_lifecycle_payload`
/// (`event-payload.schema.json#/$defs/object_lifecycle_payload`).
///
/// Generic archive / restore / tombstone-style payload for Strand and
/// Morph lifecycle events (e.g. `ak.strand.archive` / `ak.strand.restore`). The
/// target object is single-sourced by `target_ref`. Required: `target_ref`.
/// `additionalProperties:false`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectLifecyclePayload {
    pub target_ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
}
