// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/actor-profile.schema.json
// sha256=eee46a75d88e7319719802ffd55c662f3cdab48482e547c73eb78cd15a39ed2e
//
// Input: schemas/string-profiles.schema.json
// sha256=aa4422be011e02a256a0cfdc072c66b15534eb8de23b76e31329982702e06e26
//
// Input: schemas/common-ids.schema.json
// sha256=14226f0ac83e4d06639ad791cc0e52e0eb1c3b128cd4c8c12308a99b795141e4
//
// Bindings: tools/closed-model-bindings.json
// sha256=d27aff562a6c1628ec46d4e850170d384869963a898494b561139f314ad91286

/// Counterpart: `actor-profile.schema.json#/$defs/actor_profile_definition`.
/// The closed author region of `ak.profile.create`
/// (`actor-profile.schema.json#/$defs/actor_profile_definition`).
///
/// `schema`, `realm_id`, `created_at`, `updated_by` and `updated_at` are
/// reducer derivations and `id`/`resolution` are never authored, so none of
/// them is representable here. `principal_id` and `actor_kind` are author
/// input and create-locked afterwards.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorProfileDefinition {
    pub principal_id: DidCoreId,
    pub actor_kind: ActorKind,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub agent_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_principal_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_fields: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub actor_id: Option<ActorId>,
}
