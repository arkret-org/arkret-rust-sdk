// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/actor-profile.schema.json
// sha256=5268a4785ce80db16852be1e2b5c8d35bea4b2d78fba1343534f9123e69d339c
//
// Input: schemas/string-profiles.schema.json
// sha256=aa4422be011e02a256a0cfdc072c66b15534eb8de23b76e31329982702e06e26
//
// Bindings: tools/closed-model-bindings.json
// sha256=a815d160b11bd278cacb26a2d096a99bf7042e5f84772a439fcda2a7f9dedf7c

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
}
