// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/actor-profile.schema.json
// sha256=6a4500e33d8ca81d284dbb8fcba6651cc679b14e370f29fc60a37b96b07fd8a5
//
// Input: schemas/common-ids.schema.json
// sha256=0cc25a02fe0d9a94f6e41f2cf8f64e492ba36362f1e69a699cf1e684924837ee
//
// Input: schemas/string-profiles.schema.json
// sha256=aa4422be011e02a256a0cfdc072c66b15534eb8de23b76e31329982702e06e26
//
// Bindings: tools/closed-model-bindings.json
// sha256=107c58e1dbd8a2701005c9cd1dc573b3c5e861cc4f3c68403bae0ff3d579bd03

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
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<DidCoreId>,
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
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accountable_principal_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_fields: BTreeMap<String, Value>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<ActorId>,
}
