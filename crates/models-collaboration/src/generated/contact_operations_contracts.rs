// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/contact-operations.schema.json
// sha256=575f4385baf1becfed7377f507ce0c37639524b801e5001de2e13b430e244094
//
// Input: schemas/authz-operations.schema.json
// sha256=a77316365476c8c617f70a84a5bf3f6ee0be723b84b2f4713072cf1ed02e6832
//
// Input: schemas/string-profiles.schema.json
// sha256=aa4422be011e02a256a0cfdc072c66b15534eb8de23b76e31329982702e06e26
//
// Input: schemas/agent-operations.schema.json
// sha256=0d2950977b4b8d7c76137b107fd4dbf11401b0b1e5b480ba6ce34d31b82ad5aa
//
// Input: schemas/common-ids.schema.json
// sha256=14226f0ac83e4d06639ad791cc0e52e0eb1c3b128cd4c8c12308a99b795141e4
//
// Bindings: tools/closed-model-bindings.json
// sha256=d27aff562a6c1628ec46d4e850170d384869963a898494b561139f314ad91286

/// Counterpart: `contact-operations.schema.json#/$defs/contact_list`.
/// Viewer-specific current Contact rows.
/// `contact-operations.schema.json#/$defs/contact_list`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactList {
    pub contacts: Vec<ContactListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub next_cursor: Option<arkret_wire::Cursor>,
    pub has_more: bool,
}

/// Counterpart: `contact-operations.schema.json#/$defs/contact_agent_projection`.
/// `contact-operations.schema.json#/$defs/contact_agent_projection`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ContactAgentProjection {
    pub actor_id: ActorId,
    pub controller_account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub agent_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub direct_conversation: Option<DirectConversationSummary>,
}

/// Counterpart: `contact-operations.schema.json#/$defs/direct_conversation_summary`.
/// `contact-operations.schema.json#/$defs/direct_conversation_summary`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationSummary {
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub binding_event_ref: EventId,
    pub state: DirectConversationSummaryState,
}
