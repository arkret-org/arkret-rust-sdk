// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/contact-operations.schema.json
// sha256=4ff735d490eb47144c12bb1ed07462eb1f899150006106615e2377626a3540f1
//
// Input: schemas/authz-operations.schema.json
// sha256=a77316365476c8c617f70a84a5bf3f6ee0be723b84b2f4713072cf1ed02e6832
//
// Input: schemas/string-profiles.schema.json
// sha256=aa4422be011e02a256a0cfdc072c66b15534eb8de23b76e31329982702e06e26
//
// Input: schemas/agent-operations.schema.json
// sha256=61dfc936d4795906bf2eaa2ab39f5a0ad8833d024e53eddfdd2a3500fee90e8e
//
// Input: schemas/common-ids.schema.json
// sha256=993d518acb9207f123eeb5496c0e313320ad296ab0547c308fcf3fb3bf7faa2f
//
// Bindings: tools/closed-model-bindings.json
// sha256=1651c7a364d583147739726313af4bcf4b1346ca585e5a19e90e50705f09898d

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
