// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-join-intake.schema.json
// sha256=fe2be6985231d89d6aa1c1f41c19a38563ca6a06eddf5e6ba12b63757d61e590
//
// Input: schemas/realm-commit.schema.json
// sha256=6feb8f90ab444004084e457cc4c52193dbfc9d630f4739eda7712c21257af590
//
// Input: schemas/content-encryption.schema.json
// sha256=f15299dcf50eb9d402f226b2dd6829be638f416fb46629b78d24e7dbce5c5f30
//
// Input: schemas/agent-operations.schema.json
// sha256=6e3c5ec888a579f338abc03d4aa7789d04efbd445f2e0620cce10243dca5bb0c
//
// Bindings: tools/closed-model-bindings.json
// sha256=db60be1849d8bc93becf15639c6e3cafbbddfe2c4d0967db90cec73027764425

/// Counterpart: `realm-join-intake.schema.json#/$defs/peer_bootstrap_request_body`.
/// A candidate names the authority-signed RealmCommit that admitted its
/// membership. The Commit id alone addresses that admission: the bootstrap
/// answer is derived from the authority's own stream, so the request carries no
/// client-supplied Event coordinates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRealmJoinBootstrapRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub member_account_id: AccountId,
    pub membership_commit_id: RealmCommitId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub history_stream_ref: Option<CommitStreamRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub content_intent: Option<OwnedAgentContentIntent>,
}

/// Counterpart: `realm-join-intake.schema.json#/$defs/owned_agent_content_intent`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedAgentContentIntent {
    pub controller_account_id: AccountId,
    pub controller_membership_commit_id: RealmCommitId,
    pub agent_key_authorization_ref: arkret_wire::EventId,
    pub action: OwnedAgentContentAction,
    pub effective_scope: arkret_wire::ScopeRef,
    pub request_digest: arkret_wire::Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub backup_root_context: Option<arkret_models_crypto::content_history::ContentRootContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub strand_id: Option<arkret_wire::StrandId>,
}
