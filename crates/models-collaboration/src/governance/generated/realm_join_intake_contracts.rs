// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-join-intake.schema.json
// sha256=5f60fd349c8d1906aa85281625a05025ed25b95dabc360de6acf44842869af43
//
// Input: schemas/realm-commit.schema.json
// sha256=6feb8f90ab444004084e457cc4c52193dbfc9d630f4739eda7712c21257af590
//
// Input: schemas/agent-operations.schema.json
// sha256=9aa8e4ac8e3674122e0db9ede934930c6a5b515932794fb4e352562d8ba1cf26
//
// Bindings: tools/closed-model-bindings.json
// sha256=5c71516a86f6e77bf88bd907edc9f7002dddfcc4a5457d0ba636150543e5b28e

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
    pub strand_id: Option<arkret_wire::StrandId>,
}
