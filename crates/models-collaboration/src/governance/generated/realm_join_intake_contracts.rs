// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-join-intake.schema.json
// sha256=017876ee53d49e4e03cbb894250e78f79c548210d691e88103ae4db35df2d7de
//
// Input: schemas/realm-commit.schema.json
// sha256=6619ed2e2fa0e9e7c8620a7d0a53426240b5cd3cf82f1fa7f086834a355eea19
//
// Input: schemas/agent-operations.schema.json
// sha256=9aa8e4ac8e3674122e0db9ede934930c6a5b515932794fb4e352562d8ba1cf26
//
// Bindings: tools/closed-model-bindings.json
// sha256=90e21e77dae771f2c5ed933d3a57a684de6d47d3e4b73f568536e81a8e4fb8b9

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
