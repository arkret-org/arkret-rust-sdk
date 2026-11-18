// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-join-intake.schema.json
// sha256=0ee9d684775731ae52b164105cbce6362d9c088958553a2849f63e43aa08a70c
//
// Input: schemas/realm-commit.schema.json
// sha256=6feb8f90ab444004084e457cc4c52193dbfc9d630f4739eda7712c21257af590
//
// Bindings: tools/closed-model-bindings.json
// sha256=6f2298d507cfeaf587b0a77d565af971535b7d029bf667f2e4b743448bcc016f

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
}
