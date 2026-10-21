// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/realm-join-intake.schema.json
// sha256=636cdf036bb6d7c6775966162aa567d39d5289016fb4c240b6e12c86791366b8
//
// Input: schemas/realm-commit.schema.json
// sha256=5429e875d095ff71e7c0d290032f96c9ac7c89714ea99fd6df70c906759ca5c4
//
// Bindings: tools/closed-model-bindings.json
// sha256=845a18ec30cf4928c1f028c2c06dbd9f098a9996b00093b60ded7690cd8ad896

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
