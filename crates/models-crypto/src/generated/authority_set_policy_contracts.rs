// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/authority-set-policy.schema.json
// sha256=117c43cd784874177c317507f281d49e5cfd2fa7c7ee136ba77abb5484697766
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc73c01cf2bfb7cc6d4969c8f2f7faa6e44275c4a585ad81f3c94ac408daab8c

/// Counterpart: `authority-set-policy.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetPolicy {
    pub schema: String,
    pub authority_set_id: String,
    pub policy_kind: AuthoritySetPolicyKind,
    pub scope_ref: ScopeRef,
    pub source_commit_id: RealmCommitId,
    pub authorization_rules: Vec<AuthoritySetAuthorizationRule>,
}
