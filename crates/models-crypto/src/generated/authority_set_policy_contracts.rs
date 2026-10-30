// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/authority-set-policy.schema.json
// sha256=117c43cd784874177c317507f281d49e5cfd2fa7c7ee136ba77abb5484697766
//
// Bindings: tools/closed-model-bindings.json
// sha256=dd0891cd81e0fc2caaf499fd178468a13da86ea101d8780b59ca3e5c661eeecd

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
