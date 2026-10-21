// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/authority-set-policy.schema.json
// sha256=e304e1052058555e0a06421c5fd13bbe732680dfc1f7e9f1a331d5ea935aecb0
//
// Bindings: tools/closed-model-bindings.json
// sha256=845a18ec30cf4928c1f028c2c06dbd9f098a9996b00093b60ded7690cd8ad896

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
