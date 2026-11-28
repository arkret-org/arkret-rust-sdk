// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/authority-set-policy.schema.json
// sha256=2122246a1c4c8ae0dfdbbdb1178957bb255ccc3101dea2a1c556417fed6fd0e7
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

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
