// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/authenticated-signer-resolution-evidence.schema.json
// sha256=8503a7d8aa20534b337f7ef622a6828cd89b4910c342ba52d76c6033b80cb38d
//
// Bindings: tools/closed-model-bindings.json
// sha256=9ae24a86bf06fbbb34b7c213750ec967f236063bb554064280a2c76cb825acb6

/// Counterpart: `authenticated-signer-resolution-evidence.schema.json#/$defs/base`.
/// Content-addressed signer resolution evidence.
///
/// `authority_commit_id` is the single revision coordinate: the evidence
/// asserts the binding as of that committed revision and carries no window,
/// no frontier, and no reusable grant. A consumer that needs a later binding
/// resolves again; it never extrapolates this one forward.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AuthenticatedSignerResolutionEvidence {
    pub signer_kind: AuthenticatedSignerKind,
    pub subject_id: DidCoreId,
    pub verification_method: DidUrl,
    pub public_key_jwk: NonEmptyJsonObject,
    pub authority_commit_id: RealmCommitId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub resolved_at: DateTime<Utc>,
}
