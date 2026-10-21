// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/authenticated-signer-resolution-evidence.schema.json
// sha256=c73d83e394428b8904c887a7fa64fc18ea902a19ef0d974b7bbc3f6755c2f11c
//
// Bindings: tools/closed-model-bindings.json
// sha256=845a18ec30cf4928c1f028c2c06dbd9f098a9996b00093b60ded7690cd8ad896

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
