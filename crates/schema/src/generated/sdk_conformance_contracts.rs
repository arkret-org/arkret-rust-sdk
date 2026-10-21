// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/sdk-conformance-claim.schema.json
// sha256=00e7ef26b6ad616e2040ab3f32885144995918d1779d1ae2aecc3016a7156881
//
// Bindings: tools/closed-model-bindings.json
// sha256=af762bea6b5c7998721f966a440cccf3d905502ca61a6fb56cd69e1fd9203800

/// Counterpart: `sdk-conformance-claim.schema.json#/$defs/issuer`.
/// `spec/v1/artifacts/schemas/sdk-conformance-claim.schema.json#/$defs/issuer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkClaimIssuer {
    pub id: DidCoreId,
    pub verification_method: DidUrl,
}
