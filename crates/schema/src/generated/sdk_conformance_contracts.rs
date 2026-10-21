// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/sdk-conformance-claim.schema.json
// sha256=00e7ef26b6ad616e2040ab3f32885144995918d1779d1ae2aecc3016a7156881
//
// Bindings: tools/closed-model-bindings.json
// sha256=845a18ec30cf4928c1f028c2c06dbd9f098a9996b00093b60ded7690cd8ad896

/// Counterpart: `sdk-conformance-claim.schema.json#/$defs/issuer`.
/// `spec/v1/artifacts/schemas/sdk-conformance-claim.schema.json#/$defs/issuer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkClaimIssuer {
    pub id: DidCoreId,
    pub verification_method: DidUrl,
}
