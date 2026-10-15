// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/sdk-conformance-claim.schema.json
// sha256=00e7ef26b6ad616e2040ab3f32885144995918d1779d1ae2aecc3016a7156881
//
// Bindings: tools/closed-model-bindings.json
// sha256=b381c96b67ab466bbb82afb539a5bf9f04c5809ca15139346195d6a0eed4e539

/// Counterpart: `sdk-conformance-claim.schema.json#/$defs/issuer`.
/// `spec/v1/artifacts/schemas/sdk-conformance-claim.schema.json#/$defs/issuer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkClaimIssuer {
    pub id: DidCoreId,
    pub verification_method: DidUrl,
}
