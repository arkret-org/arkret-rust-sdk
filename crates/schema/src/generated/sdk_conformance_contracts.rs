// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/sdk-conformance-claim.schema.json
// sha256=00e7ef26b6ad616e2040ab3f32885144995918d1779d1ae2aecc3016a7156881
//
// Bindings: tools/closed-model-bindings.json
// sha256=ee958bb963f35540b3d330cc3731d78e388ab09c402e48014a9739bbca5c1c40

/// Counterpart: `sdk-conformance-claim.schema.json#/$defs/issuer`.
/// `spec/v1/artifacts/schemas/sdk-conformance-claim.schema.json#/$defs/issuer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkClaimIssuer {
    pub id: DidCoreId,
    pub verification_method: DidUrl,
}
