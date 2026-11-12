// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/sdk-conformance-claim.schema.json
// sha256=cf354616ed143bbcade1261cc74308ccc2a4ce544f283d3253894621cb4b05e0
//
// Bindings: tools/closed-model-bindings.json
// sha256=ba1e9867d9c38f8d402c9e6bcf11c24593e800ed0ccefe6ced03bcd0bf4272ba

/// Counterpart: `sdk-conformance-claim.schema.json#/$defs/issuer`.
/// `spec/v1/artifacts/schemas/sdk-conformance-claim.schema.json#/$defs/issuer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkClaimIssuer {
    pub id: DidCoreId,
    pub verification_method: DidUrl,
}
