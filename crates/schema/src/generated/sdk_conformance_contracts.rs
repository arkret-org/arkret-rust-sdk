// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/sdk-conformance-claim.schema.json
// sha256=cf354616ed143bbcade1261cc74308ccc2a4ce544f283d3253894621cb4b05e0
//
// Bindings: tools/closed-model-bindings.json
// sha256=3bfe22afd0deee9b00a0fd4b2c1e2c7eee318ee6752681d944e4cc4b38492100

/// Counterpart: `sdk-conformance-claim.schema.json#/$defs/issuer`.
/// `spec/v1/artifacts/schemas/sdk-conformance-claim.schema.json#/$defs/issuer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkClaimIssuer {
    pub id: DidCoreId,
    pub verification_method: DidUrl,
}
