// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/sdk-conformance-claim.schema.json
// sha256=cf354616ed143bbcade1261cc74308ccc2a4ce544f283d3253894621cb4b05e0
//
// Bindings: tools/closed-model-bindings.json
// sha256=7eb29e3393ca0d6c4a4fe35cc4d4a9f0694ef825bf0b9fd710255bafada51f39

/// Counterpart: `sdk-conformance-claim.schema.json#/$defs/issuer`.
/// `spec/v1/artifacts/schemas/sdk-conformance-claim.schema.json#/$defs/issuer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkClaimIssuer {
    pub id: DidCoreId,
    pub verification_method: DidUrl,
}
