// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/sdk-conformance-claim.schema.json
// sha256=cf354616ed143bbcade1261cc74308ccc2a4ce544f283d3253894621cb4b05e0
//
// Bindings: tools/closed-model-bindings.json
// sha256=2db9dc0b757e082d561722a2301e943a7422e79691dd5632a5a2ec129045cc3f

/// Counterpart: `sdk-conformance-claim.schema.json#/$defs/issuer`.
/// `spec/v1/artifacts/schemas/sdk-conformance-claim.schema.json#/$defs/issuer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkClaimIssuer {
    pub id: DidCoreId,
    pub verification_method: DidUrl,
}
