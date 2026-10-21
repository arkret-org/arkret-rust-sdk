// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/identity-receipt.schema.json
// sha256=3a9c3ba080d5b7d12158330e325fc7a5e9048312f012bae545d24976f018a15c
//
// Bindings: tools/closed-model-bindings.json
// sha256=ee958bb963f35540b3d330cc3731d78e388ab09c402e48014a9739bbca5c1c40

/// Counterpart: `identity-receipt.schema.json`.
/// Signed identity receipt from a DID registry
/// (`ak.schema.identity_receipt.v1`, `identity-receipt.schema.json`).
/// The registry / witness endorsement of a key-log head travels here â€”
/// never inside the key-log entry's `proofs[]`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidRegistryReceipt {
    pub schema: String,
    pub receipt_id: arkret_wire::ReceiptId,
    pub subject_did: Did,
    pub seq: u64,
    pub accepted_entry_digest: Hash,
    pub registry_id: DidCoreId,
    pub witness_role: IdentityReceiptWitnessRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub audience: Option<String>,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub signature: DetachedPayloadProof,
}
