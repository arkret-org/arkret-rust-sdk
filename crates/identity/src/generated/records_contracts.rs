// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/identity-receipt.schema.json
// sha256=24697f76ae0229af961fcf35404196e0fcc0677398a2d3259c109bc027bd4951
//
// Bindings: tools/closed-model-bindings.json
// sha256=9ae24a86bf06fbbb34b7c213750ec967f236063bb554064280a2c76cb825acb6

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
    pub sequence: u64,
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
