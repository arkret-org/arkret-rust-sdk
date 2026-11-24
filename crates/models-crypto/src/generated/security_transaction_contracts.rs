// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/recovery-receipt.schema.json
// sha256=0d0cf1f20896bf08eec12e02211bdfda7fca52c5d9130d04c71e5306c462b7be
//
// Input: schemas/security-transaction.schema.json
// sha256=36d2c5ee8b220fadbf7ac0844341f433f4194d7cebb6d588693b551c6a71aaa3
//
// Bindings: tools/closed-model-bindings.json
// sha256=db60be1849d8bc93becf15639c6e3cafbbddfe2c4d0967db90cec73027764425

/// Counterpart: `recovery-receipt.schema.json#/properties/recovery_unit`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryUnit {
    pub predecessor_ref: RealmCommitId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = [serde_json::Value; 2])))]
    pub events: [arkret_wire::EventAdmissionSubmission; 2],
}

/// Counterpart: `security-transaction.schema.json#/$defs/recovery_create_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTransactionCreateRequestBody {
    pub kind: SecurityTransactionKind,
    pub recovery_receipt: RecoveryReceipt,
}

/// Counterpart: `security-transaction.schema.json#/$defs/recovery_transaction_completion`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTransactionCompletion {
    pub transaction_id: TransactionId,
    pub kind: SecurityTransactionKind,
    pub account_id: AccountId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub recovery_receipt: RecoveryReceipt,
    pub completion_attestation: RecoveryCompletionAttestation,
}

/// Counterpart: `security-transaction.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
#[serde(untagged)]
pub enum SecurityTransaction {
    Recovery(RecoveryTransactionCompletion),
    SecurityRotation(SecurityRotationTransaction),
}

/// Counterpart: `security-transaction.schema.json#/$defs/security_transaction_create_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
#[serde(untagged)]
pub enum SecurityTransactionCreateRequestBody {
    Recovery(RecoveryTransactionCreateRequestBody),
    SecurityRotation(SecurityRotationTransactionCreateRequestBody),
}
