// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/recovery-authority.schema.json
// sha256=cb347374d3fde68e8881b5db85a7866c2732d81ccf83e609d9f0114d138d62cf
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

/// Counterpart: `recovery-authority.schema.json#/$defs/recovery_completion_grant_request_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCompletionGrantRequestBody {
    pub terminal_receipt: RecoveryReceipt,
    pub initial_session: InitialSessionGrantIntent,
    pub accepted_device_possession_proof: arkret_wire::AcceptedDeviceIssuePossessionProof,
    pub canonical_request_digest: Hash,
}

/// Counterpart:
/// `recovery-authority.schema.json#/$defs/issue_recovery_completion_grant_response_body`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRecoveryCompletionGrantResponseBody {
    pub transaction_id: arkret_wire::TransactionId,
    pub issued_session: crate::session_credential::SessionGrantResponseBody,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
}
