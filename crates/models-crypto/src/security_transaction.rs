//! Typed client artifacts carried by terminal security-transaction steps.

use arkret_wire::{
    ClientStepAttestation, DeviceId, Hash, Result, SchemaId, Seal, SecurityTransaction,
    TransactionId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::RecoveryReceipt;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRotationLocalCommit {
    pub schema: String,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub local_commit_digest: Hash,
    pub device_id: DeviceId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub committed_at: DateTime<Utc>,
}

impl SecurityRotationLocalCommit {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::SECURITY_ROTATION_LOCAL_COMMIT_V1 {
            return Err(WireError::Protocol(format!(
                "security rotation local commit schema must be {schemaid_security_rotation_local_commit_v1}",
                schemaid_security_rotation_local_commit_v1 =
                    SchemaId::SECURITY_ROTATION_LOCAL_COMMIT_V1
            )));
        }
        Ok(())
    }
}

/// `ak.schema.recovery_terminal_commit.v1` — the sole client-attested terminal
/// artifact of a RecoveryTransaction.
///
/// The replacement device signs the exact first new-generation Seal frozen by
/// the prepare transaction and the recovery receipt that binds it, then
/// delivers both in one `commit_recovery_unit` continue. No other wire position
/// accepts that Seal.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTerminalCommit {
    pub first_generation_seal: Seal,
    pub recovery_receipt: RecoveryReceipt,
}

impl RecoveryTerminalCommit {
    /// `SHA-256(RFC8785_JCS(RecoveryTerminalCommit))`.
    ///
    /// One projection serves two names: the outer client step attestation's
    /// derived `attestation_digest` and the coordinator completion
    /// attestation's `terminal_commit_digest` are the same value, so a
    /// verifier that recomputes one has recomputed the other.
    pub fn terminal_commit_digest(&self) -> Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }

    /// Structural closure of the commit: both halves name the same Seal and the
    /// receipt is a complete signed `ak.schema.recovery_receipt.v1`.
    pub fn validate(&self) -> Result<()> {
        self.recovery_receipt.validate()?;
        if self.first_generation_seal.id != self.recovery_receipt.first_generation_seal_id {
            return Err(WireError::Protocol(
                "recovery terminal commit Seal id does not equal the receipt first_generation_seal_id"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
// Untagged wire union; boxing a variant changes the public constructor shape
// without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum ClientStepAttestationArtifact {
    RecoveryTerminalCommit(RecoveryTerminalCommit),
    SecurityRotationLocalCommit(SecurityRotationLocalCommit),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityTransactionContinueRequest {
    pub request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub expected_accepted_step_count: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_attestation: Option<ClientStepAttestation<ClientStepAttestationArtifact>>,
}

impl SecurityTransactionContinueRequest {
    pub fn validate_for_transaction(&self, transaction: &SecurityTransaction) -> Result<()> {
        transaction.validate_continue(
            &self.request_digest,
            &self.prepared_plan_digest,
            self.expected_accepted_step_count,
            self.client_attestation.as_ref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::SecurityTransactionContinueRequest;

    #[test]
    fn continue_request_uses_the_closed_canonical_shape() {
        let value = serde_json::json!({
            "request_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "prepared_plan_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "expected_accepted_step_count": 0
        });
        let request: SecurityTransactionContinueRequest =
            serde_json::from_value(value.clone()).unwrap();
        assert!(request.client_attestation.is_none());
        assert_eq!(serde_json::to_value(request).unwrap(), value);
    }
}
