//! Typed client artifacts carried by terminal security-transaction steps.

use arkret_wire::{
    ClientStepAttestation, DeviceId, Error, Hash, Result, SchemaId, SecurityTransaction,
    SecurityTransactionStep, TransactionId,
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
    pub erase_confirmation_digest: Hash,
    pub device_id: DeviceId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub committed_at: DateTime<Utc>,
}

impl SecurityRotationLocalCommit {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::SECURITY_ROTATION_LOCAL_COMMIT_V1 {
            return Err(Error::Protocol(format!(
                "security rotation local commit schema must be {schemaid_security_rotation_local_commit_v1}",
                schemaid_security_rotation_local_commit_v1 =
                    SchemaId::SECURITY_ROTATION_LOCAL_COMMIT_V1
            )));
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
    RecoveryReceipt(RecoveryReceipt),
    SecurityRotationLocalCommit(SecurityRotationLocalCommit),
}

impl ClientStepAttestationArtifact {
    pub fn validate_for_step(&self, step: SecurityTransactionStep) -> Result<()> {
        match (step, self) {
            (SecurityTransactionStep::IssueTerminalReceipt, Self::RecoveryReceipt(receipt)) => {
                receipt.validate()
            }
            (SecurityTransactionStep::LocalCommit, Self::SecurityRotationLocalCommit(commit)) => {
                commit.validate()
            }
            _ => Err(Error::Protocol(
                "client step and typed attestation artifact disagree".to_owned(),
            )),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityTransactionContinueRequest {
    pub request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub expected_next_step: SecurityTransactionStep,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_attestation: Option<ClientStepAttestation<ClientStepAttestationArtifact>>,
}

impl SecurityTransactionContinueRequest {
    pub fn validate_for_transaction(&self, transaction: &SecurityTransaction) -> Result<()> {
        transaction.validate_continue(
            &self.request_digest,
            &self.prepared_plan_digest,
            self.expected_next_step,
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
            "expected_next_step": "publish_did_entry"
        });
        let request: SecurityTransactionContinueRequest =
            serde_json::from_value(value.clone()).unwrap();
        assert!(request.client_attestation.is_none());
        assert_eq!(serde_json::to_value(request).unwrap(), value);

        let mut unknown = value;
        unknown["legacy_step"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SecurityTransactionContinueRequest>(unknown).is_err());
    }
}
