//! Typed client artifacts carried by terminal security-transaction steps.

use arkret_wire::{
    ClientStepAttestation, DeviceId, Error, Hash, Result, SchemaId,
    SecurityTransactionContinueRequest, SecurityTransactionStep, TransactionId,
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

pub type TypedClientStepAttestation = ClientStepAttestation<ClientStepAttestationArtifact>;
pub type TypedSecurityTransactionContinueRequest =
    SecurityTransactionContinueRequest<ClientStepAttestationArtifact>;
