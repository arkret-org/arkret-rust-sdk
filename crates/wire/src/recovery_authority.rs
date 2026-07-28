//! Recovery authority ticket and Account Authority DTOs.
//!
//! These types implement the B-model boundary described by
//! `zh/identity/security-transactions.md`: a Principal Server issues a
//! transaction-bound one-time ticket only after the RecoveryTransaction is
//! durable, and the Account Authority returns one byte-stable signed
//! `ak.device.authorize` Event. No recovery secret or private key belongs in
//! any type in this module.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::{
    DeviceId, Did, EventId, GrantId, Hash, PolicyId, ReceiptId, RecoveryAuthorityTicketId,
    RecoverySessionId, TransactionId, TypedTrustDomainId,
};

pub const RECOVERY_AUTHORITY_TICKET_SIGNED_FIELDS: [&str; 24] = [
    "schema",
    "ticket_id",
    "transaction_id",
    "transaction_request_digest",
    "prepared_plan_digest",
    "principal_id",
    "recovery_session_id",
    "policy_id",
    "policy_version",
    "trust_domain",
    "principal_server_id",
    "account_authority_id",
    "replacement_device_id",
    "previous_model_generation_ref",
    "result_model_generation_ref",
    "registry_previous_head",
    "did_entry_ref",
    "did_entry_digest",
    "reanchor_event_id",
    "authorize_event_id",
    "authorization_preimage_digest",
    "possession_proof_digest",
    "issued_at",
    "expires_at",
];

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalEncoding {
    CanonicalJson,
    DeterministicCbor,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPublicMaterial {
    pub canonical_encoding: CanonicalEncoding,
    pub value: Value,
    pub canonical_bytes_base64url: String,
    pub digest: Hash,
}

impl CanonicalPublicMaterial {
    pub fn validate_structural(&self) -> Result<()> {
        let bytes = arkret_canonical::base64url::base64url_decode(&self.canonical_bytes_base64url)?;
        arkret_canonical::canonical::verify_digest(&bytes, self.digest.as_str())?;
        if self.canonical_encoding == CanonicalEncoding::CanonicalJson
            && bytes != arkret_canonical::canonical::canonical_json_bytes(&self.value)?
        {
            return Err(Error::Protocol(
                "canonical public material bytes do not equal canonical JSON of value".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementDevicePossessionProof {
    pub verification_method: String,
    pub alg: String,
    pub transcript_digest: Hash,
    pub signature: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAuthorizationPreimage {
    pub principal_id: Did,
    pub replacement_device_id: DeviceId,
    pub device_public_key: String,
    pub hpke_key: String,
    pub algorithms: Vec<String>,
    pub recovery_session_id: RecoverySessionId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub trust_domain: TypedTrustDomainId,
    pub identity_model: EnrollmentAuthorityIdentityModel,
    pub previous_model_generation_ref: String,
    pub result_model_generation_ref: String,
    pub registry_previous_head: String,
    pub did_entry_ref: String,
    pub did_entry_digest: Hash,
    pub reanchor_event_id: EventId,
    pub authorize_event_id: EventId,
    pub actor_seq: u64,
    pub pre_fence_frontier_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    pub authorize_event_preimage: CanonicalPublicMaterial,
    pub possession_proof: ReplacementDevicePossessionProof,
}

impl RecoveryAuthorizationPreimage {
    pub fn validate_structural(&self) -> Result<()> {
        self.authorize_event_preimage.validate_structural()?;
        if self.algorithms.is_empty()
            || self.device_public_key.is_empty()
            || self.hpke_key.is_empty()
            || self.registry_previous_head.is_empty()
            || self.did_entry_ref.is_empty()
            || self.possession_proof.verification_method.is_empty()
            || self.possession_proof.alg.is_empty()
            || self.possession_proof.signature.is_empty()
        {
            return Err(Error::Protocol(
                "recovery authorization preimage contains an empty required value".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentAuthorityIdentityModel {
    EnrollmentAuthority,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAuthorityTicketIssueRequest {
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub authority_ticket_id: RecoveryAuthorityTicketId,
    pub expected_next_step: IssueAuthorityTicketStep,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueAuthorityTicketStep {
    IssueAuthorityTicket,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceSignatureAlgorithm {
    EdDSA,
    ES256,
    PS256,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAuthorityTicketAuthData {
    pub verification_method: String,
    pub alg: ServiceSignatureAlgorithm,
    pub signature: String,
    pub signed_fields: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAuthorityTicket {
    pub schema: String,
    pub ticket_id: RecoveryAuthorityTicketId,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub principal_id: Did,
    pub recovery_session_id: RecoverySessionId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub trust_domain: TypedTrustDomainId,
    pub principal_server_id: Did,
    pub account_authority_id: Did,
    pub replacement_device_id: DeviceId,
    pub previous_model_generation_ref: String,
    pub result_model_generation_ref: String,
    pub registry_previous_head: String,
    pub did_entry_ref: String,
    pub did_entry_digest: Hash,
    pub reanchor_event_id: EventId,
    pub authorize_event_id: EventId,
    pub authorization_preimage_digest: Hash,
    pub possession_proof_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub auth_data: RecoveryAuthorityTicketAuthData,
}

impl RecoveryAuthorityTicket {
    pub fn validate_structural(&self) -> Result<()> {
        if self.schema != "ak.schema.recovery_authority_ticket.v1" {
            return Err(Error::Protocol(
                "recovery authority ticket schema must be ak.schema.recovery_authority_ticket.v1"
                    .to_owned(),
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(Error::Protocol(
                "recovery authority ticket expires_at must be after issued_at".to_owned(),
            ));
        }
        for required in RECOVERY_AUTHORITY_TICKET_SIGNED_FIELDS {
            if !self
                .auth_data
                .signed_fields
                .iter()
                .any(|field| field == required)
            {
                return Err(Error::Protocol(format!(
                    "recovery authority ticket signed_fields must include {required}"
                )));
            }
        }
        if self.auth_data.signed_fields.len()
            != self
                .auth_data
                .signed_fields
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
        {
            return Err(Error::Protocol(
                "recovery authority ticket signed_fields must be unique".to_owned(),
            ));
        }
        if self.policy_version == 0 || self.actor_refs_are_empty() {
            return Err(Error::Protocol(
                "recovery authority ticket contains an empty policy or artifact reference"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn actor_refs_are_empty(&self) -> bool {
        self.registry_previous_head.is_empty()
            || self.did_entry_ref.is_empty()
            || self.auth_data.verification_method.is_empty()
            || self.auth_data.signature.is_empty()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAuthorityHolderProof {
    pub dpop_jkt: String,
    pub proof_jwt: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeRecoveryDeviceRequest {
    pub ticket: RecoveryAuthorityTicket,
    pub authorization_preimage: RecoveryAuthorizationPreimage,
    pub canonical_request_digest: Hash,
    pub holder_proof: RecoveryAuthorityHolderProof,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeRecoveryDeviceOutcome {
    pub ticket_id: RecoveryAuthorityTicketId,
    pub transaction_id: TransactionId,
    pub authorize_event_id: EventId,
    pub authorized_event: Value,
    pub authorized_event_digest: Hash,
    pub authority_receipt_id: ReceiptId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecoveryModelGenerationRef {
    CrossSigning(u64),
    EnrollmentAuthority(String),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromoteRecoverySessionGrantRequest {
    pub old_grant_id: GrantId,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub terminal_receipt: Value,
    pub device_authorization_event_id: EventId,
    pub result_model_generation_ref: RecoveryModelGenerationRef,
    pub canonical_request_digest: Hash,
    pub holder_proof: RecoveryAuthorityHolderProof,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromoteRecoverySessionGrantOutcome {
    pub transaction_id: TransactionId,
    pub consumed_grant_id: GrantId,
    pub new_grant: Value,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub consumed_at: DateTime<Utc>,
}
