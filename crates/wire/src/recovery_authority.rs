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

pub const RECOVERY_AUTHORITY_TICKET_SIGNED_FIELDS: [&str; 25] = [
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
    "recovery_holder_jkt",
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
pub const MAX_RECOVERY_AUTHORITY_TICKET_TTL_SECONDS: i64 = 300;

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
    /// Account Authority service audience fixed by the prepared plan before
    /// the Principal Server issues the transaction-bound ticket.
    pub account_authority_id: Did,
    /// RFC 7638 thumbprint copied from the Principal Server's verified
    /// recovery-session holder binding.
    pub recovery_holder_jkt: String,
    pub identity_model: EnrollmentAuthorityIdentityModel,
    pub previous_model_generation_ref: String,
    pub result_model_generation_ref: String,
    pub registry_previous_head: String,
    pub did_entry_ref: String,
    pub did_entry_digest: Hash,
    /// Candidate did:webvh entry that the Account Authority verifies in
    /// memory against the independently resolved previous history.
    pub did_entry_preimage: CanonicalPublicMaterial,
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
        self.did_entry_preimage.validate_structural()?;
        if self.did_entry_preimage.canonical_encoding != CanonicalEncoding::CanonicalJson
            || self.did_entry_preimage.digest != self.did_entry_digest
            || did_version_id(&self.principal_id, &self.registry_previous_head)
                != Some(self.previous_model_generation_ref.as_str())
            || did_version_id(&self.principal_id, &self.did_entry_ref)
                != Some(self.result_model_generation_ref.as_str())
        {
            return Err(Error::Protocol(
                "recovery DID entry preimage/ref/generation binding is invalid".to_owned(),
            ));
        }
        if self.algorithms.is_empty()
            || self.device_public_key.is_empty()
            || self.hpke_key.is_empty()
            || !valid_recovery_holder_jkt(&self.recovery_holder_jkt)
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

fn did_version_id<'a>(principal_id: &Did, reference: &'a str) -> Option<&'a str> {
    let version_id = reference
        .strip_prefix(principal_id.as_str())?
        .strip_prefix("?versionId=")?;
    (!version_id.is_empty()
        && !version_id
            .bytes()
            .any(|byte| matches!(byte, b'&' | b'#' | b'?')))
    .then_some(version_id)
}

fn valid_recovery_holder_jkt(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
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
    pub recovery_holder_jkt: String,
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
        if (self.expires_at - self.issued_at).num_seconds()
            > MAX_RECOVERY_AUTHORITY_TICKET_TTL_SECONDS
        {
            return Err(Error::Protocol(format!(
                "recovery authority ticket TTL exceeds {MAX_RECOVERY_AUTHORITY_TICKET_TTL_SECONDS} seconds"
            )));
        }
        if self
            .auth_data
            .signed_fields
            .iter()
            .map(String::as_str)
            .ne(RECOVERY_AUTHORITY_TICKET_SIGNED_FIELDS)
        {
            return Err(Error::Protocol(
                "recovery authority ticket signed_fields must equal the registered ordered set"
                    .to_owned(),
            ));
        }
        if self.policy_version == 0 || self.actor_refs_are_empty() {
            return Err(Error::Protocol(
                "recovery authority ticket contains an empty policy or artifact reference"
                    .to_owned(),
            ));
        }
        if !valid_recovery_holder_jkt(&self.recovery_holder_jkt) {
            return Err(Error::Protocol(
                "recovery authority ticket recovery_holder_jkt must be a SHA-256 JWK thumbprint"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical signature transcript: the closed projection of the 24
    /// registered top-level fields. `auth_data` is intentionally excluded so
    /// the signature never contains itself.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        let object = value.as_object().ok_or_else(|| {
            Error::Protocol("recovery authority ticket must serialize as an object".to_owned())
        })?;
        let projection = RECOVERY_AUTHORITY_TICKET_SIGNED_FIELDS
            .iter()
            .map(|field| {
                object
                    .get(*field)
                    .cloned()
                    .map(|value| ((*field).to_owned(), value))
                    .ok_or_else(|| {
                        Error::Protocol(format!(
                            "recovery authority ticket is missing signed field {field}"
                        ))
                    })
            })
            .collect::<Result<serde_json::Map<String, Value>>>()?;
        Ok(arkret_canonical::canonical::canonical_json_bytes(
            &Value::Object(projection),
        )?)
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

fn request_digest_without_proof_jwt<T: Serialize>(request: &T) -> Result<Hash> {
    let mut value = serde_json::to_value(request)?;
    let object = value.as_object_mut().ok_or_else(|| {
        Error::Protocol("recovery authority request must serialize as an object".to_owned())
    })?;
    object.remove("canonical_request_digest");
    let holder_proof = object
        .get_mut("holder_proof")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            Error::Protocol(
                "recovery authority request holder_proof must serialize as an object".to_owned(),
            )
        })?;
    holder_proof.remove("proof_jwt");
    let bytes = arkret_canonical::canonical::canonical_json_bytes(&value)?;
    Ok(Hash::new(arkret_canonical::canonical::sha256_digest(
        &bytes,
    ))?)
}

impl AuthorizeRecoveryDeviceRequest {
    pub fn expected_canonical_request_digest(&self) -> Result<Hash> {
        request_digest_without_proof_jwt(self)
    }

    pub fn validate_structural(&self) -> Result<()> {
        self.ticket.validate_structural()?;
        self.authorization_preimage.validate_structural()?;
        let preimage = &self.authorization_preimage;
        let ticket = &self.ticket;
        if ticket.principal_id != preimage.principal_id
            || ticket.recovery_session_id != preimage.recovery_session_id
            || ticket.policy_id != preimage.policy_id
            || ticket.policy_version != preimage.policy_version
            || ticket.trust_domain != preimage.trust_domain
            || ticket.account_authority_id != preimage.account_authority_id
            || ticket.recovery_holder_jkt != preimage.recovery_holder_jkt
            || ticket.replacement_device_id != preimage.replacement_device_id
            || ticket.previous_model_generation_ref != preimage.previous_model_generation_ref
            || ticket.result_model_generation_ref != preimage.result_model_generation_ref
            || ticket.registry_previous_head != preimage.registry_previous_head
            || ticket.did_entry_ref != preimage.did_entry_ref
            || ticket.did_entry_digest != preimage.did_entry_digest
            || ticket.reanchor_event_id != preimage.reanchor_event_id
            || ticket.authorize_event_id != preimage.authorize_event_id
        {
            return Err(Error::Protocol(
                "recovery authority ticket and authorization preimage binding disagree".to_owned(),
            ));
        }
        if self.holder_proof.dpop_jkt != ticket.recovery_holder_jkt {
            return Err(Error::Protocol(
                "holder_proof.dpop_jkt does not equal the ticket-bound recovery holder".to_owned(),
            ));
        }
        let preimage_bytes =
            arkret_canonical::canonical::canonical_json_bytes(&self.authorization_preimage)?;
        arkret_canonical::canonical::verify_digest(
            &preimage_bytes,
            ticket.authorization_preimage_digest.as_str(),
        )?;
        let possession_proof_bytes =
            arkret_canonical::canonical::canonical_json_bytes(&preimage.possession_proof)?;
        arkret_canonical::canonical::verify_digest(
            &possession_proof_bytes,
            ticket.possession_proof_digest.as_str(),
        )?;
        if self.expected_canonical_request_digest()? != self.canonical_request_digest {
            return Err(Error::Protocol(
                "canonical_request_digest does not equal the canonical request projection"
                    .to_owned(),
            ));
        }
        Ok(())
    }
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

impl PromoteRecoverySessionGrantRequest {
    pub fn expected_canonical_request_digest(&self) -> Result<Hash> {
        request_digest_without_proof_jwt(self)
    }

    pub fn validate_structural(&self) -> Result<()> {
        if self.expected_canonical_request_digest()? != self.canonical_request_digest {
            return Err(Error::Protocol(
                "canonical_request_digest does not equal the canonical request projection"
                    .to_owned(),
            ));
        }
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    #[test]
    fn promotion_request_digest_excludes_digest_and_proof_jwt() {
        let mut request = PromoteRecoverySessionGrantRequest {
            old_grant_id: GrantId::new("ak:grant:019a7360-0000-7000-8000-000000000001".to_owned())
                .unwrap(),
            transaction_id: TransactionId::new(
                "ak:transaction:019a7360-0000-7000-8000-000000000002".to_owned(),
            )
            .unwrap(),
            transaction_request_digest: hash('1'),
            terminal_receipt: json!({"receipt_id": "ak:receipt:019a7360-0000-7000-8000-000000000003"}),
            device_authorization_event_id: EventId::new(
                "ak:event:019a7360-0000-7000-8000-000000000004".to_owned(),
            )
            .unwrap(),
            result_model_generation_ref: RecoveryModelGenerationRef::CrossSigning(7),
            canonical_request_digest: hash('0'),
            holder_proof: RecoveryAuthorityHolderProof {
                dpop_jkt: "holder-thumbprint".to_owned(),
                proof_jwt: "holder-proof".to_owned(),
            },
        };

        let expected = request.expected_canonical_request_digest().unwrap();
        request.canonical_request_digest = hash('9');
        assert_eq!(
            request.expected_canonical_request_digest().unwrap(),
            expected,
            "the digest field must not recursively affect its own projection"
        );
        request.holder_proof.proof_jwt = "different-holder-proof".to_owned();
        assert_eq!(
            request.expected_canonical_request_digest().unwrap(),
            expected,
            "proof_jwt signs the digest and must be excluded to avoid self-reference"
        );
        request.holder_proof.dpop_jkt = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned();
        assert_ne!(
            request.expected_canonical_request_digest().unwrap(),
            expected,
            "the holder JKT must remain covered by the canonical projection"
        );
    }

    fn ticket() -> RecoveryAuthorityTicket {
        serde_json::from_value(json!({
            "schema": "ak.schema.recovery_authority_ticket.v1",
            "ticket_id": "ak:recovery_authority_ticket:019a7360-0000-7000-8000-000000000011",
            "transaction_id": "ak:transaction:019a7360-0000-7000-8000-000000000012",
            "transaction_request_digest": hash('1'),
            "prepared_plan_digest": hash('2'),
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "recovery_session_id": "ak:recovery_session:019a7360-0000-7000-8000-000000000013",
            "policy_id": "ak:policy:019a7360-0000-7000-8000-000000000014",
            "policy_version": 3,
            "trust_domain": "ak:trust_domain:example.local",
            "principal_server_id": "did:web:principal.example",
            "account_authority_id": "did:web:accounts.example",
            "recovery_holder_jkt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "replacement_device_id": "ak:device:019a7360-0000-7000-8000-000000000015",
            "previous_model_generation_ref": "1-genesis",
            "result_model_generation_ref": "2-recovery",
            "registry_previous_head": "did:webvh:z6mkfixture:alice.example?versionId=1-genesis",
            "did_entry_ref": "did:webvh:z6mkfixture:alice.example?versionId=2-recovery",
            "did_entry_digest": hash('3'),
            "reanchor_event_id": "ak:event:019a7360-0000-7000-8000-000000000016",
            "authorize_event_id": "ak:event:019a7360-0000-7000-8000-000000000017",
            "authorization_preimage_digest": hash('4'),
            "possession_proof_digest": hash('5'),
            "issued_at": "2026-07-28T00:00:00.000Z",
            "expires_at": "2026-07-28T00:05:00.000Z",
            "auth_data": {
                "verification_method": "did:web:principal.example#service-signing-key",
                "alg": "EdDSA",
                "signature": "c2ln",
                "signed_fields": RECOVERY_AUTHORITY_TICKET_SIGNED_FIELDS
            }
        }))
        .unwrap()
    }

    #[test]
    fn ticket_signing_projection_is_closed_and_non_recursive() {
        let mut ticket = ticket();
        ticket.validate_structural().unwrap();
        let expected = ticket.signing_bytes().unwrap();

        ticket.auth_data.signature = "ZGlmZmVyZW50".to_owned();
        assert_eq!(ticket.signing_bytes().unwrap(), expected);

        ticket.account_authority_id = Did::new("did:web:other-accounts.example").unwrap();
        assert_ne!(ticket.signing_bytes().unwrap(), expected);
    }

    #[test]
    fn ticket_ttl_is_capped_at_five_minutes() {
        let mut ticket = ticket();
        ticket.expires_at = Utc.with_ymd_and_hms(2026, 7, 28, 0, 5, 1).single().unwrap();
        assert!(ticket.validate_structural().is_err());
    }

    #[test]
    fn ticket_rejects_reordered_signed_fields_metadata() {
        let mut ticket = ticket();
        ticket.auth_data.signed_fields.swap(0, 1);
        assert!(ticket.validate_structural().is_err());
    }
}
