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
    AuthoritySetPolicy, AuthoritySetRef, AuthorizationLease, CbaProofBundle, DeviceId, Did, DidUrl,
    Event, EventId, EventSubmitContext, GrantId, Hash, LeaseBasisRef, PolicyId,
    RECOVERY_ACCOUNT_AUTHORITY_SET_ID, ReceiptId, RecoveryAuthorityTicketId, RecoverySessionId,
    RiskTier, ScopeRef, TransactionId, TypedTrustDomainId,
};

const MAX_RECOVERY_PUBLICATION_CBA_BUNDLES: usize = 64;

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
pub const RECOVERY_COMPLETION_ATTESTATION_SIGNED_FIELDS: [&str; 14] = [
    "schema",
    "transaction_id",
    "transaction_request_digest",
    "prepared_plan_digest",
    "principal_id",
    "coordinator_service_id",
    "recovery_session_id",
    "terminal_receipt_id",
    "terminal_receipt_digest",
    "replacement_device_id",
    "device_authorization_event_id",
    "device_authorization_event_digest",
    "result_model_generation_ref",
    "completed_at",
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
    pub fn canonical_json(value: Value) -> Result<Self> {
        let bytes = arkret_canonical::canonical::canonical_json_bytes(&value)?;
        Ok(Self {
            canonical_encoding: CanonicalEncoding::CanonicalJson,
            canonical_bytes_base64url: arkret_canonical::base64url::base64url_encode(&bytes),
            digest: Hash::new(arkret_canonical::canonical::sha256_digest(&bytes))?,
            value,
        })
    }

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
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub transcript_digest: Hash,
    pub signature: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeEventPublicationIntent {
    pub event_id: EventId,
    pub event_preimage_digest: Hash,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub scope_ref: ScopeRef,
    pub action: String,
    pub authorization_rule_id: String,
    pub risk_tier: RiskTier,
    pub basis_ref: LeaseBasisRef,
    pub authority_set_ref: AuthoritySetRef,
    pub authority_set_policy: AuthoritySetPolicy,
    pub cba_proof_bundles: Vec<CbaProofBundle>,
}

impl AuthorizeEventPublicationIntent {
    pub fn validate_structural(&self) -> Result<()> {
        if self.action != "ak.device.authorize"
            || self.authorization_rule_id != "account_authority"
            || self.risk_tier != RiskTier::High
        {
            return Err(Error::Protocol(
                "recovery authorize publication intent must select account_authority for ak.device.authorize at high risk".to_owned(),
            ));
        }
        if self.authority_set_ref.authority_set_id != RECOVERY_ACCOUNT_AUTHORITY_SET_ID {
            return Err(Error::Protocol(
                "recovery authorize publication intent uses the wrong authority-set policy"
                    .to_owned(),
            ));
        }
        self.authority_set_policy.validate_reference_and_action(
            &self.authority_set_ref,
            &self.scope_ref,
            &self.authorization_rule_id,
            &self.action,
        )?;
        if self.cba_proof_bundles.len() > MAX_RECOVERY_PUBLICATION_CBA_BUNDLES {
            return Err(Error::Protocol(format!(
                "recovery authorize publication intent exceeds {MAX_RECOVERY_PUBLICATION_CBA_BUNDLES} CBA bundles"
            )));
        }
        for bundle in &self.cba_proof_bundles {
            bundle.validate_structural()?;
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    pub authorize_event_publication_intent: AuthorizeEventPublicationIntent,
    pub possession_proof: ReplacementDevicePossessionProof,
}

impl RecoveryAuthorizationPreimage {
    pub fn validate_structural(&self) -> Result<()> {
        self.authorize_event_preimage.validate_structural()?;
        self.authorize_event_publication_intent
            .validate_structural()?;
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
            || self.possession_proof.signature_algorithm.is_empty()
            || self.possession_proof.signature.is_empty()
        {
            return Err(Error::Protocol(
                "recovery authorization preimage contains an empty required value".to_owned(),
            ));
        }
        let event: Event = serde_json::from_value(self.authorize_event_preimage.value.clone())
            .map_err(|error| {
                Error::Protocol(format!(
                    "authorize Event preimage is not a closed Event: {error}"
                ))
            })?;
        let intent = &self.authorize_event_publication_intent;
        if self.authorize_event_preimage.canonical_encoding != CanonicalEncoding::CanonicalJson
            || !event.proofs.is_empty()
            || event.event_id != self.authorize_event_id
            || intent.event_id != self.authorize_event_id
            || intent.event_preimage_digest != self.authorize_event_preimage.digest
            || intent.actor_id != self.principal_id
            || intent.device_id != self.replacement_device_id
            || event.actor_id != intent.actor_id
            || event.scope_ref != intent.scope_ref
            || event.kind.as_str() != intent.action
            || event.payload.get("device_id").and_then(Value::as_str)
                != Some(intent.device_id.as_str())
        {
            return Err(Error::Protocol(
                "authorize Event preimage and publication intent binding is invalid".to_owned(),
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
    Ed25519,
    ES256,
    PS256,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAuthorityTicketAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: ServiceSignatureAlgorithm,
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeRecoveryDeviceOutcome {
    pub ticket_id: RecoveryAuthorityTicketId,
    pub transaction_id: TransactionId,
    pub authorize_event_id: EventId,
    pub authorized_event: Value,
    pub authorized_event_digest: Hash,
    pub authorization_lease: AuthorizationLease,
    pub cba_proof_bundles: Vec<CbaProofBundle>,
    pub authority_receipt_id: ReceiptId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

impl AuthorizeRecoveryDeviceOutcome {
    pub fn validate_against_request(&self, request: &AuthorizeRecoveryDeviceRequest) -> Result<()> {
        request.validate_structural()?;
        let preimage = &request.authorization_preimage;
        let intent = &preimage.authorize_event_publication_intent;
        let event: Event =
            serde_json::from_value(self.authorized_event.clone()).map_err(|error| {
                Error::Protocol(format!(
                    "authorized recovery Event is not a closed Event: {error}"
                ))
            })?;
        // This authority-signed authorize Event is one half of the closed
        // B-model re-anchor unit. It intentionally has no accepted Seal yet;
        // the coordinator validates the closed pair and publishes it
        // atomically.
        event.validate_for_submit_structural_in_context(EventSubmitContext::AnchorUnit)?;
        if self.ticket_id != request.ticket.ticket_id
            || self.transaction_id != request.ticket.transaction_id
            || self.authorize_event_id != request.ticket.authorize_event_id
            || event.event_id != self.authorize_event_id
            || event.event_digest()? != self.authorized_event_digest.as_str()
        {
            return Err(Error::Protocol(
                "recovery authority outcome disagrees with its ticket or signed Event".to_owned(),
            ));
        }

        let mut proof_free_event = self.authorized_event.clone();
        let proof_free_object = proof_free_event.as_object_mut().ok_or_else(|| {
            Error::Protocol("authorized recovery Event must be a JSON object".to_owned())
        })?;
        proof_free_object.insert("proofs".to_owned(), Value::Array(Vec::new()));
        if proof_free_event != preimage.authorize_event_preimage.value {
            return Err(Error::Protocol(
                "authorized recovery Event does not equal the ticket-bound proof-free preimage"
                    .to_owned(),
            ));
        }

        self.authorization_lease.validate_structural()?;
        if self.authorization_lease.basis_ref != intent.basis_ref
            || self.authorization_lease.actor_id != intent.actor_id
            || self.authorization_lease.device_id != intent.device_id
            || self.authorization_lease.scope_ref != intent.scope_ref
            || self.authorization_lease.action != intent.action
            || self.authorization_lease.risk_tier != intent.risk_tier
            || self.authorization_lease.authority_set_ref != intent.authority_set_ref
            || self.authorization_lease.authority_set_policy != intent.authority_set_policy
            || self.cba_proof_bundles != intent.cba_proof_bundles
        {
            return Err(Error::Protocol(
                "recovery authority outcome publication evidence disagrees with the prepared intent"
                    .to_owned(),
            ));
        }
        for bundle in &self.cba_proof_bundles {
            bundle.validate_structural()?;
        }
        Ok(())
    }
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
pub struct RecoveryCompletionAttestationAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub signature: String,
    pub signed_fields: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCompletionAttestation {
    pub schema: String,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub principal_id: Did,
    pub coordinator_service_id: Did,
    pub recovery_session_id: RecoverySessionId,
    pub terminal_receipt_id: ReceiptId,
    pub terminal_receipt_digest: Hash,
    pub replacement_device_id: DeviceId,
    pub device_authorization_event_id: EventId,
    pub device_authorization_event_digest: Hash,
    pub result_model_generation_ref: RecoveryModelGenerationRef,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub completed_at: DateTime<Utc>,
    pub auth_data: RecoveryCompletionAttestationAuthData,
}

impl RecoveryCompletionAttestation {
    pub fn validate_structural(&self) -> Result<()> {
        if self.schema != "ak.schema.recovery_completion_attestation.v1" {
            return Err(Error::Protocol(
                "recovery completion attestation schema is invalid".to_owned(),
            ));
        }
        if self.auth_data.signature_algorithm != "Ed25519"
            || self.auth_data.verification_method.is_empty()
            || self.auth_data.signature.is_empty()
        {
            return Err(Error::Protocol(
                "recovery completion attestation requires a complete Ed25519 authorization"
                    .to_owned(),
            ));
        }
        if self
            .auth_data
            .signed_fields
            .iter()
            .map(String::as_str)
            .ne(RECOVERY_COMPLETION_ATTESTATION_SIGNED_FIELDS)
        {
            return Err(Error::Protocol(
                "recovery completion attestation signed_fields must equal the registered ordered set"
                    .to_owned(),
            ));
        }
        match &self.result_model_generation_ref {
            RecoveryModelGenerationRef::CrossSigning(0) => {
                return Err(Error::Protocol(
                    "recovery completion generation must be positive".to_owned(),
                ));
            }
            RecoveryModelGenerationRef::EnrollmentAuthority(value) if value.is_empty() => {
                return Err(Error::Protocol(
                    "recovery completion generation must not be empty".to_owned(),
                ));
            }
            _ => {}
        }
        Ok(())
    }

    /// Canonical coordinator signature transcript. `auth_data` is excluded so
    /// the Ed25519 signature cannot recursively contain itself.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        let object = value.as_object().ok_or_else(|| {
            Error::Protocol(
                "recovery completion attestation must serialize as an object".to_owned(),
            )
        })?;
        let projection = RECOVERY_COMPLETION_ATTESTATION_SIGNED_FIELDS
            .iter()
            .map(|field| {
                object
                    .get(*field)
                    .cloned()
                    .map(|value| ((*field).to_owned(), value))
                    .ok_or_else(|| {
                        Error::Protocol(format!(
                            "recovery completion attestation is missing signed field {field}"
                        ))
                    })
            })
            .collect::<Result<serde_json::Map<String, Value>>>()?;
        Ok(arkret_canonical::canonical::canonical_json_bytes(
            &Value::Object(projection),
        )?)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromoteRecoverySessionGrantRequest {
    pub old_grant_id: GrantId,
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub terminal_receipt: Value,
    pub completion_attestation: RecoveryCompletionAttestation,
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
        self.completion_attestation.validate_structural()?;
        if self.transaction_id != self.completion_attestation.transaction_id
            || self.transaction_request_digest
                != self.completion_attestation.transaction_request_digest
            || self.device_authorization_event_id
                != self.completion_attestation.device_authorization_event_id
            || self.result_model_generation_ref
                != self.completion_attestation.result_model_generation_ref
        {
            return Err(Error::Protocol(
                "recovery promotion request and completion attestation binding disagree".to_owned(),
            ));
        }
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
    use crate::SchemaId;

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn publication_intent() -> AuthorizeEventPublicationIntent {
        let scope_ref = ScopeRef::Realm {
            realm_id: crate::RealmId::new(
                "ak:realm:019a7360-0000-8000-8000-000000000018".to_owned(),
            )
            .unwrap(),
        };
        let authority_set_policy = AuthoritySetPolicy {
            schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
            authority_set_id: RECOVERY_ACCOUNT_AUTHORITY_SET_ID.to_owned(),
            policy_kind: crate::AuthoritySetPolicyKind::PrincipalControl,
            scope_ref: scope_ref.clone(),
            source: crate::AuthoritySetPolicySource {
                source_kind: crate::AuthoritySetSourceKind::DidDocument,
                source_ref: "did:webvh:z6mkfixture:alice.example?versionId=1-genesis".to_owned(),
                source_digest: hash('3'),
                generation_ref: "1-genesis".to_owned(),
            },
            authorization_rules: vec![crate::AuthoritySetAuthorizationRule {
                rule_id: "account_authority".to_owned(),
                issuer_role: crate::AuthoritySetIssuerRole::AccountEnrollmentAuthority,
                allowed_actions: vec!["ak.device.authorize".to_owned()],
                issuers: vec![crate::AuthoritySetIssuer {
                    verification_method: DidUrl::new(
                        "did:web:accounts.example#device-enrollment-1",
                    )
                    .unwrap(),
                }],
                threshold: 1,
            }],
        };
        AuthorizeEventPublicationIntent {
            event_id: EventId::new("ak:event:019a7360-0000-8000-8000-000000000017".to_owned())
                .unwrap(),
            event_preimage_digest: hash('1'),
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:019a7360-0000-7000-8000-000000000015".to_owned())
                .unwrap(),
            scope_ref,
            action: "ak.device.authorize".to_owned(),
            authorization_rule_id: "account_authority".to_owned(),
            risk_tier: RiskTier::High,
            basis_ref: LeaseBasisRef::Seal(
                crate::SealId::new(format!("ak:seal:{}", hash('2').as_str())).unwrap(),
            ),
            authority_set_ref: AuthoritySetRef {
                authority_set_id: authority_set_policy.authority_set_id.clone(),
                authority_set_digest: authority_set_policy.digest().unwrap(),
            },
            authority_set_policy,
            cba_proof_bundles: Vec::new(),
        }
    }

    #[test]
    fn recovery_authorize_publication_intent_is_closed_to_high_risk_authorize() {
        publication_intent().validate_structural().unwrap();

        let mut lower_risk = publication_intent();
        lower_risk.risk_tier = RiskTier::Medium;
        assert!(lower_risk.validate_structural().is_err());

        let mut substituted_action = publication_intent();
        substituted_action.action = "ak.device.reanchor".to_owned();
        assert!(substituted_action.validate_structural().is_err());
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
            completion_attestation: RecoveryCompletionAttestation {
                schema: "ak.schema.recovery_completion_attestation.v1".to_owned(),
                transaction_id: TransactionId::new(
                    "ak:transaction:019a7360-0000-7000-8000-000000000002".to_owned(),
                )
                .unwrap(),
                transaction_request_digest: hash('1'),
                prepared_plan_digest: hash('2'),
                principal_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
                coordinator_service_id: Did::new("did:webvh:z6mkfixture:principal.example")
                    .unwrap(),
                recovery_session_id: RecoverySessionId::new(
                    "ak:recovery_session:019a7360-0000-7000-8000-000000000005".to_owned(),
                )
                .unwrap(),
                terminal_receipt_id: ReceiptId::new(
                    "ak:receipt:019a7360-0000-7000-8000-000000000003".to_owned(),
                )
                .unwrap(),
                terminal_receipt_digest: hash('3'),
                replacement_device_id: DeviceId::new(
                    "ak:device:019a7360-0000-7000-8000-000000000006".to_owned(),
                )
                .unwrap(),
                device_authorization_event_id: EventId::new(
                    "ak:event:019a7360-0000-8000-8000-000000000004".to_owned(),
                )
                .unwrap(),
                device_authorization_event_digest: hash('4'),
                result_model_generation_ref: RecoveryModelGenerationRef::CrossSigning(7),
                completed_at: Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap(),
                auth_data: RecoveryCompletionAttestationAuthData {
                    verification_method: DidUrl::new(
                        "did:webvh:z6mkfixture:principal.example#signing",
                    )
                    .unwrap(),
                    signature_algorithm: "Ed25519".to_owned(),
                    signature: "c2lnbmF0dXJl".to_owned(),
                    signed_fields: RECOVERY_COMPLETION_ATTESTATION_SIGNED_FIELDS
                        .iter()
                        .map(|field| (*field).to_owned())
                        .collect(),
                },
            },
            device_authorization_event_id: EventId::new(
                "ak:event:019a7360-0000-8000-8000-000000000004".to_owned(),
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
            "reanchor_event_id": "ak:event:019a7360-0000-8000-8000-000000000016",
            "authorize_event_id": "ak:event:019a7360-0000-8000-8000-000000000017",
            "authorization_preimage_digest": hash('4'),
            "possession_proof_digest": hash('5'),
            "issued_at": "2026-07-28T00:00:00.000Z",
            "expires_at": "2026-07-28T00:05:00.000Z",
            "auth_data": {
                "verification_method": "did:web:principal.example#service-signing-key",
                "signature_algorithm": "Ed25519",
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
