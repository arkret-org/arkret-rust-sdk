//! Key-package HTTP request/outcome DTO counterparts for the
//! `ak.self.keys.*` key-package operations
//! (`service-operation-dtos.schema.json`). Pure wire shapes; upload,
//! claim, and consumption behavior lives with the transport and server
//! crates.

use std::collections::BTreeSet;

use arkret_wire::{
    Base64UrlString, DeviceId, DidCoreId, DidUrl, EventId, Hash, KeyPackageRef, NonEmptyString,
    RealmId, StrandId,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::artifacts_keys::{
    Failure, KeyOperationSignature, KeyPackageClaimRecord, KeyPackageRefArray,
    KeyPackageUploadEntry,
};
use crate::key_backup::KeyBackup;
use crate::mls_records::MlsKeyPackageRecord;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesUploadRequestBody {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub keypackages: Vec<KeyPackageUploadEntry>,
    pub device_signature: KeyOperationSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
}

/// Canonical unsigned projection for
/// `ak.self.keys.keypackages.upload.create`.
///
/// The request-level signature and every optional entry signature are absent
/// by construction, so producers and verifiers cannot accidentally sign
/// different upload shapes.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesUploadUnsignedRequest {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub keypackages: Vec<KeyPackageUploadEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
}

impl KeyPackagesUploadRequestBody {
    #[must_use]
    pub fn unsigned(&self) -> KeyPackagesUploadUnsignedRequest {
        let mut keypackages = self.keypackages.clone();
        for entry in &mut keypackages {
            entry.device_signature = None;
        }
        KeyPackagesUploadUnsignedRequest {
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            keypackages,
            expires_at: self.expires_at,
            strand_id: self.strand_id.clone(),
            mls_group_id: self.mls_group_id.clone(),
        }
    }
}

impl KeyPackagesUploadUnsignedRequest {
    #[must_use]
    pub fn into_signed(
        self,
        device_signature: KeyOperationSignature,
    ) -> KeyPackagesUploadRequestBody {
        KeyPackagesUploadRequestBody {
            principal_id: self.principal_id,
            device_id: self.device_id,
            keypackages: self.keypackages,
            device_signature,
            expires_at: self.expires_at,
            strand_id: self.strand_id,
            mls_group_id: self.mls_group_id,
        }
    }
}

/// Convert a persisted MLS KeyPackage record into the canonical typed upload
/// entry shared by ordinary devices and Native Agent runtimes.
///
/// Request ownership and signing-key authorization remain caller concerns;
/// this helper owns only the record-to-wire projection so digest, expiry, and
/// last-resort semantics cannot drift between clients.
pub fn mls_key_package_record_upload_entry(
    record: &MlsKeyPackageRecord,
) -> Result<KeyPackageUploadEntry, &'static str> {
    Ok(KeyPackageUploadEntry {
        keypackage_id: record.keypackage_id.clone(),
        keypackage_ref: record.keypackage_ref.as_str().to_owned(),
        keypackage_digest: record.keypackage_ref.clone(),
        keypackage: Base64UrlString::new(record.keypackage.clone())?,
        cipher_suites: record.cipher_suites.clone(),
        capabilities: record.capabilities.clone(),
        expires_at: record
            .expires_at
            .unwrap_or(record.created_at + Duration::days(7)),
        created_at: record.created_at,
        device_signature: None,
        last_resort: record.last_resort.then_some(true),
    })
}

pub const KEYPACKAGES_UPLOAD_SIGNATURE_DOMAIN: &str = "ak.self.keys.keypackages.upload.create\n";
pub const KEYPACKAGES_CONSUME_SIGNATURE_DOMAIN: &str = "ak.self.keys.keypackages.command.consume\n";
pub const KEYPACKAGES_REVOKE_SIGNATURE_DOMAIN: &str = "ak.self.keys.keypackages.command.revoke\n";

fn keypackage_signing_input<T: Serialize>(
    domain: &str,
    unsigned: &T,
) -> arkret_canonical::Result<Vec<u8>> {
    let canonical = arkret_canonical::canonical_json_bytes(unsigned)?;
    let mut input = Vec::with_capacity(domain.len() + canonical.len());
    input.extend_from_slice(domain.as_bytes());
    input.extend_from_slice(&canonical);
    Ok(input)
}

pub fn keypackages_upload_signing_input(
    unsigned: &KeyPackagesUploadUnsignedRequest,
) -> arkret_canonical::Result<Vec<u8>> {
    keypackage_signing_input(KEYPACKAGES_UPLOAD_SIGNATURE_DOMAIN, unsigned)
}

#[derive(Serialize)]
struct KeyPackageUploadEntryUnsigned<'a> {
    principal_id: &'a DidCoreId,
    device_id: &'a DeviceId,
    keypackage: KeyPackageUploadEntry,
}

pub fn keypackage_upload_entry_signing_input(
    principal_id: &DidCoreId,
    device_id: &DeviceId,
    entry: &KeyPackageUploadEntry,
) -> arkret_canonical::Result<Vec<u8>> {
    let mut keypackage = entry.clone();
    keypackage.device_signature = None;
    keypackage_signing_input(
        KEYPACKAGES_UPLOAD_SIGNATURE_DOMAIN,
        &KeyPackageUploadEntryUnsigned {
            principal_id,
            device_id,
            keypackage,
        },
    )
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesUploadOutcome {
    pub accepted: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Failure>,
    #[serde(
        rename = "keypackage_refs",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub key_package_refs: KeyPackageRefArray,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_count: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerKeyPackageClaimPurpose {
    RealmMembership,
    DirectConversation,
    DirectConversationRepair,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PeerKeyPackageRequesterAuthorization {
    Device {
        verification_method: DidUrl,
        requester_device_id: DeviceId,
        device_authorize_event_id: EventId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        signed_at: DateTime<Utc>,
        signature: KeyOperationSignature,
    },
    NativeAgent {
        verification_method: DidUrl,
        requester_agent_id: DidCoreId,
        agent_key_authorize_event_id: EventId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        signed_at: DateTime<Utc>,
        signature: KeyOperationSignature,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimUnsignedRequest {
    pub claim_request_id: Base64UrlString,
    pub target_principal_id: DidCoreId,
    pub requester: DidCoreId,
    pub intended_realm_id: RealmId,
    pub mls_group_id: NonEmptyString,
    pub claim_purpose: PeerKeyPackageClaimPurpose,
    pub required_capabilities: Vec<NonEmptyString>,
    pub claim_nonce: Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_device_ids: Vec<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_keypackage_ref: Option<KeyPackageRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_agent_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_agent_key_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimal_metadata_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_key: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort_allowed: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesClaimServiceBinding {
    pub source_service_id: DidCoreId,
    pub destination_service_id: DidCoreId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimRequestBody {
    pub claim_request_id: Base64UrlString,
    pub target_principal_id: DidCoreId,
    pub requester: DidCoreId,
    pub intended_realm_id: RealmId,
    pub mls_group_id: NonEmptyString,
    pub claim_purpose: PeerKeyPackageClaimPurpose,
    pub required_capabilities: Vec<NonEmptyString>,
    pub claim_nonce: Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_device_ids: Vec<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_keypackage_ref: Option<KeyPackageRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_agent_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_agent_key_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimal_metadata_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_key: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resort_allowed: Option<bool>,
    pub service_binding: KeyPackagesClaimServiceBinding,
    pub requester_authorization: PeerKeyPackageRequesterAuthorization,
}

impl PeerKeyPackagesClaimRequestBody {
    pub fn unsigned_request(&self) -> PeerKeyPackagesClaimUnsignedRequest {
        PeerKeyPackagesClaimUnsignedRequest {
            claim_request_id: self.claim_request_id.clone(),
            target_principal_id: self.target_principal_id.clone(),
            requester: self.requester.clone(),
            intended_realm_id: self.intended_realm_id.clone(),
            mls_group_id: self.mls_group_id.clone(),
            claim_purpose: self.claim_purpose,
            required_capabilities: self.required_capabilities.clone(),
            claim_nonce: self.claim_nonce.clone(),
            expires_at: self.expires_at,
            target_device_ids: self.target_device_ids.clone(),
            target_keypackage_ref: self.target_keypackage_ref.clone(),
            target_agent_id: self.target_agent_id.clone(),
            target_agent_verification_method: self.target_agent_verification_method.clone(),
            target_agent_key_authorize_event_id: self.target_agent_key_authorize_event_id.clone(),
            minimal_metadata_allowed: self.minimal_metadata_allowed,
            timeout_ms: self.timeout_ms,
            strand_id: self.strand_id.clone(),
            pair_key: self.pair_key.clone(),
            last_resort_allowed: self.last_resort_allowed,
        }
    }

    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        validate_peer_claim_fields(&self.unsigned_request())?;
        match &self.requester_authorization {
            PeerKeyPackageRequesterAuthorization::Device {
                verification_method,
                requester_device_id,
                device_authorize_event_id,
                signature,
                ..
            } => {
                if signature.kid.as_str() != verification_method.as_str() {
                    return Err(PeerKeyPackageClaimShapeError::VerificationMethodMismatch);
                }
                let _ = (requester_device_id, device_authorize_event_id);
            }
            PeerKeyPackageRequesterAuthorization::NativeAgent {
                verification_method,
                requester_agent_id,
                agent_key_authorize_event_id,
                signature,
                ..
            } => {
                if signature.kid.as_str() != verification_method.as_str()
                    || requester_agent_id != &self.requester
                {
                    return Err(PeerKeyPackageClaimShapeError::VerificationMethodMismatch);
                }
                let _ = agent_key_authorize_event_id;
            }
        }
        Ok(())
    }
}

/// Canonical KeyPackage claim request shared by self and peer operations.
pub type KeyPackagesClaimRequestBody = PeerKeyPackagesClaimRequestBody;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackageClaimReceipt {
    pub claim_request_id: Base64UrlString,
    pub request_digest: Hash,
    pub claims_digest: Hash,
    pub source_service_id: DidCoreId,
    pub destination_service_id: DidCoreId,
    pub request: PeerKeyPackagesClaimUnsignedRequest,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub claimed_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimOutcome {
    pub claim_request_id: Base64UrlString,
    pub claims: Vec<KeyPackageClaimRecord>,
    pub claim_receipt: PeerKeyPackageClaimReceipt,
}

/// Canonical KeyPackage claim outcome shared by self and peer operations.
pub type KeyPackagesClaimOutcome = PeerKeyPackagesClaimOutcome;

impl PeerKeyPackagesClaimOutcome {
    /// Enforce the cross-field receipt/outcome bindings that JSON Schema
    /// cannot express by itself.
    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        let receipt = &self.claim_receipt;
        if self.claims.is_empty()
            || self.claim_request_id != receipt.claim_request_id
            || receipt.claim_request_id != receipt.request.claim_request_id
            || receipt.request.expires_at != receipt.expires_at
            || receipt.claimed_at >= receipt.expires_at
            || self
                .claims
                .iter()
                .any(|claim| claim.expires_at < receipt.expires_at)
        {
            return Err(PeerKeyPackageClaimShapeError::InvalidClaimOutcome);
        }
        for claim in &self.claims {
            validate_target_claim_evidence(claim, receipt)?;
        }
        let claims_digest = arkret_canonical::canonical_sha256(&self.claims)
            .map_err(|_| PeerKeyPackageClaimShapeError::InvalidClaimOutcome)?;
        if receipt.claims_digest.as_str() != claims_digest {
            return Err(PeerKeyPackageClaimShapeError::InvalidClaimOutcome);
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimQueryRequestBody {
    pub claim_request_id: Base64UrlString,
    pub request_digest: Hash,
}

impl PeerKeyPackagesClaimQueryRequestBody {
    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        if !(22..=128).contains(&self.claim_request_id.as_str().len()) {
            return Err(PeerKeyPackageClaimShapeError::InvalidClaimRequestId);
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerKeyPackagesClaimQueryState {
    Unknown,
    Pending,
    Claimed,
    Consumed,
    ClaimFailed,
    Expired,
    Revoked,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPackageClaimTerminalState {
    NeverClaimed,
    Expired,
    Revoked,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageClaimTerminalReceipt {
    pub domain: NonEmptyString,
    pub claim_request_id: Base64UrlString,
    pub request_digest: Hash,
    pub terminal_state: KeyPackageClaimTerminalState,
    #[serde(
        rename = "keypackage_refs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub key_package_refs: Option<KeyPackageRefArray>,
    pub source_service_id: DidCoreId,
    pub destination_service_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub terminal_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

impl KeyPackageClaimTerminalReceipt {
    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        signed_receipt_canonical_signing_bytes(self, self.domain.as_str())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimQueryOutcome {
    pub claim_request_id: Base64UrlString,
    pub state: PeerKeyPackagesClaimQueryState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_outcome: Option<PeerKeyPackagesClaimOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consume_receipt: Option<KeyPackageConsumeReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_receipt: Option<KeyPackageClaimTerminalReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<PeerKeyPackageClaimErrorCode>,
}

impl PeerKeyPackagesClaimQueryOutcome {
    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        if let Some(outcome) = &self.claim_outcome
            && (outcome.claim_request_id != self.claim_request_id
                || outcome.validate_shape().is_err())
        {
            return Err(PeerKeyPackageClaimShapeError::InvalidQueryOutcome);
        }
        match self.state {
            PeerKeyPackagesClaimQueryState::Pending
                if self.claim_outcome.is_none()
                    && self.consume_receipt.is_none()
                    && self.terminal_receipt.is_none()
                    && self.retry_after_ms.is_some_and(|value| value > 0)
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::Claimed
                if self.claim_outcome.is_some()
                    && self.consume_receipt.is_none()
                    && self.terminal_receipt.is_none()
                    && self.retry_after_ms.is_none()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::Consumed
                if self.claim_outcome.is_some()
                    && self.consume_receipt.is_some()
                    && self.terminal_receipt.is_none()
                    && self.retry_after_ms.is_none()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::Expired | PeerKeyPackagesClaimQueryState::Revoked
                if self.claim_outcome.is_some()
                    && self.consume_receipt.is_none()
                    && self.terminal_receipt.is_some()
                    && self.retry_after_ms.is_none()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::ClaimFailed
                if self.claim_outcome.is_none()
                    && self.consume_receipt.is_none()
                    && self.terminal_receipt.is_some()
                    && self.retry_after_ms.is_none()
                    && self.error_code == Some(PeerKeyPackageClaimErrorCode::ClaimFailed) =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::Unknown
                if self.claim_outcome.is_none()
                    && self.consume_receipt.is_none()
                    && self.terminal_receipt.is_none()
                    && self.retry_after_ms.is_none()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            _ => Err(PeerKeyPackageClaimShapeError::InvalidQueryOutcome),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerKeyPackageClaimErrorCode {
    #[serde(rename = "claim_failed")]
    ClaimFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PeerKeyPackageClaimShapeError {
    #[error("claim_request_id must encode at least 128 bits and be at most 128 characters")]
    InvalidClaimRequestId,
    #[error("claim_nonce must encode at least 128 bits")]
    InvalidClaimNonce,
    #[error("required_capabilities must be non-empty and unique")]
    InvalidRequiredCapabilities,
    #[error("target_device_ids must be unique")]
    DuplicateTargetDevice,
    #[error("direct conversation claims require strand_id and pair_key and forbid last resort")]
    InvalidDirectConversationFields,
    #[error("requester authorization must select exactly one supported authority model")]
    InvalidAuthorizationModel,
    #[error("requester authorization signature kid must equal verification_method")]
    VerificationMethodMismatch,
    #[error("peer claim query outcome fields do not match its state")]
    InvalidQueryOutcome,
    #[error("peer claim outcome fields or receipt bindings are inconsistent")]
    InvalidClaimOutcome,
    #[error("requester signing key evidence does not match requester authorization")]
    SignerEvidenceMismatch,
    #[error("target signing key evidence does not match its claim record")]
    TargetSignerEvidenceMismatch,
}

fn validate_target_claim_evidence(
    claim: &KeyPackageClaimRecord,
    _receipt: &PeerKeyPackageClaimReceipt,
) -> Result<(), PeerKeyPackageClaimShapeError> {
    match (
        &claim.device_authorize_event_id,
        &claim.agent_key_authorize_event_id,
    ) {
        (Some(_), None) => {
            if claim.device_id.is_none()
                || claim.agent_id.is_some()
                || claim.agent_verification_method.is_some()
            {
                return Err(PeerKeyPackageClaimShapeError::TargetSignerEvidenceMismatch);
            }
        }
        (None, Some(_)) => {
            if claim.agent_id.as_ref().map(DidCoreId::as_core_id)
                != Some(claim.principal_id.as_core_id())
                || claim.device_id.is_some()
                || claim
                    .agent_verification_method
                    .as_ref()
                    .is_none_or(|method| method.as_str() != claim.device_signature.kid.as_str())
            {
                return Err(PeerKeyPackageClaimShapeError::TargetSignerEvidenceMismatch);
            }
        }
        _ => return Err(PeerKeyPackageClaimShapeError::TargetSignerEvidenceMismatch),
    }
    Ok(())
}

fn validate_peer_claim_fields(
    request: &PeerKeyPackagesClaimUnsignedRequest,
) -> Result<(), PeerKeyPackageClaimShapeError> {
    if !(22..=128).contains(&request.claim_request_id.as_str().len()) {
        return Err(PeerKeyPackageClaimShapeError::InvalidClaimRequestId);
    }
    if request.claim_nonce.as_str().len() < 22 {
        return Err(PeerKeyPackageClaimShapeError::InvalidClaimNonce);
    }
    let capabilities = request
        .required_capabilities
        .iter()
        .map(NonEmptyString::as_str)
        .collect::<BTreeSet<_>>();
    if capabilities.is_empty() || capabilities.len() != request.required_capabilities.len() {
        return Err(PeerKeyPackageClaimShapeError::InvalidRequiredCapabilities);
    }
    let target_devices = request
        .target_device_ids
        .iter()
        .map(DeviceId::as_str)
        .collect::<BTreeSet<_>>();
    if target_devices.len() != request.target_device_ids.len() {
        return Err(PeerKeyPackageClaimShapeError::DuplicateTargetDevice);
    }
    if matches!(
        request.claim_purpose,
        PeerKeyPackageClaimPurpose::DirectConversation
            | PeerKeyPackageClaimPurpose::DirectConversationRepair
    ) && (request.strand_id.is_none()
        || request.pair_key.is_none()
        || request.last_resort_allowed == Some(true))
    {
        return Err(PeerKeyPackageClaimShapeError::InvalidDirectConversationFields);
    }
    if request.claim_purpose == PeerKeyPackageClaimPurpose::DirectConversationRepair {
        let human_target = request.target_device_ids.len() == 1
            && request.target_agent_id.is_none()
            && request.target_agent_verification_method.is_none()
            && request.target_agent_key_authorize_event_id.is_none();
        let agent_target = request.target_device_ids.is_empty()
            && request.target_agent_id.is_some()
            && request.target_agent_verification_method.is_some()
            && request.target_agent_key_authorize_event_id.is_some();
        if request.target_keypackage_ref.is_none() || human_target == agent_target {
            return Err(PeerKeyPackageClaimShapeError::InvalidDirectConversationFields);
        }
        if let Some(agent_id) = &request.target_agent_id
            && agent_id.as_core_id() != request.target_principal_id.as_core_id()
        {
            return Err(PeerKeyPackageClaimShapeError::InvalidDirectConversationFields);
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct PeerKeyPackageAuthorizationTranscript<'a> {
    authorization: PeerKeyPackageAuthorizationMetadata<'a>,
    request: &'a PeerKeyPackagesClaimUnsignedRequest,
    service_binding: &'a KeyPackagesClaimServiceBinding,
}

#[derive(Serialize)]
struct PeerKeyPackageAuthorizationMetadata<'a> {
    kind: &'static str,
    verification_method: &'a DidUrl,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_device_id: Option<&'a DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_authorize_event_id: Option<&'a EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_agent_id: Option<&'a DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_key_authorize_event_id: Option<&'a EventId>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    signed_at: DateTime<Utc>,
}

pub fn keypackage_claim_authorization_signing_bytes(
    request: &PeerKeyPackagesClaimUnsignedRequest,
    service_binding: &KeyPackagesClaimServiceBinding,
    authorization: &PeerKeyPackageRequesterAuthorization,
) -> arkret_canonical::Result<Vec<u8>> {
    let metadata = match authorization {
        PeerKeyPackageRequesterAuthorization::Device {
            verification_method,
            requester_device_id,
            device_authorize_event_id,
            signed_at,
            ..
        } => PeerKeyPackageAuthorizationMetadata {
            kind: "device",
            verification_method,
            requester_device_id: Some(requester_device_id),
            device_authorize_event_id: Some(device_authorize_event_id),
            requester_agent_id: None,
            agent_key_authorize_event_id: None,
            signed_at: *signed_at,
        },
        PeerKeyPackageRequesterAuthorization::NativeAgent {
            verification_method,
            requester_agent_id,
            agent_key_authorize_event_id,
            signed_at,
            ..
        } => PeerKeyPackageAuthorizationMetadata {
            kind: "native_agent",
            verification_method,
            requester_device_id: None,
            device_authorize_event_id: None,
            requester_agent_id: Some(requester_agent_id),
            agent_key_authorize_event_id: Some(agent_key_authorize_event_id),
            signed_at: *signed_at,
        },
    };
    let transcript = PeerKeyPackageAuthorizationTranscript {
        authorization: metadata,
        request,
        service_binding,
    };
    let canonical = arkret_canonical::canonical_json_bytes(&transcript)?;
    let mut bytes = b"ak.keypackage-claim-authorization-v1\n".to_vec();
    bytes.extend(canonical);
    Ok(bytes)
}

#[derive(Serialize)]
struct PeerKeyPackageClaimReceiptUnsigned<'a> {
    claim_request_id: &'a Base64UrlString,
    request_digest: &'a Hash,
    claims_digest: &'a Hash,
    source_service_id: &'a DidCoreId,
    destination_service_id: &'a DidCoreId,
    request: &'a PeerKeyPackagesClaimUnsignedRequest,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    claimed_at: DateTime<Utc>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
}

pub fn peer_keypackage_claim_receipt_signing_bytes(
    receipt: &PeerKeyPackageClaimReceipt,
) -> arkret_canonical::Result<Vec<u8>> {
    let unsigned = PeerKeyPackageClaimReceiptUnsigned {
        claim_request_id: &receipt.claim_request_id,
        request_digest: &receipt.request_digest,
        claims_digest: &receipt.claims_digest,
        source_service_id: &receipt.source_service_id,
        destination_service_id: &receipt.destination_service_id,
        request: &receipt.request,
        claimed_at: receipt.claimed_at,
        expires_at: receipt.expires_at,
    };
    let canonical = arkret_canonical::canonical_json_bytes(&unsigned)?;
    let mut bytes = b"ak.peer-keypackage-claim-receipt-v1\n".to_vec();
    bytes.extend(canonical);
    Ok(bytes)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug)]
pub struct RecipientMlsDurableReceipt {
    pub domain: NonEmptyString,
    pub claim_request_id: Base64UrlString,
    pub key_package_ref: NonEmptyString,
    pub recipient_principal_id: DidCoreId,
    pub recipient: RecipientMlsDurableSigner,
    pub recipient_service_id: DidCoreId,
    pub realm_id: RealmId,
    pub mls_group_id: NonEmptyString,
    pub mls_epoch: u64,
    pub welcome_ref: NonEmptyString,
    pub welcome_digest: Hash,
    pub durable_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RecipientMlsDurableSigner {
    Device {
        recipient_device_id: DeviceId,
        device_verification_method: DidUrl,
    },
    NativeAgent {
        recipient_agent_id: DidCoreId,
        recipient_agent_verification_method: DidUrl,
        agent_key_authorize_event_id: EventId,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientMlsDurableReceiptWire {
    domain: NonEmptyString,
    claim_request_id: Base64UrlString,
    key_package_ref: NonEmptyString,
    recipient_principal_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_agent_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_key_authorize_event_id: Option<EventId>,
    recipient_service_id: DidCoreId,
    realm_id: RealmId,
    mls_group_id: NonEmptyString,
    mls_epoch: u64,
    welcome_ref: NonEmptyString,
    welcome_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    durable_at: DateTime<Utc>,
    signature: KeyOperationSignature,
}

impl Serialize for RecipientMlsDurableReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (
            recipient_device_id,
            device_verification_method,
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
        ) = match &self.recipient {
            RecipientMlsDurableSigner::Device {
                recipient_device_id,
                device_verification_method,
            } => (
                Some(recipient_device_id.clone()),
                Some(device_verification_method.clone()),
                None,
                None,
                None,
            ),
            RecipientMlsDurableSigner::NativeAgent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            } => (
                None,
                None,
                Some(recipient_agent_id.clone()),
                Some(recipient_agent_verification_method.clone()),
                Some(agent_key_authorize_event_id.clone()),
            ),
        };
        RecipientMlsDurableReceiptWire {
            domain: self.domain.clone(),
            claim_request_id: self.claim_request_id.clone(),
            key_package_ref: self.key_package_ref.clone(),
            recipient_principal_id: self.recipient_principal_id.clone(),
            recipient_device_id,
            device_verification_method,
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
            recipient_service_id: self.recipient_service_id.clone(),
            realm_id: self.realm_id.clone(),
            mls_group_id: self.mls_group_id.clone(),
            mls_epoch: self.mls_epoch,
            welcome_ref: self.welcome_ref.clone(),
            welcome_digest: self.welcome_digest.clone(),
            durable_at: self.durable_at,
            signature: self.signature.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RecipientMlsDurableReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RecipientMlsDurableReceiptWire::deserialize(deserializer)?;
        let recipient = match (
            wire.recipient_device_id,
            wire.device_verification_method,
            wire.recipient_agent_id,
            wire.recipient_agent_verification_method,
            wire.agent_key_authorize_event_id,
        ) {
            (Some(device_id), Some(method), None, None, None) => {
                RecipientMlsDurableSigner::Device {
                    recipient_device_id: device_id,
                    device_verification_method: method,
                }
            }
            (None, None, Some(agent_id), Some(method), Some(event_id)) => {
                RecipientMlsDurableSigner::NativeAgent {
                    recipient_agent_id: agent_id,
                    recipient_agent_verification_method: method,
                    agent_key_authorize_event_id: event_id,
                }
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "recipient durable receipt must select exactly one device or Native Agent signer",
                ));
            }
        };
        let receipt = Self {
            domain: wire.domain,
            claim_request_id: wire.claim_request_id,
            key_package_ref: wire.key_package_ref,
            recipient_principal_id: wire.recipient_principal_id,
            recipient,
            recipient_service_id: wire.recipient_service_id,
            realm_id: wire.realm_id,
            mls_group_id: wire.mls_group_id,
            mls_epoch: wire.mls_epoch,
            welcome_ref: wire.welcome_ref,
            welcome_digest: wire.welcome_digest,
            durable_at: wire.durable_at,
            signature: wire.signature,
        };
        receipt.validate_shape().map_err(serde::de::Error::custom)?;
        Ok(receipt)
    }
}

impl RecipientMlsDurableReceipt {
    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        signed_receipt_canonical_signing_bytes(self, self.domain.as_str())
    }

    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.domain.as_str() != "ak.mls.recipient-durable-receipt.v1" {
            return Err("recipient durable receipt domain mismatch");
        }
        match &self.recipient {
            RecipientMlsDurableSigner::Device {
                device_verification_method,
                ..
            } => {
                if self.signature.kid.as_str() != device_verification_method.as_str() {
                    return Err("recipient device receipt signature kid mismatch");
                }
            }
            RecipientMlsDurableSigner::NativeAgent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            } => {
                if recipient_agent_id.as_core_id() != self.recipient_principal_id.as_core_id()
                    || self.signature.kid.as_str() != recipient_agent_verification_method.as_str()
                {
                    return Err("recipient Native Agent durable receipt binding mismatch");
                }
                let _ = agent_key_authorize_event_id;
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug)]
pub enum KeyPackageConsumer {
    Device {
        consumer_device_id: DeviceId,
    },
    NativeAgent {
        consumer_agent_id: DidCoreId,
        consumer_agent_verification_method: DidUrl,
        consumer_agent_key_authorize_event_id: EventId,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug)]
pub struct KeyPackagesConsumeRequestBody {
    pub owner_account_id: DidCoreId,
    pub key_package_refs: KeyPackageRefArray,
    pub consumer: KeyPackageConsumer,
    pub claim_ids: Vec<NonEmptyString>,
    pub welcome_ref: NonEmptyString,
    pub recipient_durable_receipt: RecipientMlsDurableReceipt,
    pub signature: KeyOperationSignature,
    pub realm_id: Option<RealmId>,
    pub strand_id: Option<StrandId>,
    pub mls_group_id: Option<NonEmptyString>,
    pub epoch: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug)]
pub struct KeyPackagesConsumeUnsignedRequest {
    pub owner_account_id: DidCoreId,
    pub key_package_refs: KeyPackageRefArray,
    pub consumer: KeyPackageConsumer,
    pub claim_ids: Vec<NonEmptyString>,
    pub welcome_ref: NonEmptyString,
    pub recipient_durable_receipt: RecipientMlsDurableReceipt,
    pub realm_id: Option<RealmId>,
    pub strand_id: Option<StrandId>,
    pub mls_group_id: Option<NonEmptyString>,
    pub epoch: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPackagesConsumeRequestBodyWire {
    owner_account_id: DidCoreId,
    #[serde(rename = "keypackage_refs")]
    key_package_refs: KeyPackageRefArray,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumer_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumer_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumer_agent_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumer_agent_key_authorize_event_id: Option<EventId>,
    claim_ids: Vec<NonEmptyString>,
    welcome_ref: NonEmptyString,
    recipient_durable_receipt: RecipientMlsDurableReceipt,
    signature: KeyOperationSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mls_group_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epoch: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPackagesConsumeUnsignedRequestWire {
    owner_account_id: DidCoreId,
    #[serde(rename = "keypackage_refs")]
    key_package_refs: KeyPackageRefArray,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumer_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumer_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumer_agent_verification_method: Option<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumer_agent_key_authorize_event_id: Option<EventId>,
    claim_ids: Vec<NonEmptyString>,
    welcome_ref: NonEmptyString,
    recipient_durable_receipt: RecipientMlsDurableReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mls_group_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epoch: Option<u64>,
}

fn keypackage_consumer_to_wire(
    consumer: &KeyPackageConsumer,
) -> (
    Option<DeviceId>,
    Option<DidCoreId>,
    Option<DidUrl>,
    Option<EventId>,
) {
    match consumer {
        KeyPackageConsumer::Device { consumer_device_id } => {
            (Some(consumer_device_id.clone()), None, None, None)
        }
        KeyPackageConsumer::NativeAgent {
            consumer_agent_id,
            consumer_agent_verification_method,
            consumer_agent_key_authorize_event_id,
        } => (
            None,
            Some(consumer_agent_id.clone()),
            Some(consumer_agent_verification_method.clone()),
            Some(consumer_agent_key_authorize_event_id.clone()),
        ),
    }
}

fn keypackage_consumer_from_wire<E: serde::de::Error>(
    device_id: Option<DeviceId>,
    agent_id: Option<DidCoreId>,
    agent_method: Option<DidUrl>,
    agent_authorize_event_id: Option<EventId>,
) -> Result<KeyPackageConsumer, E> {
    match (device_id, agent_id, agent_method, agent_authorize_event_id) {
        (Some(device_id), None, None, None) => Ok(KeyPackageConsumer::Device {
            consumer_device_id: device_id,
        }),
        (None, Some(agent_id), Some(method), Some(event_id)) => {
            Ok(KeyPackageConsumer::NativeAgent {
                consumer_agent_id: agent_id,
                consumer_agent_verification_method: method,
                consumer_agent_key_authorize_event_id: event_id,
            })
        }
        _ => Err(E::custom(
            "KeyPackage consume request must select exactly one device or Native Agent consumer",
        )),
    }
}

impl Serialize for KeyPackagesConsumeUnsignedRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (device_id, agent_id, agent_method, agent_event_id) =
            keypackage_consumer_to_wire(&self.consumer);
        KeyPackagesConsumeUnsignedRequestWire {
            owner_account_id: self.owner_account_id.clone(),
            key_package_refs: self.key_package_refs.clone(),
            consumer_device_id: device_id,
            consumer_agent_id: agent_id,
            consumer_agent_verification_method: agent_method,
            consumer_agent_key_authorize_event_id: agent_event_id,
            claim_ids: self.claim_ids.clone(),
            welcome_ref: self.welcome_ref.clone(),
            recipient_durable_receipt: self.recipient_durable_receipt.clone(),
            realm_id: self.realm_id.clone(),
            strand_id: self.strand_id.clone(),
            mls_group_id: self.mls_group_id.clone(),
            epoch: self.epoch,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeyPackagesConsumeUnsignedRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = KeyPackagesConsumeUnsignedRequestWire::deserialize(deserializer)?;
        let consumer = keypackage_consumer_from_wire::<D::Error>(
            wire.consumer_device_id,
            wire.consumer_agent_id,
            wire.consumer_agent_verification_method,
            wire.consumer_agent_key_authorize_event_id,
        )?;
        let request = Self {
            owner_account_id: wire.owner_account_id,
            key_package_refs: wire.key_package_refs,
            consumer,
            claim_ids: wire.claim_ids,
            welcome_ref: wire.welcome_ref,
            recipient_durable_receipt: wire.recipient_durable_receipt,
            realm_id: wire.realm_id,
            strand_id: wire.strand_id,
            mls_group_id: wire.mls_group_id,
            epoch: wire.epoch,
        };
        request.validate_shape().map_err(serde::de::Error::custom)?;
        Ok(request)
    }
}

impl Serialize for KeyPackagesConsumeRequestBody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (device_id, agent_id, agent_method, agent_event_id) =
            keypackage_consumer_to_wire(&self.consumer);
        KeyPackagesConsumeRequestBodyWire {
            owner_account_id: self.owner_account_id.clone(),
            key_package_refs: self.key_package_refs.clone(),
            consumer_device_id: device_id,
            consumer_agent_id: agent_id,
            consumer_agent_verification_method: agent_method,
            consumer_agent_key_authorize_event_id: agent_event_id,
            claim_ids: self.claim_ids.clone(),
            welcome_ref: self.welcome_ref.clone(),
            recipient_durable_receipt: self.recipient_durable_receipt.clone(),
            signature: self.signature.clone(),
            realm_id: self.realm_id.clone(),
            strand_id: self.strand_id.clone(),
            mls_group_id: self.mls_group_id.clone(),
            epoch: self.epoch,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeyPackagesConsumeRequestBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = KeyPackagesConsumeRequestBodyWire::deserialize(deserializer)?;
        let consumer = keypackage_consumer_from_wire::<D::Error>(
            wire.consumer_device_id,
            wire.consumer_agent_id,
            wire.consumer_agent_verification_method,
            wire.consumer_agent_key_authorize_event_id,
        )?;
        let request = Self {
            owner_account_id: wire.owner_account_id,
            key_package_refs: wire.key_package_refs,
            consumer,
            claim_ids: wire.claim_ids,
            welcome_ref: wire.welcome_ref,
            recipient_durable_receipt: wire.recipient_durable_receipt,
            signature: wire.signature,
            realm_id: wire.realm_id,
            strand_id: wire.strand_id,
            mls_group_id: wire.mls_group_id,
            epoch: wire.epoch,
        };
        request.validate_shape().map_err(serde::de::Error::custom)?;
        Ok(request)
    }
}

impl KeyPackagesConsumeRequestBody {
    #[must_use]
    pub fn unsigned(&self) -> KeyPackagesConsumeUnsignedRequest {
        KeyPackagesConsumeUnsignedRequest {
            owner_account_id: self.owner_account_id.clone(),
            key_package_refs: self.key_package_refs.clone(),
            consumer: self.consumer.clone(),
            claim_ids: self.claim_ids.clone(),
            welcome_ref: self.welcome_ref.clone(),
            recipient_durable_receipt: self.recipient_durable_receipt.clone(),
            realm_id: self.realm_id.clone(),
            strand_id: self.strand_id.clone(),
            mls_group_id: self.mls_group_id.clone(),
            epoch: self.epoch,
        }
    }

    pub fn validate_shape(&self) -> Result<(), &'static str> {
        let unsigned = self.unsigned();
        unsigned.validate_shape()?;
        if self.owner_account_id != self.recipient_durable_receipt.recipient_principal_id {
            return Err("KeyPackage consume owner and durable recipient principal mismatch");
        }
        if let KeyPackageConsumer::NativeAgent {
            consumer_agent_verification_method,
            ..
        } = &self.consumer
            && self.signature.kid.as_str() != consumer_agent_verification_method.as_str()
        {
            return Err("Native Agent consume signature kid mismatch");
        }
        Ok(())
    }
}

impl KeyPackagesConsumeUnsignedRequest {
    #[must_use]
    pub fn into_signed(self, signature: KeyOperationSignature) -> KeyPackagesConsumeRequestBody {
        KeyPackagesConsumeRequestBody {
            owner_account_id: self.owner_account_id,
            key_package_refs: self.key_package_refs,
            consumer: self.consumer,
            signature,
            claim_ids: self.claim_ids,
            welcome_ref: self.welcome_ref,
            recipient_durable_receipt: self.recipient_durable_receipt,
            realm_id: self.realm_id,
            strand_id: self.strand_id,
            mls_group_id: self.mls_group_id,
            epoch: self.epoch,
        }
    }
}

impl KeyPackagesConsumeUnsignedRequest {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        self.recipient_durable_receipt.validate_shape()?;
        if self.key_package_refs.is_empty() || self.claim_ids.is_empty() {
            return Err("KeyPackage consume request requires claims and KeyPackage refs");
        }
        if !self.key_package_refs.iter().any(|keypackage_ref| {
            keypackage_ref == self.recipient_durable_receipt.key_package_ref.as_str()
        }) || self.welcome_ref != self.recipient_durable_receipt.welcome_ref
        {
            return Err("KeyPackage consume request durable receipt coordinates mismatch");
        }
        if self
            .realm_id
            .as_ref()
            .is_some_and(|realm_id| realm_id != &self.recipient_durable_receipt.realm_id)
            || self
                .mls_group_id
                .as_ref()
                .is_some_and(|group_id| group_id != &self.recipient_durable_receipt.mls_group_id)
            || self
                .epoch
                .is_some_and(|epoch| epoch != self.recipient_durable_receipt.mls_epoch)
        {
            return Err("KeyPackage consume request MLS coordinates mismatch");
        }
        match (&self.consumer, &self.recipient_durable_receipt.recipient) {
            (
                KeyPackageConsumer::Device { consumer_device_id },
                RecipientMlsDurableSigner::Device {
                    recipient_device_id,
                    ..
                },
            ) if consumer_device_id == recipient_device_id => {}
            (
                KeyPackageConsumer::NativeAgent {
                    consumer_agent_id,
                    consumer_agent_verification_method,
                    consumer_agent_key_authorize_event_id,
                },
                RecipientMlsDurableSigner::NativeAgent {
                    recipient_agent_id,
                    recipient_agent_verification_method,
                    agent_key_authorize_event_id,
                    ..
                },
            ) if consumer_agent_id == recipient_agent_id
                && consumer_agent_verification_method == recipient_agent_verification_method
                && consumer_agent_key_authorize_event_id == agent_key_authorize_event_id => {}
            _ => return Err("KeyPackage consume requester and durable recipient mismatch"),
        }
        Ok(())
    }
}

pub fn keypackages_consume_signing_input(
    unsigned: &KeyPackagesConsumeUnsignedRequest,
) -> arkret_canonical::Result<Vec<u8>> {
    keypackage_signing_input(KEYPACKAGES_CONSUME_SIGNATURE_DOMAIN, unsigned)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageConsumeReceipt {
    pub domain: NonEmptyString,
    pub claim_request_id: Base64UrlString,
    pub claim_ids: Vec<NonEmptyString>,
    #[serde(rename = "keypackage_refs")]
    pub key_package_refs: KeyPackageRefArray,
    pub recipient_durable_receipt: RecipientMlsDurableReceipt,
    pub welcome_ref: NonEmptyString,
    pub realm_id: RealmId,
    pub mls_group_id: NonEmptyString,
    pub mls_epoch: u64,
    pub source_service_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub consumed_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

impl KeyPackageConsumeReceipt {
    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        signed_receipt_canonical_signing_bytes(self, self.domain.as_str())
    }

    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.domain.as_str() != "ak.keypackage.consume-receipt.v1" {
            return Err("KeyPackage consume receipt domain mismatch");
        }
        self.recipient_durable_receipt.validate_shape()?;
        if self.claim_ids.is_empty()
            || self.key_package_refs.is_empty()
            || !self.key_package_refs.iter().any(|keypackage_ref| {
                keypackage_ref == self.recipient_durable_receipt.key_package_ref.as_str()
            })
            || self.welcome_ref != self.recipient_durable_receipt.welcome_ref
            || self.realm_id != self.recipient_durable_receipt.realm_id
            || self.mls_group_id != self.recipient_durable_receipt.mls_group_id
            || self.mls_epoch != self.recipient_durable_receipt.mls_epoch
        {
            return Err("KeyPackage consume receipt coordinates mismatch");
        }
        Ok(())
    }
}

fn signed_receipt_canonical_signing_bytes(
    value: &impl Serialize,
    domain: &str,
) -> arkret_canonical::Result<Vec<u8>> {
    let mut unsigned = serde_json::to_value(value)?;
    let object = unsigned.as_object_mut().ok_or_else(|| {
        arkret_canonical::CanonicalError::Protocol(
            "signed receipt must serialize as an object".to_owned(),
        )
    })?;
    object.remove("signature");
    keypackage_signing_input(&format!("{domain}\n"), &unsigned)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesConsumeOutcome {
    pub consumed: KeyPackageRefArray,
    pub consume_receipt: KeyPackageConsumeReceipt,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Failure>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesRevokeRequestBody {
    pub owner_account_id: DidCoreId,
    #[serde(rename = "keypackage_refs")]
    pub key_package_refs: KeyPackageRefArray,
    pub device_id: DeviceId,
    pub signature: KeyOperationSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<NonEmptyString>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesRevokeUnsignedRequest {
    pub owner_account_id: DidCoreId,
    #[serde(rename = "keypackage_refs")]
    pub key_package_refs: KeyPackageRefArray,
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NonEmptyString>,
}

impl KeyPackagesRevokeRequestBody {
    #[must_use]
    pub fn unsigned(&self) -> KeyPackagesRevokeUnsignedRequest {
        KeyPackagesRevokeUnsignedRequest {
            owner_account_id: self.owner_account_id.clone(),
            key_package_refs: self.key_package_refs.clone(),
            device_id: self.device_id.clone(),
            reason: self.reason.clone(),
        }
    }
}

impl KeyPackagesRevokeUnsignedRequest {
    #[must_use]
    pub fn into_signed(self, signature: KeyOperationSignature) -> KeyPackagesRevokeRequestBody {
        KeyPackagesRevokeRequestBody {
            owner_account_id: self.owner_account_id,
            key_package_refs: self.key_package_refs,
            device_id: self.device_id,
            signature,
            reason: self.reason,
        }
    }
}

pub fn keypackages_revoke_signing_input(
    unsigned: &KeyPackagesRevokeUnsignedRequest,
) -> arkret_canonical::Result<Vec<u8>> {
    keypackage_signing_input(KEYPACKAGES_REVOKE_SIGNATURE_DOMAIN, unsigned)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesRevokeOutcome {
    pub revoked: KeyPackageRefArray,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Failure>,
}

/// Transparent wrapper over `KeyBackup` for the `ak.self.keys.command.put_backup`
/// request body Salvo OpenAPI bindings.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeysBackupsPutRequestBody(pub KeyBackup);

/// Transparent wrapper over `KeyBackup` for the `ak.self.keys.read.get_backup`
/// outcome Salvo OpenAPI bindings.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeysBackupsGetOutcome(pub KeyBackup);
