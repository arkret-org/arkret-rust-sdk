//! Key-package HTTP request/outcome DTO counterparts for the
//! `ak.self.keys.*` key-package operations
//! (`service-operation-dtos.schema.json`). Pure wire shapes; upload,
//! claim, and consumption behavior lives with the transport and server
//! crates.

use std::collections::BTreeSet;

use arkret_wire::{
    Base64UrlString, DeviceId, Did, FederatedDeviceSigningKeyEvidence, Hash, NonEmptyString, Proof,
    RealmId, StrandId, TypedTrustDomainId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::artifacts_keys::{
    Failure, KeyOperationSignature, KeyPackageClaimRecord, KeyPackageRefArray,
    KeyPackageUploadEntry,
};
use crate::key_backup::KeyBackup;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesUploadRequestBody {
    pub principal_id: Did,
    pub device_id: DeviceId,
    #[serde(default)]
    pub key_packages: Vec<KeyPackageUploadEntry>,
    pub device_signature: KeyOperationSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesUploadOutcome {
    pub accepted: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Failure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_package_refs: KeyPackageRefArray,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_count: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesClaimRequestBody {
    pub target_principal_id: Did,
    pub intended_realm_id: RealmId,
    pub requester: Did,
    pub required_capabilities: Vec<String>,
    pub claim_nonce: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_device_ids: Vec<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimal_metadata_allowed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesClaimOutcome {
    #[serde(default)]
    pub claims: Vec<KeyPackageClaimRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Failure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_count: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PeerKeyPackageClaimPurpose {
    RealmMembership,
    DirectConversation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackageRequesterAuthorization {
    pub verification_method: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssk_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<NonEmptyString>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub signed_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimUnsignedRequest {
    pub claim_request_id: Base64UrlString,
    pub target_principal_id: Did,
    pub requester: Did,
    pub intended_realm_id: RealmId,
    pub mls_group_id: NonEmptyString,
    pub claim_purpose: PeerKeyPackageClaimPurpose,
    pub required_capabilities: Vec<NonEmptyString>,
    pub claim_nonce: Base64UrlString,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_device_ids: Vec<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimal_metadata_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_key: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_last_resort: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimTransportBinding {
    pub source_service_id: Did,
    pub destination_service_id: Did,
    pub source_trust_domain: TypedTrustDomainId,
    pub destination_trust_domain: TypedTrustDomainId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimAuthorizationDraft {
    pub request: PeerKeyPackagesClaimUnsignedRequest,
    pub transport_binding: PeerKeyPackagesClaimTransportBinding,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimRequestBody {
    pub claim_request_id: Base64UrlString,
    pub target_principal_id: Did,
    pub requester: Did,
    pub intended_realm_id: RealmId,
    pub mls_group_id: NonEmptyString,
    pub claim_purpose: PeerKeyPackageClaimPurpose,
    pub required_capabilities: Vec<NonEmptyString>,
    pub claim_nonce: Base64UrlString,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_device_ids: Vec<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimal_metadata_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_key: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_last_resort: Option<bool>,
    pub requester_authorization: PeerKeyPackageRequesterAuthorization,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_signing_key_evidence: Option<FederatedDeviceSigningKeyEvidence>,
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
            minimal_metadata_allowed: self.minimal_metadata_allowed,
            timeout_ms: self.timeout_ms,
            strand_id: self.strand_id.clone(),
            pair_key: self.pair_key.clone(),
            allow_last_resort: self.allow_last_resort,
        }
    }

    pub fn validate_shape(&self) -> Result<(), PeerKeyPackageClaimShapeError> {
        validate_peer_claim_fields(&self.unsigned_request())?;
        let authorization = &self.requester_authorization;
        if authorization.signature.kid.as_str() != authorization.verification_method.as_str() {
            return Err(PeerKeyPackageClaimShapeError::VerificationMethodMismatch);
        }
        match (
            authorization.ssk_generation,
            authorization.requester_device_id.as_ref(),
            authorization.device_authorize_event_id.as_ref(),
        ) {
            (Some(generation), None, None) if generation > 0 => {
                if self.requester_signing_key_evidence.is_some() {
                    return Err(PeerKeyPackageClaimShapeError::SignerEvidenceMismatch);
                }
                Ok(())
            }
            (None, Some(device_id), Some(authorize_event_id)) => {
                if let Some(evidence) = &self.requester_signing_key_evidence {
                    evidence
                        .validate_shape()
                        .map_err(|_| PeerKeyPackageClaimShapeError::SignerEvidenceMismatch)?;
                    if evidence.actor_id != self.requester
                        || &evidence.device_id != device_id
                        || evidence.verification_method
                            != authorization.verification_method.as_str()
                        || evidence.device_authorize_event.event_id.as_str()
                            != authorize_event_id.as_str()
                    {
                        return Err(PeerKeyPackageClaimShapeError::SignerEvidenceMismatch);
                    }
                }
                Ok(())
            }
            _ => Err(PeerKeyPackageClaimShapeError::InvalidAuthorizationModel),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackageClaimReceipt {
    pub claim_request_id: Base64UrlString,
    pub request_digest: Hash,
    pub claims_digest: Hash,
    pub source_service_id: Did,
    pub destination_service_id: Did,
    pub request: PeerKeyPackagesClaimUnsignedRequest,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub claimed_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimOutcome {
    pub claim_request_id: Base64UrlString,
    pub claims: Vec<KeyPackageClaimRecord>,
    pub claim_receipt: PeerKeyPackageClaimReceipt,
}

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
        let claims_digest = arkret_canonical::canonical_sha256(&self.claims)
            .map_err(|_| PeerKeyPackageClaimShapeError::InvalidClaimOutcome)?;
        if receipt.claims_digest.as_str() != claims_digest {
            return Err(PeerKeyPackageClaimShapeError::InvalidClaimOutcome);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PeerKeyPackagesClaimQueryState {
    Unknown,
    Pending,
    Claimed,
    ClaimFailed,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimQueryOutcome {
    pub claim_request_id: Base64UrlString,
    pub state: PeerKeyPackagesClaimQueryState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_outcome: Option<PeerKeyPackagesClaimOutcome>,
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
                    && self.retry_after_ms.is_some_and(|value| value > 0)
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::Claimed
            | PeerKeyPackagesClaimQueryState::Expired
            | PeerKeyPackagesClaimQueryState::Revoked
                if self.claim_outcome.is_some()
                    && self.retry_after_ms.is_none()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::ClaimFailed
                if self.claim_outcome.is_none()
                    && self.retry_after_ms.is_none()
                    && self.error_code == Some(PeerKeyPackageClaimErrorCode::ClaimFailed) =>
            {
                Ok(())
            }
            PeerKeyPackagesClaimQueryState::Unknown
                if self.claim_outcome.is_none()
                    && self.retry_after_ms.is_none()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            _ => Err(PeerKeyPackageClaimShapeError::InvalidQueryOutcome),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
    if request.claim_purpose == PeerKeyPackageClaimPurpose::DirectConversation
        && (request.strand_id.is_none()
            || request.pair_key.is_none()
            || request.allow_last_resort == Some(true))
    {
        return Err(PeerKeyPackageClaimShapeError::InvalidDirectConversationFields);
    }
    Ok(())
}

#[derive(Serialize)]
struct PeerKeyPackageAuthorizationTranscript<'a> {
    authorization: PeerKeyPackageAuthorizationMetadata<'a>,
    request: &'a PeerKeyPackagesClaimUnsignedRequest,
    transport_binding: &'a PeerKeyPackagesClaimTransportBinding,
}

#[derive(Serialize)]
struct PeerKeyPackageAuthorizationMetadata<'a> {
    verification_method: &'a NonEmptyString,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_device_id: Option<&'a DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssk_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_authorize_event_id: Option<&'a NonEmptyString>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    signed_at: DateTime<Utc>,
}

pub fn peer_keypackage_claim_authorization_signing_bytes(
    draft: &PeerKeyPackagesClaimAuthorizationDraft,
    authorization: &PeerKeyPackageRequesterAuthorization,
) -> arkret_canonical::Result<Vec<u8>> {
    let transcript = PeerKeyPackageAuthorizationTranscript {
        authorization: PeerKeyPackageAuthorizationMetadata {
            verification_method: &authorization.verification_method,
            requester_device_id: authorization.requester_device_id.as_ref(),
            ssk_generation: authorization.ssk_generation,
            device_authorize_event_id: authorization.device_authorize_event_id.as_ref(),
            signed_at: authorization.signed_at,
        },
        request: &draft.request,
        transport_binding: &draft.transport_binding,
    };
    let canonical = arkret_canonical::canonical_json_bytes(&transcript)?;
    let mut bytes = b"ak.peer-keypackage-claim-authorization-v1\n".to_vec();
    bytes.extend(canonical);
    Ok(bytes)
}

#[derive(Serialize)]
struct PeerKeyPackageClaimReceiptUnsigned<'a> {
    claim_request_id: &'a Base64UrlString,
    request_digest: &'a Hash,
    claims_digest: &'a Hash,
    source_service_id: &'a Did,
    destination_service_id: &'a Did,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesConsumeRequestBody {
    #[serde(default)]
    pub key_package_refs: Vec<String>,
    pub consumer_device_id: DeviceId,
    pub signature: KeyOperationSignature,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claim_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesConsumeOutcome {
    #[serde(default)]
    pub consumed: KeyPackageRefArray,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Failure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesRevokeRequestBody {
    #[serde(default)]
    pub key_package_refs: Vec<String>,
    pub device_id: DeviceId,
    pub signature: KeyOperationSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct KeyPackagesRevokeOutcome {
    #[serde(default)]
    pub revoked: KeyPackageRefArray,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Failure>,
}

/// Transparent wrapper over `KeyBackup` for the `ak.self.keys.command.put_backup`
/// request body Salvo OpenAPI bindings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = KeyBackup)))]
pub struct KeysBackupsPutRequestBody(pub KeyBackup);

/// Transparent wrapper over `KeyBackup` for the `ak.self.keys.query.get_backup`
/// outcome Salvo OpenAPI bindings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = KeyBackup)))]
pub struct KeysBackupsGetOutcome(pub KeyBackup);

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn peer_claim_request() -> PeerKeyPackagesClaimRequestBody {
        serde_json::from_value(json!({
            "claim_request_id": "AAAAAAAAAAAAAAAAAAAAAA",
            "target_principal_id": "did:webvh:z6mkfixture:bob.example",
            "requester": "did:webvh:z6mkfixture:alice.example",
            "intended_realm_id": "ak:realm:0196419b-0000-7000-8000-000000000010",
            "mls_group_id": "dm-group-1",
            "claim_purpose": "direct_conversation",
            "required_capabilities": ["ak.feature.mls_rfc9420.v1"],
            "claim_nonce": "BBBBBBBBBBBBBBBBBBBBBB",
            "expires_at": "2026-07-21T00:05:00.000Z",
            "strand_id": "ak:strand:0196419b-0000-7000-8000-000000000011",
            "pair_key": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
            "allow_last_resort": false,
            "requester_authorization": {
                "verification_method": "did:webvh:z6mkfixture:alice.example#ssk-7",
                "ssk_generation": 7,
                "signed_at": "2026-07-21T00:00:00.000Z",
                "signature": {
                    "kid": "did:webvh:z6mkfixture:alice.example#ssk-7",
                    "alg": "EdDSA",
                    "sig": "c2lnbmF0dXJl"
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn direct_peer_claim_shape_forbids_last_resort() {
        let request = peer_claim_request();
        assert_eq!(request.validate_shape(), Ok(()));

        let mut invalid = request;
        invalid.allow_last_resort = Some(true);
        assert_eq!(
            invalid.validate_shape(),
            Err(PeerKeyPackageClaimShapeError::InvalidDirectConversationFields)
        );
    }

    #[test]
    fn authorization_transcript_binds_explicit_transport_destination() {
        let request = peer_claim_request();
        let draft: PeerKeyPackagesClaimAuthorizationDraft = serde_json::from_value(json!({
            "request": request.unsigned_request(),
            "transport_binding": {
                "source_service_id": "did:webvh:z6mkfixture:server-alpha.example",
                "destination_service_id": "did:webvh:z6mkfixture:server-beta.example",
                "source_trust_domain": "ak:trust_domain:fixture.example",
                "destination_trust_domain": "ak:trust_domain:fixture.example"
            }
        }))
        .unwrap();
        let bytes = peer_keypackage_claim_authorization_signing_bytes(
            &draft,
            &request.requester_authorization,
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("ak.peer-keypackage-claim-authorization-v1\n"));
        assert!(text.contains("did:webvh:z6mkfixture:server-beta.example"));
        assert!(text.contains("ak:trust_domain:fixture.example"));
        assert!(!text.contains("\"signature\""));
    }

    #[test]
    fn query_outcome_enforces_state_dependent_fields() {
        let pending: PeerKeyPackagesClaimQueryOutcome = serde_json::from_value(json!({
            "claim_request_id": "AAAAAAAAAAAAAAAAAAAAAA",
            "state": "pending",
            "retry_after_ms": 250
        }))
        .unwrap();
        assert_eq!(pending.validate_shape(), Ok(()));

        let invalid: PeerKeyPackagesClaimQueryOutcome = serde_json::from_value(json!({
            "claim_request_id": "AAAAAAAAAAAAAAAAAAAAAA",
            "state": "unknown",
            "retry_after_ms": 250
        }))
        .unwrap();
        assert_eq!(
            invalid.validate_shape(),
            Err(PeerKeyPackageClaimShapeError::InvalidQueryOutcome)
        );
    }
}
