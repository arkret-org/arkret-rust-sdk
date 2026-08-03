//! Key-package HTTP request/outcome DTO counterparts for the
//! `ak.self.keys.*` key-package operations
//! (`service-operation-dtos.schema.json`). Pure wire shapes; upload,
//! claim, and consumption behavior lives with the transport and server
//! crates.

use std::collections::BTreeSet;

use arkret_wire::{
    Base64UrlString, DeviceId, Did, DidUrl, FederatedDeviceSigningKeyEvidence, Hash,
    NonEmptyString, RealmId, StrandId, TypedTrustDomainId,
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
pub struct KeyPackagesUploadRequestBody {
    pub principal_id: Did,
    pub device_id: DeviceId,
    #[serde(default)]
    pub key_packages: Vec<KeyPackageUploadEntry>,
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
    pub principal_id: Did,
    pub device_id: DeviceId,
    #[serde(default)]
    pub key_packages: Vec<KeyPackageUploadEntry>,
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
        let mut key_packages = self.key_packages.clone();
        for entry in &mut key_packages {
            entry.device_signature = None;
        }
        KeyPackagesUploadUnsignedRequest {
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            key_packages,
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
            key_packages: self.key_packages,
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
        key_package: Base64UrlString::new(record.key_package.clone())?,
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
    principal_id: &'a Did,
    device_id: &'a DeviceId,
    key_package: KeyPackageUploadEntry,
}

pub fn keypackage_upload_entry_signing_input(
    principal_id: &Did,
    device_id: &DeviceId,
    entry: &KeyPackageUploadEntry,
) -> arkret_canonical::Result<Vec<u8>> {
    let mut key_package = entry.clone();
    key_package.device_signature = None;
    keypackage_signing_input(
        KEYPACKAGES_UPLOAD_SIGNATURE_DOMAIN,
        &KeyPackageUploadEntryUnsigned {
            principal_id,
            device_id,
            key_package,
        },
    )
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPackagesUploadOutcome {
    pub accepted: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Failure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_package_refs: KeyPackageRefArray,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_count: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPackageClaimProofKind {
    #[serde(rename = "detached_jws")]
    DetachedJws,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPackageClaimProofAlgorithm {
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPackageClaimProofPurpose {
    #[serde(rename = "holder_acceptance")]
    HolderAcceptance,
}

/// Exact-one self KeyPackage claim authorization proof. The dedicated shape
/// makes `domain`, a non-DID audience, and an unregistered proof purpose
/// unrepresentable.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageClaimProof {
    pub kind: KeyPackageClaimProofKind,
    pub verification_method: DidUrl,
    pub alg: KeyPackageClaimProofAlgorithm,
    pub payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub audience: Did,
    pub proof_purpose: KeyPackageClaimProofPurpose,
    pub jws: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesClaimRequestBody {
    pub target_principal_id: Did,
    pub intended_realm_id: RealmId,
    pub requester: Did,
    pub required_capabilities: Vec<String>,
    pub claim_nonce: Base64UrlString,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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
    pub holder_acceptance_proof: KeyPackageClaimProof,
}

impl KeyPackagesClaimRequestBody {
    /// The protocol payload digest removes `holder_acceptance_proof` entirely and preserves
    /// every actually present optional request member.
    pub fn payload_digest(&self) -> Result<Hash, arkret_wire::Error> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("KeyPackagesClaimRequestBody serializes as an object")
            .remove("holder_acceptance_proof");
        Hash::new(arkret_canonical::canonical_sha256(&value)?)
            .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>, arkret_wire::Error> {
        let proof = &self.holder_acceptance_proof;
        Ok(arkret_canonical::canonical_json_bytes(
            &serde_json::json!({
                "context": "ak.keypackage-claim-request-proof-v1",
                "payload_digest": proof.payload_digest,
                "requester": self.requester,
                "target_principal_id": self.target_principal_id,
                "intended_realm_id": self.intended_realm_id,
                "claim_nonce": self.claim_nonce,
                "verification_method": proof.verification_method,
                "created_at": arkret_canonical::format_timestamp_canonical(proof.created_at),
                "proof_purpose": "holder_acceptance",
                "audience": proof.audience,
            }),
        )?)
    }

    pub fn validate_proof_shape(
        &self,
        authority_service_id: &Did,
        verifier_now: DateTime<Utc>,
    ) -> Result<Vec<u8>, arkret_wire::Error> {
        let nonce = arkret_canonical::base64url_decode(self.claim_nonce.as_str())?;
        if !(22..=128).contains(&self.claim_nonce.as_str().len()) || nonce.len() < 16 {
            return Err(arkret_wire::Error::Protocol(
                "claim_nonce must be 22..=128 canonical base64url characters carrying at least 128 bits"
                    .to_owned(),
            ));
        }
        let proof = &self.holder_acceptance_proof;
        if &proof.audience != authority_service_id
            || proof.payload_digest != self.payload_digest()?
            || !proof
                .verification_method
                .as_str()
                .starts_with(&format!("{}#", self.requester))
            || proof.created_at > verifier_now + Duration::seconds(60)
            || proof.created_at >= self.expires_at
            || self.expires_at > proof.created_at + Duration::seconds(300)
            || verifier_now >= self.expires_at
        {
            return Err(arkret_wire::Error::Protocol(
                "KeyPackage self-claim proof binding or freshness is invalid".to_owned(),
            ));
        }
        let parts = proof.jws.split('.').collect::<Vec<_>>();
        if parts.len() != 3 || !parts[1].is_empty() {
            return Err(arkret_wire::Error::Protocol(
                "KeyPackage self-claim proof must be a compact detached JWS".to_owned(),
            ));
        }
        self.proof_binding_bytes()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPackagesClaimOutcome {
    #[serde(default)]
    pub claims: Vec<KeyPackageClaimRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Failure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_count: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerKeyPackageClaimPurpose {
    RealmMembership,
    DirectConversation,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackageRequesterAuthorization {
    pub verification_method: DidUrl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssk_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<NonEmptyString>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub signed_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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
    pub last_resort_allowed: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimTransportBinding {
    pub source_service_id: Did,
    pub destination_service_id: Did,
    pub source_trust_domain: TypedTrustDomainId,
    pub destination_trust_domain: TypedTrustDomainId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackagesClaimAuthorizationDraft {
    pub request: PeerKeyPackagesClaimUnsignedRequest,
    pub transport_binding: PeerKeyPackagesClaimTransportBinding,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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
    pub last_resort_allowed: Option<bool>,
    pub requester_authorization: PeerKeyPackageRequesterAuthorization,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
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
            last_resort_allowed: self.last_resort_allowed,
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeyPackageClaimReceipt {
    pub claim_request_id: Base64UrlString,
    pub request_digest: Hash,
    pub claims_digest: Hash,
    pub source_service_id: Did,
    pub destination_service_id: Did,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_package_refs: Option<KeyPackageRefArray>,
    pub source_service_id: Did,
    pub destination_service_id: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub terminal_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
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
            || request.last_resort_allowed == Some(true))
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
    verification_method: &'a DidUrl,
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

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientMlsDurableReceipt {
    pub domain: NonEmptyString,
    pub claim_request_id: Base64UrlString,
    pub key_package_ref: NonEmptyString,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub recipient_service_id: Did,
    pub realm_id: RealmId,
    pub mls_group_id: NonEmptyString,
    pub mls_epoch: u64,
    pub welcome_ref: NonEmptyString,
    pub welcome_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub durable_at: DateTime<Utc>,
    pub device_verification_method: NonEmptyString,
    pub signature: KeyOperationSignature,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesConsumeRequestBody {
    pub owner_account_id: Did,
    pub key_package_refs: KeyPackageRefArray,
    pub consumer_device_id: DeviceId,
    pub claim_ids: Vec<NonEmptyString>,
    pub welcome_ref: NonEmptyString,
    pub recipient_durable_receipt: RecipientMlsDurableReceipt,
    pub signature: KeyOperationSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesConsumeUnsignedRequest {
    pub owner_account_id: Did,
    pub key_package_refs: KeyPackageRefArray,
    pub consumer_device_id: DeviceId,
    pub claim_ids: Vec<NonEmptyString>,
    pub welcome_ref: NonEmptyString,
    pub recipient_durable_receipt: RecipientMlsDurableReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
}

impl KeyPackagesConsumeRequestBody {
    #[must_use]
    pub fn unsigned(&self) -> KeyPackagesConsumeUnsignedRequest {
        KeyPackagesConsumeUnsignedRequest {
            owner_account_id: self.owner_account_id.clone(),
            key_package_refs: self.key_package_refs.clone(),
            consumer_device_id: self.consumer_device_id.clone(),
            claim_ids: self.claim_ids.clone(),
            welcome_ref: self.welcome_ref.clone(),
            recipient_durable_receipt: self.recipient_durable_receipt.clone(),
            realm_id: self.realm_id.clone(),
            strand_id: self.strand_id.clone(),
            mls_group_id: self.mls_group_id.clone(),
            epoch: self.epoch,
        }
    }
}

impl KeyPackagesConsumeUnsignedRequest {
    #[must_use]
    pub fn into_signed(self, signature: KeyOperationSignature) -> KeyPackagesConsumeRequestBody {
        KeyPackagesConsumeRequestBody {
            owner_account_id: self.owner_account_id,
            key_package_refs: self.key_package_refs,
            consumer_device_id: self.consumer_device_id,
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
    pub key_package_refs: KeyPackageRefArray,
    pub recipient_durable_receipt: RecipientMlsDurableReceipt,
    pub welcome_ref: NonEmptyString,
    pub realm_id: RealmId,
    pub mls_group_id: NonEmptyString,
    pub mls_epoch: u64,
    pub source_service_id: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub consumed_at: DateTime<Utc>,
    pub signature: KeyOperationSignature,
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
pub struct KeyPackagesRevokeRequestBody {
    #[serde(default)]
    pub key_package_refs: Vec<String>,
    pub device_id: DeviceId,
    pub signature: KeyOperationSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<NonEmptyString>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackagesRevokeUnsignedRequest {
    #[serde(default)]
    pub key_package_refs: Vec<String>,
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NonEmptyString>,
}

impl KeyPackagesRevokeRequestBody {
    #[must_use]
    pub fn unsigned(&self) -> KeyPackagesRevokeUnsignedRequest {
        KeyPackagesRevokeUnsignedRequest {
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
pub struct KeyPackagesRevokeOutcome {
    #[serde(default)]
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

/// Transparent wrapper over `KeyBackup` for the `ak.self.keys.query.get_backup`
/// outcome Salvo OpenAPI bindings.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
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
            "last_resort_allowed": false,
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
        invalid.last_resort_allowed = Some(true);
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

    #[test]
    fn keypackage_write_transcripts_match_canonical_fixture() {
        let upload: KeyPackagesUploadUnsignedRequest = serde_json::from_value(json!({
            "principal_id": "did:webvh:z6mkfixture:agent.example",
            "device_id": "ak:device:01964137-0000-7000-8000-00000000000d",
            "key_packages": [{
                "keypackage_id": "keypackage-fixture-001",
                "keypackage_ref": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "keypackage_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "key_package": "AA",
                "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
                "capabilities": ["mimi.content.v1", "ak.content.v1"],
                "expires_at": "2026-07-29T00:00:00.000Z",
                "created_at": "2026-07-22T00:00:00.000Z"
            }]
        }))
        .unwrap();
        let upload_input =
            String::from_utf8(keypackages_upload_signing_input(&upload).unwrap()).unwrap();
        assert_eq!(
            upload_input,
            concat!(
                "ak.self.keys.keypackages.upload.create\n",
                "{\"device_id\":\"ak:device:01964137-0000-7000-8000-00000000000d\",",
                "\"key_packages\":[{\"capabilities\":[\"mimi.content.v1\",\"ak.content.v1\"],",
                "\"cipher_suites\":[\"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519\"],",
                "\"created_at\":\"2026-07-22T00:00:00.000Z\",",
                "\"expires_at\":\"2026-07-29T00:00:00.000Z\",\"key_package\":\"AA\",",
                "\"keypackage_digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\",",
                "\"keypackage_id\":\"keypackage-fixture-001\",",
                "\"keypackage_ref\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\"}],",
                "\"principal_id\":\"did:webvh:z6mkfixture:agent.example\"}"
            )
        );

        let consume: KeyPackagesConsumeUnsignedRequest = serde_json::from_value(json!({
            "key_package_refs": ["sha256:1111111111111111111111111111111111111111111111111111111111111111"],
            "consumer_device_id": "ak:device:01964137-0000-7000-8000-00000000000d",
            "claim_ids": ["claim-fixture-001"],
            "welcome_ref": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "realm_id": "ak:realm:01964137-0000-7000-8000-00000000000f",
            "strand_id": "ak:strand:01964137-0000-7000-8000-00000000000e",
            "mls_group_id": "mls-fixture-group",
            "epoch": 1
        }))
        .unwrap();
        let consume_input =
            String::from_utf8(keypackages_consume_signing_input(&consume).unwrap()).unwrap();
        assert!(consume_input.starts_with(KEYPACKAGES_CONSUME_SIGNATURE_DOMAIN));
        assert!(!consume_input.contains("\"signature\""));
        assert!(!consume_input.contains(":null"));

        let revoke: KeyPackagesRevokeUnsignedRequest = serde_json::from_value(json!({
            "key_package_refs": ["sha256:1111111111111111111111111111111111111111111111111111111111111111"],
            "device_id": "ak:device:01964137-0000-7000-8000-00000000000d",
            "reason": "authorization_superseded"
        }))
        .unwrap();
        let revoke_input =
            String::from_utf8(keypackages_revoke_signing_input(&revoke).unwrap()).unwrap();
        assert_eq!(
            revoke_input,
            concat!(
                "ak.self.keys.keypackages.command.revoke\n",
                "{\"device_id\":\"ak:device:01964137-0000-7000-8000-00000000000d\",",
                "\"key_package_refs\":[\"sha256:1111111111111111111111111111111111111111111111111111111111111111\"],",
                "\"reason\":\"authorization_superseded\"}"
            )
        );
    }

    #[test]
    fn keypackage_record_upload_projection_is_shared_and_closed() {
        let mut record: MlsKeyPackageRecord = serde_json::from_value(json!({
            "keypackage_id": "keypackage-fixture-001",
            "principal_id": "did:webvh:z6mkfixture:agent.example",
            "device_id": "ak:device:01964137-0000-7000-8000-00000000000d",
            "key_package": "AA",
            "keypackage_ref": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
            "capabilities": ["mimi.content.v1", "ak.content.v1"],
            "state": "published",
            "created_at": "2026-07-22T00:00:00.000Z",
            "last_resort": false
        }))
        .unwrap();

        let ordinary = mls_key_package_record_upload_entry(&record).unwrap();
        assert_eq!(ordinary.keypackage_ref, record.keypackage_ref.as_str());
        assert_eq!(ordinary.keypackage_digest, record.keypackage_ref);
        assert_eq!(ordinary.expires_at, record.created_at + Duration::days(7));
        assert!(ordinary.device_signature.is_none());
        assert_eq!(ordinary.last_resort, None);

        record.expires_at = Some(record.created_at + Duration::hours(2));
        record.last_resort = true;
        let last_resort = mls_key_package_record_upload_entry(&record).unwrap();
        assert_eq!(last_resort.expires_at, record.expires_at.unwrap());
        assert_eq!(last_resort.last_resort, Some(true));
    }
}
