//! Offline verification of the retained ordinary account-device evidence root.

use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{AccountId, DeviceId};
use chrono::{DateTime, Utc};

use crate::{DidVerificationRelationship, IdentityError, Result};

/// Verify the complete Service method history and exact signed projection at
/// the attestation's source time. The short cache deadline does not make a
/// historical signer fact expire; a current keys/query caller must separately
/// require `now < attestation.expires_at` and current lifecycle status.
pub fn verify_historical_account_device_signer_evidence(
    evidence: &AccountDeviceSignerEvidence,
    account_id: &AccountId,
    device_id: &DeviceId,
) -> Result<()> {
    evidence
        .validate_binding(account_id, device_id)
        .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    let attestation = &evidence.device_projection_attestation;
    let source_time = attestation.attestation.attested_at;
    let document = crate::service_resolution_evidence::authenticated_service_document_at(
        &evidence.service_resolution,
        &account_id.station_id,
        source_time,
    )?;
    let did = &document.id;
    crate::validate_verification_method_relationship(
        &document,
        &attestation.proof.verification_method,
        did,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    let key = crate::jws::resolve_ed25519_pubkey_from_document(
        &document,
        attestation.proof.verification_method.as_str(),
    )
    .map_err(|error| IdentityError::Protocol(error.to_string()))?;
    arkret_signatures::device_projection::verify_device_projection_attestation(
        attestation,
        &key,
        source_time,
    )
    .map_err(|error| IdentityError::Protocol(error.to_string()))
}

/// Current-query verifier: historical closure plus a fresh cache deadline.
pub fn verify_current_account_device_signer_evidence(
    evidence: &AccountDeviceSignerEvidence,
    account_id: &AccountId,
    device_id: &DeviceId,
    now: DateTime<Utc>,
) -> Result<()> {
    verify_historical_account_device_signer_evidence(evidence, account_id, device_id)?;
    if now
        >= evidence
            .device_projection_attestation
            .attestation
            .expires_at
    {
        return Err(IdentityError::Protocol(
            "account-device signer evidence current-query cache deadline elapsed".into(),
        ));
    }
    Ok(())
}
