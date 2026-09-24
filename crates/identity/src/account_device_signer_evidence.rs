//! Offline verification of the retained ordinary account-device evidence root
//! and of the `producer_device_evidence` carried by a cross-Station
//! `authority_forward`.

use arkret_canonical::DigestSuite;
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_signatures::{Ed25519DetachedJwsVerifier, EventProofBuilder, PublicKeyMaterial};
use arkret_wire::{
    AccountId, DeviceId, Did, DidCoreId, ErrorCode, Event, HumanDeviceProducer, WireError,
};
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

fn rejected(code: ErrorCode, message: impl Into<String>) -> IdentityError {
    IdentityError::Wire(WireError::ProtocolCode {
        code,
        message: message.into(),
    })
}

fn signature_invalid(message: impl Into<String>) -> IdentityError {
    rejected(ErrorCode::SignatureInvalid, message)
}

fn device_unauthorized(message: impl Into<String>) -> IdentityError {
    rejected(ErrorCode::DeviceUnauthorized, message)
}

fn method_controller(method: &str) -> Option<Did> {
    let (did, fragment) = method.split_once('#')?;
    if fragment.is_empty() {
        return None;
    }
    Did::new(did.to_owned()).ok()
}

/// Admit the human-device producer of an Event forwarded by another Station.
///
/// This is the governance Station's whole cross-Station signer resolution for
/// a human Account device: the `producer_device_evidence` carried by
/// `authority_forward` is the only admissible source. Every failure is a
/// [`WireError::ProtocolCode`] carrying an already-active error code, and the
/// caller MUST reject with zero writes. The steps run in this order:
///
/// 1. the authenticated `Source-Service-ID` equals the attested `account_id.station_id`
///    (`signature_invalid`);
/// 2. the carried Service resolution authenticates the attestation assertion method and Station
///    identity at `attested_at`, and the attestation signature verifies (`signature_invalid`);
/// 3. `now` is before the attestation `expires_at` (`device_unauthorized`);
/// 4. the original `authorization_window` covers both the Event `created_at` and `now`
///    (`device_unauthorized`), and the device is active (`device_revoked` otherwise);
/// 5. the attested Account and device equal the producer and its proof fragment, and
///    `device_signing_key_did` verifies the producer proof (`signature_invalid`).
///
/// An Event whose actual signer is not a human Account device has no evidence
/// to verify (`schema_violation`). `now` is supplied by the caller; this
/// function never reads a clock. An exact duplicate of an already committed
/// Event returns its original outcome before this check runs, so an expired
/// evidence object never turns a committed Event into a failure.
pub fn verify_forwarded_human_producer(
    evidence: &AccountDeviceSignerEvidence,
    event: &Event,
    source_service_id: &DidCoreId,
    digest_suite: DigestSuite,
    now: DateTime<Utc>,
) -> Result<HumanDeviceProducer> {
    let producer = event.human_device_producer()?.ok_or_else(|| {
        rejected(
            ErrorCode::SchemaViolation,
            "producer_device_evidence is forbidden unless the producer is a human Account device",
        )
    })?;
    let attestation = &evidence.device_projection_attestation;
    let core = &attestation.attestation;
    let station_id = &core.account_id.station_id;

    if source_service_id != station_id {
        return Err(signature_invalid(
            "authenticated Source-Service-ID is not the attested Account Station",
        ));
    }

    if &evidence.service_resolution.service_id != station_id {
        return Err(signature_invalid(
            "producer device evidence Service resolution names another Station",
        ));
    }
    let attester = method_controller(attestation.proof.verification_method.as_str())
        .ok_or_else(|| signature_invalid("attestation proof method has no DID controller"))?;
    if attester != evidence.service_resolution.normalized_did_document.id
        || arkret_wire::project_did_to_core_id(&attester).ok().as_ref() != Some(station_id)
    {
        return Err(signature_invalid(
            "attestation proof method is not controlled by the attested Account Station",
        ));
    }
    if attestation.proof.created_at != core.attested_at {
        return Err(signature_invalid(
            "attestation proof timestamp differs from attested_at",
        ));
    }
    let document = crate::service_resolution_evidence::authenticated_service_document_at(
        &evidence.service_resolution,
        station_id,
        core.attested_at,
    )
    .map_err(|error| signature_invalid(error.to_string()))?;
    crate::validate_verification_method_relationship(
        &document,
        &attestation.proof.verification_method,
        &document.id,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| signature_invalid(error.to_string()))?;
    let station_key = crate::jws::resolve_ed25519_pubkey_from_document(
        &document,
        attestation.proof.verification_method.as_str(),
    )
    .map_err(|error| signature_invalid(error.to_string()))?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &attestation.proof.jws,
            &attestation.proof_signing_bytes()?,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: station_key.to_bytes().to_vec(),
            },
        )
        .map_err(|_| signature_invalid("device projection attestation signature is invalid"))?;

    if now >= core.expires_at {
        return Err(device_unauthorized(
            "producer device evidence is past its attestation expires_at",
        ));
    }

    let window = &core.authorization_window;
    let covers =
        |at: DateTime<Utc>| at >= window.not_before && window.expires_at.is_none_or(|end| at < end);
    if !covers(event.created_at) || !covers(now) {
        return Err(device_unauthorized(
            "device authorization window does not cover the Event created_at and the current time",
        ));
    }
    if !core.device_status.is_active() {
        return Err(rejected(
            ErrorCode::DeviceRevoked,
            "producer device evidence does not attest an active device",
        ));
    }

    if core.account_id != producer.account_id || core.device_id != producer.device_id {
        return Err(signature_invalid(
            "producer device evidence attests another Account or device",
        ));
    }
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        rejected(
            ErrorCode::SchemaViolation,
            "Event must carry producer_proof",
        )
    })?;
    let producer_did = method_controller(proof.verification_method.as_str())
        .ok_or_else(|| signature_invalid("producer proof method has no DID controller"))?;
    if arkret_wire::project_did_to_core_id(&producer_did)
        .ok()
        .as_ref()
        != Some(&producer.account_id.principal_id)
    {
        return Err(signature_invalid(
            "producer proof method is not controlled by the producer Account",
        ));
    }
    let multibase = core
        .device_signing_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| signature_invalid("attested device signing key is not did:key"))?;
    let envelope = EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| rejected(ErrorCode::SchemaViolation, error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &envelope,
        &event.actor_id,
        &PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        },
        digest_suite,
    )
    .map_err(|error| signature_invalid(format!("producer proof does not verify: {error}")))?;
    Ok(producer)
}
