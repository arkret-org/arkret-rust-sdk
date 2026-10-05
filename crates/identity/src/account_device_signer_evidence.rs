//! Offline verification of the retained ordinary account-device evidence root
//! and of the `producer_device_evidence` carried by a cross-Station
//! `authority_forward`.

use arkret_canonical::DigestSuite;
use arkret_models_identity::{AccountDeviceSignerEvidence, ForwardAccountDeviceSignerEvidence};
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
/// Step 5 starts with the key-free producer-proof self-consistency
/// ([`Event::verify_producer_proof_self_consistency`]). An Event whose actual
/// signer is not a human Account device has no evidence to verify
/// (`schema_violation`). `now` is supplied by the caller; this
/// function never reads a clock. An exact duplicate of an already committed
/// Event returns its original outcome before this check runs, so an expired
/// evidence object never turns a committed Event into a failure.
pub fn verify_forwarded_human_producer(
    evidence: &ForwardAccountDeviceSignerEvidence,
    event: &Event,
    source_service_id: &DidCoreId,
    destination_service_id: &DidCoreId,
    forward_body_digest: &arkret_wire::Hash,
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
    let source = &core.event_authorization;
    let method = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| signature_invalid("Human Event lacks producer proof"))?;
    if source.event_id != event.event_id
        || source.verification_method != method.verification_method
        || &source.destination_service_id != destination_service_id
        || &source.forward_body_digest != forward_body_digest
        || !source.forward_body_digest.as_str().starts_with("sha256:")
        || source.authorization_ref.event_id != core.device_authorize_event_id
        || !matches!(
            &source.authorization_ref.stream_ref,
            arkret_wire::CommitStreamRef::Realm { .. }
        )
        || source.authorization_ref.stream_position > source.revision.stream_position
        || (source.authorization_ref.commit_id == source.revision.commit_id
            && source.authorization_ref.stream_position != source.revision.stream_position)
    {
        return Err(signature_invalid(
            "forward evidence does not bind the exact original Human source and destination",
        ));
    }
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
    if !covers(event.created_at) || !covers(method.created_at) || !covers(now) {
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
    event.verify_producer_proof_self_consistency(digest_suite)?;
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        rejected(
            ErrorCode::SchemaViolation,
            "Event must carry producer_proof",
        )
    })?;
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

/// Source fact obtained only after the original Station proof and actual Event Ed verify.
#[derive(Clone, Debug)]
pub struct VerifiedHumanHistoricalSignerFact {
    fact: arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact,
}
impl VerifiedHumanHistoricalSignerFact {
    pub fn fact(
        &self,
    ) -> &arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact {
        &self.fact
    }
    pub fn into_fact(
        self,
    ) -> arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact {
        self.fact
    }
}

pub fn verify_forwarded_human_signer_fact(
    evidence: &ForwardAccountDeviceSignerEvidence,
    event: &Event,
    source_service_id: &DidCoreId,
    destination_service_id: &DidCoreId,
    forward_body_digest: &arkret_wire::Hash,
    digest_suite: DigestSuite,
    now: DateTime<Utc>,
) -> Result<VerifiedHumanHistoricalSignerFact> {
    verify_forwarded_human_producer(
        evidence,
        event,
        source_service_id,
        destination_service_id,
        forward_body_digest,
        digest_suite,
        now,
    )?;
    let core = &evidence.device_projection_attestation.attestation;
    let source = &core.event_authorization;
    let encoded = core
        .device_signing_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| signature_invalid("forward device key is not did:key"))?;
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: encoded.to_owned(),
    };
    let raw = key
        .ed25519_bytes()
        .map_err(|error| signature_invalid(error.to_string()))?;
    let fact = arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact {
        event_id: event.event_id.clone(),
        actor: event.actual_signer().clone(),
        device_id: core.device_id.clone(),
        verification_method: source.verification_method.clone(),
        key: arkret_models_identity::ResolvedSignerKey {
            public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                raw,
            ))
            .map_err(|error| signature_invalid(error.to_string()))?,
            authorization_ref: source.authorization_ref.clone(),
            revision: source.revision.clone(),
            governance_generation: source.governance_generation,
        },
        accepted_at: source.accepted_at,
    };
    fact.validate_event_binding(event, digest_suite)?;
    Ok(VerifiedHumanHistoricalSignerFact { fact })
}

/// Verify original governance authority separately from the historical Human Event signature.
pub fn verify_historical_human_committed_event(
    full: &arkret_wire::CommittedEventFullView,
    fact: &arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact,
    authority: &crate::realm_authority_chain::VerifiedRealmAuthority,
    keys: &dyn crate::realm_authority_chain::RealmAuthorityKeyDirectory,
    digest_suite: DigestSuite,
) -> Result<VerifiedHumanHistoricalSignerFact> {
    fact.validate_commit_binding(full, digest_suite)?;
    authority
        .verify_committed_item(full, keys)
        .map_err(|error| signature_invalid(error.to_string()))?;
    verify_historical_human_event_signature(&full.event, fact, digest_suite)?;
    Ok(VerifiedHumanHistoricalSignerFact { fact: fact.clone() })
}

/// Requires a caller-authenticated original Commit before establishing its authority.
pub fn verify_historical_human_event_signature(
    event: &Event,
    fact: &arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact,
    digest_suite: DigestSuite,
) -> Result<()> {
    fact.validate_event_binding(event, digest_suite)?;
    let raw = arkret_canonical::base64url_decode(fact.key.public_key_b64u.as_str())
        .map_err(|error| signature_invalid(error.to_string()))?;
    let envelope = EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| signature_invalid(error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        event
            .producer_proof
            .as_ref()
            .ok_or_else(|| signature_invalid("Human Event lacks producer proof"))?,
        &envelope,
        &event.actor_id,
        &PublicKeyMaterial::Ed25519Raw { bytes: raw },
        digest_suite,
    )
    .map_err(|error| signature_invalid(error.to_string()))?;
    Ok(())
}

/// Verify every imported Human original under the already-verified historical governance chain.
/// The caller separately authenticates the new handoff's two signatures and frozen import cut.
pub fn verify_handoff_human_signer_inventory(
    request: &arkret_models_collaboration::authority_commit::AuthorityHandoffRequest,
    imported: &[arkret_wire::CommittedEventFullView],
    authority: &crate::realm_authority_chain::VerifiedRealmAuthority,
    keys: &dyn crate::realm_authority_chain::RealmAuthorityKeyDirectory,
) -> Result<Vec<VerifiedHumanHistoricalSignerFact>> {
    request.validate_new_handoff()?;
    request.validate_imported_signer_facts(imported)?;
    let mut verified = Vec::new();
    for entry in request.historical_signer_facts.as_deref().unwrap_or(&[]) {
        let full = imported
            .iter()
            .find(|full| {
                full.commit.commit_id == entry.target.commit_id
                    && full.commit.stream_ref == entry.target.stream_ref
                    && full.commit.stream_position == entry.target.stream_position
                    && full.event.event_id == entry.target.event_id
            })
            .ok_or_else(|| {
                signature_invalid("handoff inventory target is not an imported original")
            })?;
        let suite = arkret_canonical::canonical::digest_suite(
            full.event.event_id.digest_suite_code().as_str(),
        )
        .map_err(|error| signature_invalid(error.to_string()))?;
        verified.push(verify_historical_human_committed_event(
            full,
            &entry.producer_signer_fact,
            authority,
            keys,
            suite,
        )?);
    }
    Ok(verified)
}

/// Verify the exact privately delivered Invite original; current receiver policy remains separate.
pub fn verify_invite_delivery_human_signer(
    request: &arkret_models_collaboration::governance::invite_addressing::InviteDeliveryRequestBody,
    authority: &crate::realm_authority_chain::VerifiedRealmAuthority,
    keys: &dyn crate::realm_authority_chain::RealmAuthorityKeyDirectory,
) -> Result<VerifiedHumanHistoricalSignerFact> {
    request.validate_minimal()?;
    if request.invite_event.kind != arkret_wire::EventKind::InviteCreate {
        return Err(signature_invalid(
            "delivery is not the original Invite create Event",
        ));
    }
    let fact = request.producer_signer_fact.as_ref().ok_or_else(|| {
        signature_invalid("Invite Full original lacks its immutable Human signer source")
    })?;
    let suite = arkret_canonical::canonical::digest_suite(
        request.invite_event.event_id.digest_suite_code().as_str(),
    )
    .map_err(|error| signature_invalid(error.to_string()))?;
    verify_historical_human_committed_event(
        &arkret_wire::CommittedEventFullView {
            event: request.invite_event.clone(),
            commit: request.invite_commit.clone(),
        },
        fact,
        authority,
        keys,
        suite,
    )
}
