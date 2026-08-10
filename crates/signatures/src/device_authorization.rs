//! Cryptographic proof-of-possession verification for `ak.device.authorize`.

use std::collections::BTreeMap;

use arkret_canonical::canonical;
use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceReanchorPayload,
    DeviceRevokePayload, SignatureMaterial,
};
use arkret_wire::{
    DeviceId, DidCoreId, DidFullId, DidKey, DidUrl, Event, EventBatchReceipt, EventId, EventKind,
    FederatedCurrentDeviceProjection, FederatedDeviceSigningKeyEvidence, Hash,
    PrincipalAuthorityInstance, RealmId, RegistrationDidEvidence, Seal, SealId, event_spec,
};
use chrono::{DateTime, Duration, Utc};

use crate::{
    Error, PublicKeyMaterial, Result, verify_detached_ed25519_signature,
    verify_ed25519_detached_jws_proof,
};

type RangeCompletenessVerifier<'a> = dyn Fn(&[Event], &[Event], &Seal) -> Result<()> + 'a;

/// Trust-domain inputs required to close the portable PCR device-evidence
/// containers around the SDK-owned device-control replay.
///
/// The callbacks must verify historical issuer/notary keys and the applicable
/// PCR/range reducer policy. Current service assertions are not substitutes.
pub struct FederatedDeviceEvidenceVerificationContext<'a> {
    pub expected_authority_instance: &'a PrincipalAuthorityInstance,
    pub expected_device_id: &'a DeviceId,
    pub expected_verification_method: &'a DidUrl,
    pub now: DateTime<Utc>,
    /// Maximum lifetime of the verified, purpose-scoped in-process token.
    /// Historical accepted-at evidence does not become invalid merely because
    /// the authority instance is old.
    pub verification_ttl: Duration,
    pub verify_registration_did_evidence:
        &'a dyn Fn(&RegistrationDidEvidence, &EventBatchReceipt) -> Result<()>,
    pub verify_genesis_receipt: &'a dyn Fn(&EventBatchReceipt) -> Result<()>,
    pub verify_accepted_seal: &'a dyn Fn(&Seal) -> Result<()>,
    /// Verify the attestations as one complete range proof from PCR genesis
    /// through the accepted Seal. Per-item signature checks alone cannot
    /// detect an omitted interval.
    pub verify_range_completeness: &'a RangeCompletenessVerifier<'a>,
}

/// Fully replayed, trust-domain-verified PCR device signing authority.
///
/// Fields are private so a bare identity, service assertion, or self-reported
/// KeyPackage claim cannot manufacture this token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFederatedDeviceEvidence {
    authority_instance: PrincipalAuthorityInstance,
    device_id: DeviceId,
    verification_method: DidUrl,
    signing_key: DidKey,
    generation_ref: String,
    authorize_event_id: EventId,
    accepted_seal_id: SealId,
    verified_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl VerifiedFederatedDeviceEvidence {
    pub fn principal_id(&self) -> &DidCoreId {
        &self.authority_instance.principal_id
    }

    pub fn principal_server_id(&self) -> &DidCoreId {
        &self.authority_instance.principal_server_id
    }

    pub fn pcr_realm_id(&self) -> &RealmId {
        &self.authority_instance.pcr_realm_id
    }

    pub fn principal_genesis_receipt_digest(&self) -> &Hash {
        &self.authority_instance.principal_genesis_receipt_digest
    }

    pub fn authority_instance(&self) -> &PrincipalAuthorityInstance {
        &self.authority_instance
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn verification_method(&self) -> &DidUrl {
        &self.verification_method
    }

    pub fn signing_key(&self) -> &DidKey {
        &self.signing_key
    }

    pub fn generation_ref(&self) -> &str {
        &self.generation_ref
    }

    pub fn authorize_event_id(&self) -> &EventId {
        &self.authorize_event_id
    }

    pub fn accepted_seal_id(&self) -> &SealId {
        &self.accepted_seal_id
    }

    pub const fn verified_at(&self) -> &DateTime<Utc> {
        &self.verified_at
    }

    pub const fn expires_at(&self) -> &DateTime<Utc> {
        &self.expires_at
    }
}

/// Verify every portable container and replay the exact device authority
/// before producing an unforgeable authority token.
pub fn verify_federated_device_evidence(
    evidence: &FederatedDeviceSigningKeyEvidence,
    context: &FederatedDeviceEvidenceVerificationContext<'_>,
) -> Result<VerifiedFederatedDeviceEvidence> {
    if context.verification_ttl <= Duration::zero()
        || evidence.authority_instance != *context.expected_authority_instance
        || evidence.actor_id != context.expected_authority_instance.principal_id
        || evidence.device_id != *context.expected_device_id
        || evidence.verification_method != *context.expected_verification_method
        || evidence.authorization_accepted_at > context.now
    {
        return Err(Error::Protocol(
            "federated device evidence expected authority binding mismatch".to_owned(),
        ));
    }
    let expires_at = context.now + context.verification_ttl;

    evidence.validate_shape()?;
    (context.verify_registration_did_evidence)(
        &evidence.registration_did_evidence,
        &evidence.principal_genesis_receipt,
    )?;
    (context.verify_genesis_receipt)(&evidence.principal_genesis_receipt)?;
    (context.verify_accepted_seal)(&evidence.accepted_seal)?;
    (context.verify_range_completeness)(
        &evidence.range_completeness_evidence,
        &evidence.authorization_chain,
        &evidence.accepted_seal,
    )?;

    let projection = replay_federated_device_authorization(evidence)?;
    let create = &evidence.authorization_chain[0];
    let receipt_scope = evidence.principal_genesis_receipt.pcr_genesis_scope()?;
    if receipt_scope.principal_id != evidence.actor_id
        || receipt_scope.realm_id != create.realm_id
        || evidence.accepted_seal.realm_id != create.realm_id
    {
        return Err(Error::Protocol(
            "federated device evidence PCR lineage mismatch".to_owned(),
        ));
    }

    let authorize_event_id = projection
        .device_record
        .device_authorize_event_id
        .as_ref()
        .ok_or_else(|| {
            Error::Protocol("federated device evidence projection omits authorize event".to_owned())
        })?;
    let authorize = evidence
        .authorization_chain
        .iter()
        .find(|event| &event.event_id == authorize_event_id)
        .ok_or_else(|| {
            Error::Protocol(
                "federated device evidence authorize event is absent from replay".to_owned(),
            )
        })?;
    let authorize_payload: DeviceAuthorizePayload =
        authorize.typed_payload::<event_spec::DeviceAuthorize>()?;
    let authorize_digest = Hash::new(authorize.event_digest()?)?;
    if authorize_payload.device_id != evidence.device_id
        || authorize_payload.device_public_key.as_str() != evidence.device_signing_key.as_str()
        || !evidence.accepted_seal.delta.contains(&authorize_digest)
    {
        return Err(Error::Protocol(
            "federated device evidence exact signer binding mismatch".to_owned(),
        ));
    }

    Ok(VerifiedFederatedDeviceEvidence {
        authority_instance: evidence.authority_instance.clone(),
        device_id: evidence.device_id.clone(),
        verification_method: evidence.verification_method.clone(),
        signing_key: evidence.device_signing_key.clone(),
        generation_ref: projection
            .generation_state
            .current_device_generation_ref
            .to_string(),
        authorize_event_id: authorize_event_id.clone(),
        accepted_seal_id: evidence.accepted_seal.id.clone(),
        verified_at: context.now,
        expires_at,
    })
}

/// Verify the required Ed25519 proof of possession over the SDK-owned
/// `ak.device-authorize-possession-proof-v1` transcript.
pub fn verify_device_authorize_possession(payload: &DeviceAuthorizePayload) -> Result<()> {
    payload
        .validate_wire_constraints()
        .map_err(|reason| Error::Protocol(reason.to_owned()))?;
    let signature = device_authorize_signature_value(&payload.device_signature)?;
    let public_key = payload
        .device_public_key
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| Error::Protocol("device_authorize_device_public_key_invalid".to_owned()))?;
    let key = PublicKeyMaterial::Ed25519Multibase {
        value: public_key.to_owned(),
    };
    let transcript = payload.device_possession_signature_input()?;
    if !verify_detached_ed25519_signature(&key, &transcript, signature) {
        return Err(Error::Protocol(
            "device_authorize_device_signature_invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Verify every cryptographic link in the device-authorization portion of
/// portable PCR evidence.
///
/// The PCR create is verified directly from its root `did:key`. The founding
/// authorization is verified with the candidate key carried by that payload;
/// later authorizations are verified with the already-accepted authorizer key.
/// Every candidate independently proves possession through
/// [`verify_device_authorize_possession`]. This intentionally does not verify
/// the receipt issuer or accepted-seal notary proof: those keys come from the
/// caller's federated service trust configuration.
pub fn verify_federated_device_authorization_chain(
    evidence: &FederatedDeviceSigningKeyEvidence,
) -> Result<()> {
    replay_federated_device_authorization(evidence).map(|_| ())
}

/// Cryptographically replay the bounded PCR device-control history and return
/// the exact active target projection committed by the evidence.
///
/// Callers first verify the identity-root history, genesis receipt issuer,
/// accepted Seal and range-completeness attestations against their configured
/// trust policy. This pure replay then prevents those externally verified
/// containers from being combined with an omitted, reordered, mis-signed or
/// internally inconsistent device history.
pub fn replay_federated_device_authorization(
    evidence: &FederatedDeviceSigningKeyEvidence,
) -> Result<FederatedCurrentDeviceProjection> {
    evidence.validate_shape()?;

    let create = &evidence.authorization_chain[0];
    let create_proof = &create.proofs[0];
    let root_key = did_key_public_key(create_proof.verification_method.as_str())?;
    let create_bytes = canonical::canonical_json_bytes(&create.digest_payload()?)?;
    verify_ed25519_detached_jws_proof(create_proof, &create_bytes, &create.actor_id, &root_key)?;

    let mut accepted_keys = BTreeMap::<String, PublicKeyMaterial>::new();
    let mut expecting_root_authorize = true;
    let mut replayed_generation = None;
    for event in evidence.authorization_chain.iter().skip(1) {
        let event_bytes = canonical::canonical_json_bytes(&event.digest_payload()?)?;
        match &event.kind {
            EventKind::DeviceAuthorize => {
                let payload: DeviceAuthorizePayload =
                    event.typed_payload::<event_spec::DeviceAuthorize>()?;
                verify_device_authorize_possession(&payload)?;
                let candidate_key = did_key_public_key(payload.device_public_key.as_str())?;
                let event_proof_key = match payload.authorization_binding_kind {
                    DeviceAuthorizationBindingKind::RootAnchored if expecting_root_authorize => {
                        candidate_key.clone()
                    }
                    DeviceAuthorizationBindingKind::AcceptedDevice if !expecting_root_authorize => {
                        let arkret_models_collaboration::events_payloads::DeviceOrPrincipalRef::DeviceId(
                            authorizing_device_id,
                        ) = &payload.authorized_by
                        else {
                            return Err(Error::Protocol(
                                "accepted-device authorization must name a device authorizer"
                                    .to_owned(),
                            ));
                        };
                        accepted_keys
                            .get(authorizing_device_id.as_str())
                            .cloned()
                            .ok_or_else(|| {
                                Error::Protocol(
                                    "device authorization authorizer is not in the active replayed prefix"
                                        .to_owned(),
                                )
                            })?
                    }
                    _ => {
                        return Err(Error::Protocol(
                            "device authorization chain binding kind is invalid for its position"
                                .to_owned(),
                        ));
                    }
                };
                verify_ed25519_detached_jws_proof(
                    &event.proofs[0],
                    &event_bytes,
                    &event.actor_id,
                    &event_proof_key,
                )?;
                accepted_keys.insert(payload.device_id.to_string(), candidate_key);
                expecting_root_authorize = false;
            }
            EventKind::DeviceRevoke | EventKind::DeviceListUpdate | EventKind::DeviceReanchor => {
                let event_proof_key = resolve_control_event_proof_key(event, &accepted_keys)?;
                verify_ed25519_detached_jws_proof(
                    &event.proofs[0],
                    &event_bytes,
                    &event.actor_id,
                    &event_proof_key,
                )?;
                if event.kind == EventKind::DeviceRevoke {
                    let payload: DeviceRevokePayload =
                        event.typed_payload::<event_spec::DeviceRevoke>()?;
                    accepted_keys.remove(payload.device_id.as_str());
                } else if event.kind == EventKind::DeviceReanchor {
                    let payload: DeviceReanchorPayload =
                        event.typed_payload::<event_spec::DeviceReanchor>()?;
                    replayed_generation = Some(payload.new_device_generation.to_string());
                    accepted_keys.clear();
                    expecting_root_authorize = true;
                }
            }
            _ => {
                return Err(Error::Protocol(
                    "authorization chain contains a non-device-control Event".to_owned(),
                ));
            }
        }
    }
    if !accepted_keys.contains_key(evidence.device_id.as_str()) {
        return Err(Error::Protocol(
            "target device is not active after authorization replay".to_owned(),
        ));
    }
    if replayed_generation.as_deref().is_some_and(|generation| {
        generation
            != evidence
                .current_device_projection
                .generation_state
                .current_device_generation_ref
                .as_str()
    }) {
        return Err(Error::Protocol(
            "replayed reanchor generation does not match current projection".to_owned(),
        ));
    }
    if !evidence
        .current_device_projection
        .device_record
        .algorithms
        .is_empty()
    {
        return Err(Error::Protocol(
            "device authorization evidence cannot assert uncommitted prekey records".to_owned(),
        ));
    }
    Ok(evidence.current_device_projection.clone())
}

fn resolve_control_event_proof_key(
    event: &Event,
    accepted_keys: &BTreeMap<String, PublicKeyMaterial>,
) -> Result<PublicKeyMaterial> {
    let method = event.proofs[0].verification_method.as_str();
    if method.starts_with("did:key:") {
        return did_key_public_key(method);
    }
    let (controller, device_id) = method.split_once('#').ok_or_else(|| {
        Error::Protocol("device control Event proof method has no fragment".to_owned())
    })?;
    let controller = DidFullId::new(controller.to_owned())?;
    if arkret_wire::project_full_id_to_core_id(&controller)? != event.actor_id
        || device_id.is_empty()
    {
        return Err(Error::Protocol(
            "device control Event proof method does not project to actor_id".to_owned(),
        ));
    }
    accepted_keys.get(device_id).cloned().ok_or_else(|| {
        Error::Protocol(
            "device control Event signer is not active in the replayed prefix".to_owned(),
        )
    })
}

fn did_key_public_key(value: &str) -> Result<PublicKeyMaterial> {
    let controller = value
        .split_once('#')
        .map_or(value, |(controller, _)| controller);
    let multibase = controller.strip_prefix("did:key:").ok_or_else(|| {
        Error::Protocol("device authorization requires an Ed25519 did:key".to_owned())
    })?;
    if !multibase.starts_with("z6Mk") {
        return Err(Error::Protocol(
            "device authorization requires an Ed25519 did:key".to_owned(),
        ));
    }
    Ok(PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    })
}

fn device_authorize_signature_value(signature: &SignatureMaterial) -> Result<&str> {
    match signature {
        SignatureMaterial::NonEmptyString(value) => Ok(value.as_str()),
        SignatureMaterial::Variant1(object) => {
            if object
                .get("signature_algorithm")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|algorithm| algorithm != "Ed25519")
            {
                return Err(Error::Protocol(
                    "device_authorize_device_signature_algorithm_unsupported".to_owned(),
                ));
            }
            object
                .get("signature")
                .or_else(|| object.get("sig"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    Error::Protocol(
                        "device_authorize_device_signature_missing_signature".to_owned(),
                    )
                })
        }
    }
}
