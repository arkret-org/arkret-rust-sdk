//! Cryptographic proof-of-possession verification for `ak.device.authorize`.

use std::collections::BTreeMap;

use arkret_canonical::canonical;
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, SignatureMaterial,
};
use arkret_wire::{FederatedCurrentDeviceProjection, FederatedDeviceSigningKeyEvidence};

use crate::{
    Error, PublicKeyMaterial, Result, verify_detached_ed25519_signature,
    verify_ed25519_detached_jws_proof,
};

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
        match event.kind.as_str() {
            "ak.device.authorize" => {
                let payload: DeviceAuthorizePayload = event.typed_payload("ak.device.authorize")?;
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
            "ak.device.revoke" | "ak.device.list.update" | "ak.device.reanchor" => {
                let event_proof_key = resolve_control_event_proof_key(event, &accepted_keys)?;
                verify_ed25519_detached_jws_proof(
                    &event.proofs[0],
                    &event_bytes,
                    &event.actor_id,
                    &event_proof_key,
                )?;
                if event.kind.as_str() == "ak.device.revoke" {
                    let revoked = event
                        .payload
                        .get("device_id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            Error::Protocol("device revoke omits device_id".to_owned())
                        })?;
                    accepted_keys.remove(revoked);
                } else if event.kind.as_str() == "ak.device.reanchor" {
                    replayed_generation = Some(
                        event
                            .payload
                            .get("new_device_generation")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| {
                                Error::Protocol(
                                    "device reanchor omits new_device_generation".to_owned(),
                                )
                            })?
                            .to_owned(),
                    );
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
    event: &arkret_wire::Event,
    accepted_keys: &BTreeMap<String, PublicKeyMaterial>,
) -> Result<PublicKeyMaterial> {
    let method = event.proofs[0].verification_method.as_str();
    if method.starts_with("did:key:") {
        return did_key_public_key(method);
    }
    let prefix = format!("{}#", event.actor_id);
    let device_id = method.strip_prefix(&prefix).ok_or_else(|| {
        Error::Protocol("device control Event proof method is not canonical".to_owned())
    })?;
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
