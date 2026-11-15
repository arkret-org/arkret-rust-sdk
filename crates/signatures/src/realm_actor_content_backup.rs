//! Native packet signatures and immutable receipt transcripts. A valid packet
//! signature alone is not evidence of remote custody or current authorization.

use arkret_models_crypto::{
    KeyBackup, RealmActorContentBackupAdmission, RealmActorContentBackupAdmissionSignatureInput,
};
use arkret_wire::{DetachedSignatureContext, DidUrl};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::{Error, PublicKeyMaterial, Result};

/// Signature verification consumes the independently resolved current Device
/// or Manager key. Challenge consumption and current authority remain one
/// durable service transaction; signature validity alone never authorizes it.
pub fn verify_realm_actor_device_unlock_proof(
    proof: &arkret_models_crypto::RealmActorDeviceKeyBackupUnlockProof,
    challenge: &arkret_models_crypto::RealmActorBackupUnlockChallenge,
    expected_method: &DidUrl,
    current_key: &PublicKeyMaterial,
) -> Result<()> {
    proof.validate_for_challenge(challenge)?;
    if &proof.signature_proof.verification_method != expected_method {
        return Err(Error::Protocol(
            "native Device unlock uses another current method".into(),
        ));
    }
    crate::proof::verify_ed25519_raw_transcript_signature(
        &proof.signing_payload_bytes()?,
        proof.signature_proof.signature.as_str(),
        current_key,
    )
    .map_err(|error| Error::Protocol(error.to_string()))
}

pub fn verify_realm_actor_manager_unlock_proof(
    proof: &arkret_models_crypto::RealmActorManagerKeyBackupUnlockProof,
    challenge: &arkret_models_crypto::RealmActorBackupUnlockChallenge,
    expected_method: &DidUrl,
    current_key: &PublicKeyMaterial,
) -> Result<()> {
    proof.validate_for_challenge(challenge)?;
    if &proof.signature_proof.verification_method != expected_method {
        return Err(Error::Protocol(
            "native Manager unlock uses another current method".into(),
        ));
    }
    crate::proof::verify_ed25519_raw_transcript_signature(
        &proof.signing_payload_bytes()?,
        proof.signature_proof.signature.as_str(),
        current_key,
    )
    .map_err(|error| Error::Protocol(error.to_string()))
}

pub fn verify_current_device_backup_unlock_proof(
    proof: &arkret_models_crypto::KeyBackupUnlockProof,
    challenge: &arkret_models_crypto::KeysBackupsUnlockChallenge,
    expected_method: &DidUrl,
    current_key: &PublicKeyMaterial,
) -> Result<()> {
    proof.validate_for_challenge(challenge)?;
    if &proof.signature_proof.verification_method != expected_method {
        return Err(Error::Protocol(
            "backup unlock uses another current Device method".into(),
        ));
    }
    crate::proof::verify_ed25519_raw_transcript_signature(
        &proof.signing_payload_bytes()?,
        proof.signature_proof.signature.as_str(),
        current_key,
    )
    .map_err(|error| Error::Protocol(error.to_string()))
}

pub fn admission_signing_input(
    admission: &RealmActorContentBackupAdmission,
) -> Result<RealmActorContentBackupAdmissionSignatureInput> {
    Ok(serde_json::from_value(arkret_canonical::unsigned_value(
        admission,
        &["signature"],
    )?)?)
}

pub fn sign_realm_actor_content_backup_admission(
    input: RealmActorContentBackupAdmissionSignatureInput,
    verification_method: DidUrl,
    key: &SigningKey,
) -> Result<RealmActorContentBackupAdmission> {
    arkret_models_crypto::validate_realm_actor_backup_scope(
        &input.realm_actor_id,
        &input.effective_scope,
    )?;
    if input.device_generation == 0
        || arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(
            verification_method
                .as_str()
                .split('#')
                .next()
                .unwrap_or_default(),
        )?)? != input.service_id
    {
        return Err(Error::Protocol(
            "admission signer differs from its original governance issuer".into(),
        ));
    }
    let signature = crate::detached_object::sign_detached_object(
        &input,
        DetachedSignatureContext::RealmActorContentBackupAdmission,
        verification_method,
        input.accepted_at,
        key,
    )?;
    let mut value = serde_json::to_value(input)?;
    value["signature"] = serde_json::to_value(signature)?;
    Ok(serde_json::from_value(value)?)
}

/// Manager-side signature check after its independently validated historical
/// origin/tenure source has selected the original issuing Service key.
pub fn verify_realm_actor_content_backup_admission_signature(
    admission: &RealmActorContentBackupAdmission,
    original_issuer: &PublicKeyMaterial,
) -> Result<()> {
    if admission.signature.created_at != admission.accepted_at
        || arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(
            admission
                .signature
                .verification_method
                .as_str()
                .split('#')
                .next()
                .unwrap_or_default(),
        )?)? != admission.service_id
    {
        return Err(Error::Protocol(
            "admission signature must bind its actual first accepted time".into(),
        ));
    }
    crate::detached_object::verify_detached_object_signature(
        &admission.signature,
        &admission_signing_input(admission)?,
        DetachedSignatureContext::RealmActorContentBackupAdmission,
        original_issuer,
    )
}

/// Verify every immutable receipt/packet binding and the original author's Ed.
/// The Device obtains this receipt through an independently bound own-Station
/// response. This function does not establish receipt issuer authority, storage
/// success, a current head, or a new publication credential.
pub fn verify_realm_actor_backup_packet(
    packet: &KeyBackup,
    admission: &RealmActorContentBackupAdmission,
) -> Result<()> {
    packet.validate()?;
    packet.validate_ciphertext_digest()?;
    arkret_models_crypto::validate_realm_actor_backup_scope(
        &admission.realm_actor_id,
        &admission.effective_scope,
    )?;
    let auth = packet
        .auth_binding
        .as_ref()
        .ok_or_else(|| Error::Protocol("packet lacks native binding".into()))?;
    let context = packet
        .contents
        .first()
        .and_then(|item| item.root_context.as_ref())
        .ok_or_else(|| Error::Protocol("packet lacks its single root context".into()))?;
    if packet.actor_id.as_realm_actor_id() != Some(&admission.realm_actor_id)
        || admission.signature.context != DetachedSignatureContext::RealmActorContentBackupAdmission
        || packet.backup_id != admission.backup_id
        || packet.ciphertext_digest != admission.ciphertext_digest
        || admission.envelope_digest.as_str() != arkret_canonical::canonical_sha256(packet)?
        || packet.device_id.as_ref() != Some(&admission.device_id)
        || packet.signature_proof.device_authorize_event_id.as_ref()
            != Some(&admission.device_authorize_ref.event_id)
        || auth.device_generation != admission.device_generation
        || auth.manager_ref != admission.manager_ref
        || auth.recovery_ref != admission.recovery_ref
        || auth.recipient_ref != admission.recipient_ref
        || context.effective_scope != admission.effective_scope
        || admission.signature.created_at != admission.accepted_at
    {
        return Err(Error::Protocol(
            "native packet differs from immutable first-PUT admission".into(),
        ));
    }
    let raw = arkret_canonical::base64url_decode(&admission.device_public_key_base64url)?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| Error::Protocol("native author key must be 32 bytes".into()))?;
    if arkret_canonical::base64url_encode(bytes) != admission.device_public_key_base64url {
        return Err(Error::Protocol("noncanonical native author key".into()));
    }
    let key = VerifyingKey::from_bytes(&bytes).map_err(|e| Error::Crypto(e.to_string()))?;
    let signature = arkret_canonical::base64url_decode(packet.signature_proof.signature.as_str())?;
    let signature = Signature::from_slice(&signature).map_err(|e| Error::Crypto(e.to_string()))?;
    key.verify_strict(&packet.signing_payload_bytes()?, &signature)
        .map_err(|e| Error::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json")).unwrap()
    }

    fn native_challenge(manager: bool) -> arkret_models_crypto::RealmActorBackupUnlockChallenge {
        let fixture = fixture();
        let admission = &fixture["native_put_response"]["admission"];
        let mut value = serde_json::json!({
            "challenge_id":"AAAAAAAAAAAAAAAAAAAAAA", "challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "operation":"ak.self.keys.backups.command.unlock.v1", "backup_id":admission["backup_id"],
            "audience":"https://station.example", "service_id":admission["service_id"],"request_id":"BBBBBBBBBBBBBBBBBBBBBB",
            "issued_at":"2026-11-14T12:00:00.000Z", "expires_at":"2026-11-14T12:05:00.000Z",
            "series_id":fixture["native_packet"]["series_id"],"ciphertext_digest":admission["ciphertext_digest"],
            "kind":if manager {"realm_actor_manager"}else{"realm_actor_device"},
            "purpose":if manager {"archive_recovery"}else{"series_predecessor"},
            "realm_actor_id":admission["realm_actor_id"], "effective_scope":admission["effective_scope"],
            "manager_ref":admission["manager_ref"],"recovery_ref":admission["recovery_ref"],"recipient_ref":admission["recipient_ref"],
            "envelope_digest":admission["envelope_digest"],
        });
        if !manager {
            value["requesting_device_id"] = admission["device_id"].clone();
            value["device_authorize_event_id"] =
                admission["device_authorize_ref"]["event_id"].clone();
            value["device_generation"] = admission["device_generation"].clone();
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn native_single_challenge_device_and_manager_proofs_match_independent_ed_goldens() {
        use ed25519_dalek::Signer as _;
        let fixture = fixture();
        for manager in [false, true] {
            let challenge = native_challenge(manager);
            let (seed, method, expected_hash, expected_signature) = if manager {
                (
                    &fixture["test_material"]["manager_seed_hex"],
                    &fixture["native_put_response"]["admission"]["signature"]["verification_method"],
                    "sha256:b17946a2e80724faec233bba7979c173fb12572bf73b063aaf54823583a3aad2",
                    "lxDom3Lgreyiuw8C7K5zzdIhDSPxKDAbNET3Vd_wrjugyQrqgw3ZI0Esi3oQ5whJI8uHF21HTGZrV3Xj7yBPAQ",
                )
            } else {
                (
                    &fixture["test_material"]["device_seed_hex"],
                    &fixture["native_packet"]["signature_proof"]["verification_method"],
                    "sha256:cf7d7e00f839f09a63bb9c12a7ad78ef0feb683f9fc85b8b2507b4732d4be8f4",
                    "qh8eXp0oS759EedTCHKiBG3NRR2I51gwDmkVYeZTLq5nGlvU4Hq2oNgUYmO00BgCc8YiheelKd3ZjCCAHGB_AA",
                )
            };
            let seed = seed.as_str().unwrap();
            let bytes: [u8; 32] = core::array::from_fn(|index| {
                u8::from_str_radix(&seed[index * 2..index * 2 + 2], 16).unwrap()
            });
            let key = SigningKey::from_bytes(&bytes);
            let method = DidUrl::new(method.as_str().unwrap()).unwrap();
            let public = PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().as_bytes().to_vec(),
            };
            let sign = |bytes: &[u8]| Ok(key.sign(bytes).to_bytes().to_vec());
            let value = if manager {
                let proof = challenge
                    .sign_manager_unlock_proof_at(method.clone(), challenge.issued_at, sign)
                    .unwrap();
                verify_realm_actor_manager_unlock_proof(&proof, &challenge, &method, &public)
                    .unwrap();
                assert_eq!(
                    arkret_canonical::canonical::sha256_digest(
                        proof.signing_payload_bytes().unwrap()
                    ),
                    expected_hash
                );
                serde_json::to_value(proof).unwrap()
            } else {
                let proof = challenge
                    .sign_device_unlock_proof_at(method.clone(), challenge.issued_at, sign)
                    .unwrap();
                verify_realm_actor_device_unlock_proof(&proof, &challenge, &method, &public)
                    .unwrap();
                assert_eq!(
                    arkret_canonical::canonical::sha256_digest(
                        proof.signing_payload_bytes().unwrap()
                    ),
                    expected_hash
                );
                assert!(
                    challenge
                        .sign_manager_unlock_proof_at(method.clone(), challenge.issued_at, sign)
                        .is_err()
                );
                serde_json::to_value(proof).unwrap()
            };
            assert_eq!(value["signature_proof"]["signature"], expected_signature);
            assert!(value.get("nonce").is_none());
            let mut legacy = value;
            legacy["nonce"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAA");
            assert!(
                serde_json::from_value::<arkret_models_crypto::KeyBackupUnlockProofBody>(legacy)
                    .is_err()
            );
            let mut widened = challenge.clone();
            widened.expires_at += chrono::Duration::milliseconds(1);
            assert!(widened.validate_at(widened.issued_at).is_err());
        }
    }

    #[test]
    fn ordinary_single_challenge_proof_retains_all_signed_object_bindings() {
        use ed25519_dalek::Signer as _;
        let fixture =
            arkret_schema_conformance::spec_json_artifact("fixtures/key-backup-fixture.json")
                .unwrap();
        let mut value = fixture["schema_validation_cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "key_backup_unlock_proof_valid")
            .unwrap()["instance"]
            .clone();
        let method = DidUrl::new(
            value["signature_proof"]["verification_method"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let object = value.as_object_mut().unwrap();
        for key in [
            "schema",
            "kind",
            "signature_proof",
            "recovery_session_id",
            "backup_kind",
        ] {
            object.remove(key);
        }
        object.insert(
            "challenge_id".into(),
            serde_json::json!("AAAAAAAAAAAAAAAAAAAAAA"),
        );
        object.insert(
            "request_id".into(),
            serde_json::json!("BBBBBBBBBBBBBBBBBBBBBB"),
        );
        object.insert(
            "operation".into(),
            serde_json::json!("ak.self.keys.backups.command.unlock.v1"),
        );
        let challenge: arkret_models_crypto::KeysBackupsUnlockChallenge =
            serde_json::from_value(value).unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        let proof = challenge
            .sign_unlock_proof_at(method.clone(), challenge.issued_at, |bytes| {
                Ok(key.sign(bytes).to_bytes().to_vec())
            })
            .unwrap();
        let public = PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().as_bytes().to_vec(),
        };
        verify_current_device_backup_unlock_proof(&proof, &challenge, &method, &public).unwrap();
        assert_eq!(
            arkret_canonical::canonical::sha256_digest(proof.signing_payload_bytes().unwrap()),
            "sha256:d99f49c31c6a4c9e2170b2b84208f6ef6e6b67aff8019543b789cfabf3d39c95"
        );
        assert_eq!(
            proof.signature_proof.signature.as_str(),
            "qdCXiQe3L3a-Upu-32rNsaxaiD91H1qOn0YFi8j5lOSQVyr2Y_uNvVJme-P4SyxEiLpHn2Q5vW2YAYMv3qJvAA"
        );
        let mut changed = challenge;
        changed.challenge =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([7; 32])).unwrap();
        assert!(
            verify_current_device_backup_unlock_proof(&proof, &changed, &method, &public).is_err()
        );
    }
    #[test]
    fn formal_native_packet_keeps_its_original_webvh_method_and_verifies_real_ed() {
        let f = fixture();
        let packet: KeyBackup = serde_json::from_value(f["native_packet"].clone()).unwrap();
        let admission: RealmActorContentBackupAdmission =
            serde_json::from_value(f["native_put_response"]["admission"].clone()).unwrap();
        assert!(
            packet
                .signature_proof
                .verification_method
                .as_str()
                .starts_with("did:webvh:")
        );
        verify_realm_actor_backup_packet(&packet, &admission).unwrap();
        let mut bad = admission.clone();
        bad.device_public_key_base64url = arkret_canonical::base64url_encode([8; 32]);
        assert!(verify_realm_actor_backup_packet(&packet, &bad).is_err());
        let original_signing_bytes = packet.signing_payload_bytes().unwrap();
        let original_envelope_digest = arkret_canonical::canonical_sha256(&packet).unwrap();
        let mut bad = packet;
        bad.signature_proof.signature =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([0; 64])).unwrap();
        assert_eq!(bad.signing_payload_bytes().unwrap(), original_signing_bytes);
        assert_ne!(
            arkret_canonical::canonical_sha256(&bad).unwrap(),
            original_envelope_digest
        );
        assert!(
            verify_realm_actor_backup_packet(&bad, &admission)
                .unwrap_err()
                .to_string()
                .contains("native packet differs from immutable first-PUT admission")
        );
    }

    #[test]
    fn receipt_whole_packet_digest_includes_signature_and_is_not_predecessor_digest() {
        let f = fixture();
        let packet: KeyBackup = serde_json::from_value(f["native_packet"].clone()).unwrap();
        let mut admission: RealmActorContentBackupAdmission =
            serde_json::from_value(f["native_put_response"]["admission"].clone()).unwrap();
        admission.envelope_digest = arkret_wire::Hash::new(arkret_canonical::sha256_digest(
            packet.signing_payload_bytes().unwrap(),
        ))
        .unwrap();
        assert!(verify_realm_actor_backup_packet(&packet, &admission).is_err());
    }
}
