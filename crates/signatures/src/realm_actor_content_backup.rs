//! Native packet signatures and immutable receipt transcripts. A valid packet
//! signature alone is not evidence of remote custody or current authorization.

use arkret_models_crypto::{
    KeyBackup, RealmActorContentBackupAdmission, RealmActorContentBackupAdmissionSignatureInput,
};
use arkret_wire::{DetachedSignatureContext, DidUrl};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::{Error, PublicKeyMaterial, Result};

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
        let mut bad = packet;
        bad.signature_proof.signature =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([0; 64])).unwrap();
        assert!(verify_realm_actor_backup_packet(&bad, &admission).is_err());
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
