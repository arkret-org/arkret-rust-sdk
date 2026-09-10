//! Canonical device-pairing challenge transcript generation and verification.

use arkret_models_collaboration::events_payloads::SignatureMaterial;
use arkret_models_collaboration::governance::agent_artifacts::{DeviceMetadata, PublicKey};
use arkret_models_collaboration::http_bodies::{
    DevicePairingBootstrap, DevicePairingCode, DevicePairingNonce, DevicePairingRequestId,
    DevicePairingStageOutcome, DevicePairingStageRequestBody, DevicePairingTargetProof,
    UnsignedDevicePairingTargetProof,
};
#[cfg(test)]
use arkret_wire::{Base64UrlString, DeviceId};
use arkret_wire::{Hash, NonEmptyString};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer as _;
use serde::Serialize;

const SERVER_TRANSCRIPT: &str = "ak.device-pairing.challenge.v1";

#[derive(Clone, Debug)]
pub struct ServerDevicePairingChallenge {
    pub client_nonce: DevicePairingNonce,
    pub device_pairing_request_id: DevicePairingRequestId,
    pub expires_at: DateTime<Utc>,
    pub gate_audience_uri: String,
    pub pairing_code: DevicePairingCode,
    pub server_nonce: DevicePairingNonce,
    pub display_name: Option<NonEmptyString>,
    pub device_metadata: Option<DeviceMetadata>,
}

impl ServerDevicePairingChallenge {
    pub fn from_stage(
        request: &DevicePairingStageRequestBody,
        outcome: &DevicePairingStageOutcome,
    ) -> Self {
        Self {
            client_nonce: request.client_nonce.clone(),
            display_name: request.display_name.clone(),
            device_metadata: request.device_metadata.clone(),
            device_pairing_request_id: outcome.device_pairing_request_id.clone(),
            expires_at: outcome.expires_at,
            gate_audience_uri: outcome.gate_audience_uri.clone(),
            pairing_code: outcome.pairing_code.clone(),
            server_nonce: outcome.server_nonce.clone(),
        }
    }

    pub fn from_bootstrap(bootstrap: &DevicePairingBootstrap) -> Self {
        Self {
            client_nonce: bootstrap.client_nonce.clone(),
            display_name: bootstrap.display_name.clone(),
            device_metadata: bootstrap.device_metadata.clone(),
            device_pairing_request_id: bootstrap.device_pairing_request_id.clone(),
            expires_at: bootstrap.expires_at,
            gate_audience_uri: bootstrap.gate_audience_uri.clone(),
            pairing_code: bootstrap.pairing_code.clone(),
            server_nonce: bootstrap.server_nonce.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DevicePairingProofError {
    #[error("device pairing public key is not a supported Ed25519 key")]
    UnsupportedKey,
    #[error("device pairing verification_method does not match new_device_pubkey.kid")]
    VerificationMethodMismatch,
    #[error("device pairing proof signature_algorithm does not match new_device_pubkey.algorithm")]
    AlgorithmMismatch,
    #[error("device pairing proof uses the wrong transcript")]
    TranscriptMismatch,
    #[error("device pairing challenge has expired")]
    Expired,
    #[error("device pairing transcript digest mismatch")]
    DigestMismatch,
    #[error("device pairing signature is malformed")]
    MalformedSignature,
    #[error("device pairing signature verification failed")]
    SignatureInvalid,
    #[error("device pairing target attestation signature is not the closed Ed25519 string form")]
    InvalidTargetProofSignatureShape,
    #[error("device pairing transcript could not be canonicalized: {0}")]
    Canonical(#[from] arkret_canonical::CanonicalError),
    #[error("device pairing wire value is invalid: {0}")]
    Wire(#[from] arkret_wire::WireError),
}

/// Sign the target-owned accepted-device possession attestation that travels
/// out of band to the approving sibling.
pub fn sign_device_pairing_target_proof(
    unsigned: UnsignedDevicePairingTargetProof,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<DevicePairingTargetProof, DevicePairingProofError> {
    let input = unsigned.signing_input()?;
    let signature =
        NonEmptyString::new(URL_SAFE_NO_PAD.encode(signing_key.sign(&input).to_bytes()))
            .map_err(|error| arkret_wire::WireError::Protocol(error.to_owned()))?;
    let attestation = unsigned.attach_signature(SignatureMaterial::NonEmptyString(signature));
    verify_device_pairing_target_proof(&attestation)?;
    Ok(attestation)
}

/// Verify the target-device possession proof independently of the approving
/// device Event. Call `DevicePairingTargetProof::validate_against_pair_request`
/// afterwards to bind the verified material to the exact preassembled request.
pub fn verify_device_pairing_target_proof(
    attestation: &DevicePairingTargetProof,
) -> Result<(), DevicePairingProofError> {
    let multibase = attestation
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or(DevicePairingProofError::UnsupportedKey)?;
    let public_key = arkret_canonical::decode_ed25519_multibase(multibase)
        .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    let SignatureMaterial::NonEmptyString(signature) = &attestation.device_signature else {
        return Err(DevicePairingProofError::InvalidTargetProofSignatureShape);
    };
    let signature = URL_SAFE_NO_PAD
        .decode(signature.as_str())
        .map_err(|_| DevicePairingProofError::MalformedSignature)?;
    let signature = ed25519_dalek::Signature::from_slice(&signature)
        .map_err(|_| DevicePairingProofError::MalformedSignature)?;
    verifying_key
        .verify_strict(&attestation.signing_input()?, &signature)
        .map_err(|_| DevicePairingProofError::SignatureInvalid)
}

#[derive(Serialize)]
struct ServerTranscriptBody<'a> {
    client_nonce: &'a str,
    device_pairing_request_id: &'a str,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    gate_audience: &'a str,
    device_metadata_digest: &'a str,
    new_device_pubkey_digest: &'a str,
    pairing_code: &'a str,
    server_nonce: &'a str,
}

pub fn server_device_pairing_transcript(
    public_key: &PublicKey,
    challenge: &ServerDevicePairingChallenge,
) -> Result<(Vec<u8>, Hash), DevicePairingProofError> {
    let public_key_digest = arkret_canonical::canonical_sha256(public_key)?;
    let metadata_digest = arkret_canonical::canonical_sha256(&serde_json::json!({
        "display_name": &challenge.display_name, "device_metadata": &challenge.device_metadata
    }))?;
    let body = ServerTranscriptBody {
        client_nonce: challenge.client_nonce.as_str(),
        device_pairing_request_id: challenge.device_pairing_request_id.as_str(),
        expires_at: challenge.expires_at,
        gate_audience: &challenge.gate_audience_uri,
        device_metadata_digest: &metadata_digest,
        new_device_pubkey_digest: &public_key_digest,
        pairing_code: challenge.pairing_code.as_str(),
        server_nonce: challenge.server_nonce.as_str(),
    };
    let mut bytes = format!("{SERVER_TRANSCRIPT}\n").into_bytes();
    bytes.extend(arkret_canonical::canonical_json_bytes(&body)?);
    let digest = Hash::new(format!("sha256:{}", arkret_canonical::sha256_hex(&bytes)))
        .map_err(arkret_wire::WireError::from)?;
    Ok((bytes, digest))
}

/// Verify the sole target proof against independently reconstructed stage inputs.
pub fn verify_server_device_pairing_target_proof(
    public_key: &PublicKey,
    challenge: &ServerDevicePairingChallenge,
    proof: &DevicePairingTargetProof,
    verification_time: DateTime<Utc>,
) -> Result<(), DevicePairingProofError> {
    if challenge.expires_at <= verification_time {
        return Err(DevicePairingProofError::Expired);
    }
    if proof.device_id.as_str() != public_key.kid.as_str() {
        return Err(DevicePairingProofError::VerificationMethodMismatch);
    }
    let target_key = arkret_canonical::decode_ed25519_multibase(
        proof
            .device_public_key_did
            .as_str()
            .strip_prefix("did:key:")
            .ok_or(DevicePairingProofError::UnsupportedKey)?,
    )
    .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    validate_public_key(public_key, &target_key)?;
    let (_, digest) = server_device_pairing_transcript(public_key, challenge)?;
    if digest != proof.pairing_challenge_transcript_digest {
        return Err(DevicePairingProofError::DigestMismatch);
    }
    verify_device_pairing_target_proof(proof)
}

fn validate_public_key(
    public_key: &PublicKey,
    expected_bytes: &[u8; 32],
) -> Result<(), DevicePairingProofError> {
    if public_key.kty.as_str() != "OKP" || public_key.algorithm.as_str() != "Ed25519" {
        return Err(DevicePairingProofError::UnsupportedKey);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(public_key.key.as_str())
        .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    if decoded.as_slice() != expected_bytes {
        return Err(DevicePairingProofError::UnsupportedKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn fixture() -> (
        PublicKey,
        ServerDevicePairingChallenge,
        ed25519_dalek::SigningKey,
    ) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
        let public_key = PublicKey {
            kty: NonEmptyString::new("OKP").unwrap(),
            kid: NonEmptyString::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            algorithm: NonEmptyString::new("Ed25519").unwrap(),
            key: Base64UrlString::new(
                URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            )
            .unwrap(),
            key_digest: None,
        };
        let challenge = ServerDevicePairingChallenge {
            client_nonce: DevicePairingNonce::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            device_pairing_request_id: DevicePairingRequestId::new(
                "device_pairing_request:01904100-0000-7000-8000-000000000002".to_owned(),
            )
            .unwrap(),
            expires_at: DateTime::parse_from_rfc3339("2026-07-26T00:10:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            gate_audience_uri: "https://account.example".to_owned(),
            pairing_code: DevicePairingCode::new("ABCDEFGH".to_owned()).unwrap(),
            server_nonce: DevicePairingNonce::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap(),
            display_name: None,
            device_metadata: None,
        };
        (public_key, challenge, signing_key)
    }

    #[test]
    fn server_transcript_round_trip_and_tamper_rejection() {
        let (public_key, challenge, signing_key) = fixture();
        let (_, digest) = server_device_pairing_transcript(&public_key, &challenge).unwrap();
        let unsigned = UnsignedDevicePairingTargetProof::new(
            DeviceId::new(public_key.kid.as_str()).unwrap(),
            arkret_wire::DidKey::new(format!(
                "did:key:{}",
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    signing_key.verifying_key().as_bytes()
                )
            ))
            .unwrap(),
            NonEmptyString::new("hpke-public-key-fixture").unwrap(),
            vec![NonEmptyString::new("Ed25519").unwrap()],
            digest,
        )
        .unwrap();
        let proof = sign_device_pairing_target_proof(unsigned, &signing_key).unwrap();
        let verification_time = challenge.expires_at - chrono::Duration::minutes(1);
        verify_server_device_pairing_target_proof(
            &public_key,
            &challenge,
            &proof,
            verification_time,
        )
        .unwrap();
        let mut tampered = challenge.clone();
        tampered.gate_audience_uri = "https://attacker.example".to_owned();
        assert!(
            verify_server_device_pairing_target_proof(
                &public_key,
                &tampered,
                &proof,
                verification_time
            )
            .is_err()
        );
        let mut tampered = challenge.clone();
        tampered.display_name = Some(NonEmptyString::new("attacker label").unwrap());
        assert!(
            verify_server_device_pairing_target_proof(
                &public_key,
                &tampered,
                &proof,
                verification_time
            )
            .is_err()
        );
        assert!(
            verify_server_device_pairing_target_proof(
                &public_key,
                &challenge,
                &proof,
                challenge.expires_at
            )
            .is_err()
        );
        let mut tampered = proof;
        tampered.hpke_key = NonEmptyString::new("wrong-hpke-key").unwrap();
        assert!(
            verify_server_device_pairing_target_proof(
                &public_key,
                &challenge,
                &tampered,
                verification_time
            )
            .is_err()
        );
    }

    fn target_proof_fixture(
        signing_key: &ed25519_dalek::SigningKey,
    ) -> UnsignedDevicePairingTargetProof {
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        UnsignedDevicePairingTargetProof::new(
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000009").unwrap(),
            arkret_wire::DidKey::new(format!("did:key:{multibase}")).unwrap(),
            NonEmptyString::new("hpke-public-key-fixture").unwrap(),
            vec![NonEmptyString::new("Ed25519").unwrap()],
            Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn target_proof_signing_input_and_wire_shape_are_fixed() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
        let unsigned = target_proof_fixture(&signing_key);
        let did_key = format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                signing_key.verifying_key().as_bytes()
            )
        );
        assert_eq!(
            String::from_utf8(unsigned.signing_input().unwrap()).unwrap(),
            format!(
                "ak.device_authorize_accepted_device_possession_proof.v1\n\
                 {{\"algorithms\":[\"Ed25519\"],\"authorization_binding_kind\":\"accepted_device\",\
                 \"device_id\":\"ak:device:01904100-0000-7000-8000-000000000009\",\
                 \"device_key_algorithm\":\"Ed25519\",\"device_public_key_did\":\"{did_key}\",\
                 \"hpke_key\":\"hpke-public-key-fixture\",\
                 \"pairing_challenge_transcript_digest\":\"sha256:{}\"}}",
                "a".repeat(64)
            )
        );

        let attestation = sign_device_pairing_target_proof(unsigned, &signing_key).unwrap();
        verify_device_pairing_target_proof(&attestation).unwrap();
        let value = serde_json::to_value(&attestation).unwrap();
        assert_eq!(value["device_key_algorithm"], "Ed25519");
        assert_eq!(value["authorization_binding_kind"], "accepted_device");
        assert!(value["device_signature"].is_string());
    }

    #[test]
    fn target_proof_rejects_tampering_polymorphic_signature_and_bad_algorithm_set() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[10_u8; 32]);
        let mut attestation =
            sign_device_pairing_target_proof(target_proof_fixture(&signing_key), &signing_key)
                .unwrap();
        attestation.hpke_key = NonEmptyString::new("tampered-hpke-key").unwrap();
        assert!(matches!(
            verify_device_pairing_target_proof(&attestation),
            Err(DevicePairingProofError::SignatureInvalid)
        ));

        let mut map_signature =
            sign_device_pairing_target_proof(target_proof_fixture(&signing_key), &signing_key)
                .unwrap();
        map_signature.device_signature = SignatureMaterial::Variant1(BTreeMap::new());
        assert!(matches!(
            verify_device_pairing_target_proof(&map_signature),
            Err(DevicePairingProofError::InvalidTargetProofSignatureShape)
        ));

        let device_id = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000009").unwrap();
        let did_key = arkret_wire::DidKey::new(format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                signing_key.verifying_key().as_bytes()
            )
        ))
        .unwrap();
        let digest = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        for algorithms in [
            Vec::new(),
            vec![
                NonEmptyString::new("MLS").unwrap(),
                NonEmptyString::new("Ed25519").unwrap(),
            ],
            vec![
                NonEmptyString::new("Ed25519").unwrap(),
                NonEmptyString::new("Ed25519").unwrap(),
            ],
        ] {
            assert!(
                UnsignedDevicePairingTargetProof::new(
                    device_id.clone(),
                    did_key.clone(),
                    NonEmptyString::new("hpke-public-key-fixture").unwrap(),
                    algorithms,
                    digest.clone(),
                )
                .is_err()
            );
        }
    }
}
