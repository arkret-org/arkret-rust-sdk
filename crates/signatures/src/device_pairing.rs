//! Canonical device-pairing challenge transcript generation and verification.

use arkret_models_collaboration::governance::agent_artifacts::PublicKey;
use arkret_models_collaboration::http_bodies::{
    DevicePairingBootstrap, DevicePairingChallengeProof, DevicePairingChallengeTranscriptKind,
    DevicePairingCode, DevicePairingNonce, DevicePairingRequestId, DevicePairingStageOutcome,
    DevicePairingToDeviceChallengeTranscript,
};
use arkret_wire::{Base64UrlString, DeviceId, Hash, NonEmptyString};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer as _;
use serde::Serialize;

const SERVER_TRANSCRIPT: &str = "ak.device-pairing.challenge.v1";
const TO_DEVICE_TRANSCRIPT: &str = "ak.device-pairing.challenge.to_device.v1";

#[derive(Clone, Debug)]
pub struct ServerDevicePairingChallenge {
    pub client_nonce: DevicePairingNonce,
    pub device_pairing_request_id: DevicePairingRequestId,
    pub expires_at: DateTime<Utc>,
    pub gate_audience: String,
    pub pairing_code: DevicePairingCode,
    pub server_nonce: DevicePairingNonce,
}

impl ServerDevicePairingChallenge {
    pub fn from_stage(
        client_nonce: DevicePairingNonce,
        outcome: &DevicePairingStageOutcome,
    ) -> Self {
        Self {
            client_nonce,
            device_pairing_request_id: outcome.device_pairing_request_id.clone(),
            expires_at: outcome.expires_at,
            gate_audience: outcome.gate_audience.clone(),
            pairing_code: outcome.pairing_code.clone(),
            server_nonce: outcome.server_nonce.clone(),
        }
    }

    pub fn from_bootstrap(bootstrap: &DevicePairingBootstrap) -> Self {
        Self {
            client_nonce: bootstrap.client_nonce.clone(),
            device_pairing_request_id: bootstrap.device_pairing_request_id.clone(),
            expires_at: bootstrap.expires_at,
            gate_audience: bootstrap.gate_audience.clone(),
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
    #[error("device pairing proof algorithm does not match new_device_pubkey.alg")]
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
    InvalidSignature,
    #[error("device pairing transcript could not be canonicalized: {0}")]
    Canonical(#[from] arkret_canonical::CanonicalError),
    #[error("device pairing wire value is invalid: {0}")]
    Wire(#[from] arkret_wire::Error),
}

#[derive(Serialize)]
struct ServerTranscriptBody<'a> {
    client_nonce: &'a str,
    device_pairing_request_id: &'a str,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    gate_audience: &'a str,
    new_device_pubkey_digest: &'a str,
    pairing_code: &'a str,
    server_nonce: &'a str,
}

#[derive(Serialize)]
struct ToDeviceTranscriptBody<'a> {
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    gate_audience: &'a str,
    new_device_pubkey_digest: &'a str,
    pairing_code: &'a str,
    request_canonical_digest: &'a str,
    transaction_id: &'a str,
}

pub fn server_device_pairing_transcript(
    public_key: &PublicKey,
    challenge: &ServerDevicePairingChallenge,
) -> Result<(Vec<u8>, Hash), DevicePairingProofError> {
    let public_key_digest = arkret_canonical::canonical_sha256(public_key)?;
    let body = ServerTranscriptBody {
        client_nonce: challenge.client_nonce.as_str(),
        device_pairing_request_id: challenge.device_pairing_request_id.as_str(),
        expires_at: challenge.expires_at,
        gate_audience: &challenge.gate_audience,
        new_device_pubkey_digest: &public_key_digest,
        pairing_code: challenge.pairing_code.as_str(),
        server_nonce: challenge.server_nonce.as_str(),
    };
    let mut bytes = format!("{SERVER_TRANSCRIPT}\n").into_bytes();
    bytes.extend(arkret_canonical::canonical_json_bytes(&body)?);
    let digest = Hash::new(format!("sha256:{}", arkret_canonical::sha256_hex(&bytes)))
        .map_err(arkret_wire::Error::from)?;
    Ok((bytes, digest))
}

pub fn sign_server_device_pairing_challenge(
    public_key: &PublicKey,
    challenge: &ServerDevicePairingChallenge,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<DevicePairingChallengeProof, DevicePairingProofError> {
    validate_public_key(public_key, signing_key.verifying_key().as_bytes())?;
    let (bytes, transcript_digest) = server_device_pairing_transcript(public_key, challenge)?;
    let kid = DeviceId::new(public_key.kid.as_str().to_owned())
        .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    Ok(DevicePairingChallengeProof {
        transcript: DevicePairingChallengeTranscriptKind::ServerMediated,
        kid,
        alg: NonEmptyString::new(public_key.alg.as_str().to_owned())
            .map_err(|error| arkret_wire::Error::Protocol(error.to_owned()))?,
        transcript_digest,
        signature: Base64UrlString::new(
            URL_SAFE_NO_PAD.encode(signing_key.sign(&bytes).to_bytes()),
        )
        .map_err(|error| arkret_wire::Error::Protocol(error.to_owned()))?,
    })
}

pub fn verify_server_device_pairing_challenge(
    public_key: &PublicKey,
    challenge: &ServerDevicePairingChallenge,
    proof: &DevicePairingChallengeProof,
    verification_time: DateTime<Utc>,
) -> Result<(), DevicePairingProofError> {
    if challenge.expires_at <= verification_time {
        return Err(DevicePairingProofError::Expired);
    }
    if proof.transcript != DevicePairingChallengeTranscriptKind::ServerMediated {
        return Err(DevicePairingProofError::TranscriptMismatch);
    }
    if proof.kid.as_str() != public_key.kid.as_str() {
        return Err(DevicePairingProofError::VerificationMethodMismatch);
    }
    if proof.alg.as_str() != public_key.alg.as_str() {
        return Err(DevicePairingProofError::AlgorithmMismatch);
    }
    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(public_key.key.as_str())
        .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    validate_public_key(public_key, &public_key_array)?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    let (bytes, digest) = server_device_pairing_transcript(public_key, challenge)?;
    if digest != proof.transcript_digest {
        return Err(DevicePairingProofError::DigestMismatch);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(proof.signature.as_str())
        .map_err(|_| DevicePairingProofError::MalformedSignature)?;
    let signature = ed25519_dalek::Signature::from_slice(&signature)
        .map_err(|_| DevicePairingProofError::MalformedSignature)?;
    verifying_key
        .verify_strict(&bytes, &signature)
        .map_err(|_| DevicePairingProofError::InvalidSignature)
}

pub fn to_device_pairing_transcript(
    public_key: &PublicKey,
    pairing_code: &DevicePairingCode,
    gate_audience: &str,
    challenge: &DevicePairingToDeviceChallengeTranscript,
) -> Result<(Vec<u8>, Hash), DevicePairingProofError> {
    let public_key_digest = arkret_canonical::canonical_sha256(public_key)?;
    let body = ToDeviceTranscriptBody {
        expires_at: challenge.expires_at,
        gate_audience,
        new_device_pubkey_digest: &public_key_digest,
        pairing_code: pairing_code.as_str(),
        request_canonical_digest: challenge.request_canonical_digest.as_str(),
        transaction_id: challenge.transaction_id.as_str(),
    };
    let mut bytes = format!("{TO_DEVICE_TRANSCRIPT}\n").into_bytes();
    bytes.extend(arkret_canonical::canonical_json_bytes(&body)?);
    let digest = Hash::new(format!("sha256:{}", arkret_canonical::sha256_hex(&bytes)))
        .map_err(arkret_wire::Error::from)?;
    Ok((bytes, digest))
}

pub fn sign_to_device_pairing_challenge(
    public_key: &PublicKey,
    pairing_code: &DevicePairingCode,
    gate_audience: &str,
    challenge: &DevicePairingToDeviceChallengeTranscript,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<DevicePairingChallengeProof, DevicePairingProofError> {
    validate_public_key(public_key, signing_key.verifying_key().as_bytes())?;
    let (bytes, transcript_digest) =
        to_device_pairing_transcript(public_key, pairing_code, gate_audience, challenge)?;
    let kid = DeviceId::new(public_key.kid.as_str().to_owned())
        .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    Ok(DevicePairingChallengeProof {
        transcript: DevicePairingChallengeTranscriptKind::ToDevice,
        kid,
        alg: NonEmptyString::new(public_key.alg.as_str().to_owned())
            .map_err(|error| arkret_wire::Error::Protocol(error.to_owned()))?,
        transcript_digest,
        signature: Base64UrlString::new(
            URL_SAFE_NO_PAD.encode(signing_key.sign(&bytes).to_bytes()),
        )
        .map_err(|error| arkret_wire::Error::Protocol(error.to_owned()))?,
    })
}

pub fn verify_to_device_pairing_challenge(
    public_key: &PublicKey,
    pairing_code: &DevicePairingCode,
    gate_audience: &str,
    challenge: &DevicePairingToDeviceChallengeTranscript,
    proof: &DevicePairingChallengeProof,
    verification_time: DateTime<Utc>,
) -> Result<(), DevicePairingProofError> {
    if challenge.expires_at <= verification_time {
        return Err(DevicePairingProofError::Expired);
    }
    if proof.transcript != DevicePairingChallengeTranscriptKind::ToDevice {
        return Err(DevicePairingProofError::TranscriptMismatch);
    }
    if proof.kid.as_str() != public_key.kid.as_str() {
        return Err(DevicePairingProofError::VerificationMethodMismatch);
    }
    if proof.alg.as_str() != public_key.alg.as_str() {
        return Err(DevicePairingProofError::AlgorithmMismatch);
    }
    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(public_key.key.as_str())
        .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    validate_public_key(public_key, &public_key_array)?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| DevicePairingProofError::UnsupportedKey)?;
    let (bytes, digest) =
        to_device_pairing_transcript(public_key, pairing_code, gate_audience, challenge)?;
    if digest != proof.transcript_digest {
        return Err(DevicePairingProofError::DigestMismatch);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(proof.signature.as_str())
        .map_err(|_| DevicePairingProofError::MalformedSignature)?;
    let signature = ed25519_dalek::Signature::from_slice(&signature)
        .map_err(|_| DevicePairingProofError::MalformedSignature)?;
    verifying_key
        .verify_strict(&bytes, &signature)
        .map_err(|_| DevicePairingProofError::InvalidSignature)
}

fn validate_public_key(
    public_key: &PublicKey,
    expected_bytes: &[u8; 32],
) -> Result<(), DevicePairingProofError> {
    if public_key.kty.as_str() != "OKP" || !matches!(public_key.alg.as_str(), "EdDSA" | "Ed25519") {
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
            alg: NonEmptyString::new("EdDSA").unwrap(),
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
            gate_audience: "https://account.example".to_owned(),
            pairing_code: DevicePairingCode::new("ABCDEFGH".to_owned()).unwrap(),
            server_nonce: DevicePairingNonce::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap(),
        };
        (public_key, challenge, signing_key)
    }

    #[test]
    fn server_transcript_round_trip_and_tamper_rejection() {
        let (public_key, challenge, signing_key) = fixture();
        let proof =
            sign_server_device_pairing_challenge(&public_key, &challenge, &signing_key).unwrap();
        let verification_time = DateTime::parse_from_rfc3339("2026-07-26T00:05:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        verify_server_device_pairing_challenge(&public_key, &challenge, &proof, verification_time)
            .unwrap();

        let mut tampered = challenge;
        tampered.gate_audience = "https://attacker.example".to_owned();
        assert!(matches!(
            verify_server_device_pairing_challenge(
                &public_key,
                &tampered,
                &proof,
                verification_time
            ),
            Err(DevicePairingProofError::DigestMismatch)
        ));
    }
}
