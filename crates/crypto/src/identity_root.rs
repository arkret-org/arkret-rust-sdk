//! Recovery-secret key schedule and recovery-proof authoring for principal identity roots.

use std::collections::BTreeMap;

use arkret_models_crypto::{
    GenericRecoveryTranscript, RecoveryIdentityModel, RecoveryModelGenerationRef,
    RecoveryProofKind, RecoverySessionProof, RecoverySessionState, RecoverySessionUnlockProof,
    RecoverySessionUnlockProofKind, SessionState,
};
use arkret_wire::{Base64UrlString, DidUrl, Hash, NonEmptyString};
use ed25519_dalek::{Signer as _, SigningKey};
use hpke::{Kem, Serializable};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const EXTRACT_SALT: &[u8] = b"arkret-identity-recovery-kdf-v1";
const ROOT_INFO: &[u8] = b"arkret/did-update/root/v1";
const RECOVERY_PROOF_INFO: &[u8] = b"arkret/recovery-proof/v1";
const BACKUP_HPKE_INFO: &[u8] = b"arkret/backup-hpke/v1";
const RECOVERY_UNLOCK_BINDING_DOMAIN: &[u8] = b"ak.recovery-session-unlock-binding-v1\n";
const X25519_MULTICODEC_PREFIX: [u8; 2] = [0xec, 0x01];
const HPKE_X25519_KEM_SUITE_ID: &[u8] = b"KEM\x00\x20";

#[derive(Debug, Error)]
pub enum IdentityRecoveryKdfError {
    #[error("BIP-39 mnemonic is invalid: {0}")]
    InvalidMnemonic(String),
    #[error("identity recovery requires an English 24-word BIP-39 mnemonic")]
    MnemonicMustHave24Words,
    #[error("identity recovery root generation overflow")]
    RootGenerationOverflow,
    #[error("identity recovery HKDF expansion failed")]
    HkdfExpand,
    #[error("identity recovery HPKE derivation disagrees with the RFC 9180 implementation")]
    HpkeDerivationMismatch,
}

#[derive(Debug, Error)]
pub enum RecoveryUnlockAuthoringError {
    #[error("recovery session is invalid: {0}")]
    InvalidSession(String),
    #[error("recovery_unlock may only be authored for a pending recovery session")]
    SessionNotPending,
    #[error("recovery secret ref is invalid: {0}")]
    InvalidRecoverySecretRef(String),
    #[error("recovery transcript canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("recovery proof field is invalid: {0}")]
    InvalidProofField(String),
}

/// Secret and public outputs for root generation `root_generation` and its
/// mandatory next-generation pre-rotation commitment.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityRecoveryKeyMaterial {
    pub prk: [u8; 32],
    #[zeroize(skip)]
    pub root_generation: u64,
    pub root_seed: [u8; 32],
    pub next_root_seed: [u8; 32],
    pub recovery_proof_seed: [u8; 32],
    pub backup_hpke_ikm: [u8; 32],
    #[zeroize(skip)]
    pub root_public_key: [u8; 32],
    #[zeroize(skip)]
    pub root_public_key_multikey: String,
    #[zeroize(skip)]
    pub next_root_public_key: [u8; 32],
    #[zeroize(skip)]
    pub next_root_public_key_multikey: String,
    #[zeroize(skip)]
    pub recovery_proof_public_key: [u8; 32],
    #[zeroize(skip)]
    pub recovery_proof_public_key_multikey: String,
    pub backup_hpke_derived_private_key: [u8; 32],
    pub backup_hpke_serialized_private_key: [u8; 32],
    #[zeroize(skip)]
    pub backup_hpke_public_key: [u8; 32],
    #[zeroize(skip)]
    pub backup_hpke_public_key_multikey: String,
    #[zeroize(skip)]
    pub next_root_key_hash: String,
}

impl std::fmt::Debug for IdentityRecoveryKeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityRecoveryKeyMaterial")
            .field("root_generation", &self.root_generation)
            .field("root_public_key_multikey", &self.root_public_key_multikey)
            .field(
                "next_root_public_key_multikey",
                &self.next_root_public_key_multikey,
            )
            .field("next_root_key_hash", &self.next_root_key_hash)
            .field("secret_material", &"<redacted>")
            .finish()
    }
}

/// Convert an English 24-word BIP-39 mnemonic and passphrase to its raw
/// 64-byte recovery secret. The bytes are fed directly into HKDF-Extract.
pub fn bip39_identity_recovery_secret(
    mnemonic_utf8: &str,
    passphrase_utf8: &str,
) -> Result<[u8; 64], IdentityRecoveryKdfError> {
    let mnemonic = bip39::Mnemonic::parse(mnemonic_utf8)
        .map_err(|error| IdentityRecoveryKdfError::InvalidMnemonic(error.to_string()))?;
    if mnemonic.word_count() != 24 {
        return Err(IdentityRecoveryKdfError::MnemonicMustHave24Words);
    }
    Ok(mnemonic.to_seed(passphrase_utf8))
}

/// Derive the complete principal identity schedule from raw recovery-secret
/// bytes. Callers should normally request generation 0 at inception.
pub fn derive_identity_recovery_key_material(
    recovery_secret_bytes: &[u8],
    root_generation: u64,
) -> Result<IdentityRecoveryKeyMaterial, IdentityRecoveryKdfError> {
    let next_generation = root_generation
        .checked_add(1)
        .ok_or(IdentityRecoveryKdfError::RootGenerationOverflow)?;
    let (prk_output, hkdf) =
        hkdf::Hkdf::<Sha256>::extract(Some(EXTRACT_SALT), recovery_secret_bytes);
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&prk_output);
    let root_seed = expand_root(&hkdf, root_generation)?;
    let next_root_seed = expand_root(&hkdf, next_generation)?;
    let recovery_proof_seed = expand_fixed(&hkdf, RECOVERY_PROOF_INFO)?;
    let backup_hpke_ikm = expand_fixed(&hkdf, BACKUP_HPKE_INFO)?;

    let root_public_key = SigningKey::from_bytes(&root_seed)
        .verifying_key()
        .to_bytes();
    let next_root_public_key = SigningKey::from_bytes(&next_root_seed)
        .verifying_key()
        .to_bytes();
    let recovery_proof_public_key = SigningKey::from_bytes(&recovery_proof_seed)
        .verifying_key()
        .to_bytes();
    let root_public_key_multikey = ed25519_public_multikey(&root_public_key);
    let next_root_public_key_multikey = ed25519_public_multikey(&next_root_public_key);
    let recovery_proof_public_key_multikey = ed25519_public_multikey(&recovery_proof_public_key);

    type BackupKem = hpke::kem::X25519HkdfSha256;
    let backup_hpke_derived_private_key = derive_hpke_x25519_raw_private_key(&backup_hpke_ikm)?;
    let (backup_private_key, backup_public_key) =
        <BackupKem as Kem>::derive_keypair(&backup_hpke_ikm);
    let backup_private_key_bytes = backup_private_key.to_bytes();
    let hpke_derived_private_key: [u8; 32] = backup_private_key_bytes[..]
        .try_into()
        .expect("X25519 private keys are exactly 32 bytes");
    if hpke_derived_private_key != backup_hpke_derived_private_key {
        return Err(IdentityRecoveryKdfError::HpkeDerivationMismatch);
    }
    let mut backup_hpke_serialized_private_key = backup_hpke_derived_private_key;
    backup_hpke_serialized_private_key[0] &= 248;
    backup_hpke_serialized_private_key[31] &= 127;
    backup_hpke_serialized_private_key[31] |= 64;
    let backup_public_key_bytes = backup_public_key.to_bytes();
    let backup_hpke_public_key: [u8; 32] = backup_public_key_bytes[..]
        .try_into()
        .expect("X25519 public keys are exactly 32 bytes");
    let backup_hpke_public_key_multikey = x25519_public_multikey(&backup_hpke_public_key);
    let next_root_key_hash = did_webvh_next_key_hash(&next_root_public_key_multikey);

    Ok(IdentityRecoveryKeyMaterial {
        prk,
        root_generation,
        root_seed,
        next_root_seed,
        recovery_proof_seed,
        backup_hpke_ikm,
        root_public_key,
        root_public_key_multikey,
        next_root_public_key,
        next_root_public_key_multikey,
        recovery_proof_public_key,
        recovery_proof_public_key_multikey,
        backup_hpke_derived_private_key,
        backup_hpke_serialized_private_key,
        backup_hpke_public_key,
        backup_hpke_public_key_multikey,
        next_root_key_hash,
    })
}

/// BIP-39 convenience wrapper for [`derive_identity_recovery_key_material`].
pub fn derive_identity_recovery_key_material_from_bip39(
    mnemonic_utf8: &str,
    passphrase_utf8: &str,
    root_generation: u64,
) -> Result<IdentityRecoveryKeyMaterial, IdentityRecoveryKdfError> {
    let mut secret = bip39_identity_recovery_secret(mnemonic_utf8, passphrase_utf8)?;
    let result = derive_identity_recovery_key_material(&secret, root_generation);
    secret.zeroize();
    result
}

/// Build the canonical §15 `recovery_unlock` transcript.
///
/// `proof_body` is exactly the submitted proof object with `signature` and
/// `unlock_commitment` omitted. The server reconstructs the same object from
/// its stored recovery-session snapshot; callers cannot supply model or
/// generation metadata independently.
pub fn recovery_unlock_transcript(
    session: &RecoverySessionState,
    recovery_secret_ref: &str,
) -> Result<GenericRecoveryTranscript, RecoveryUnlockAuthoringError> {
    session
        .validate()
        .map_err(|error| RecoveryUnlockAuthoringError::InvalidSession(error.to_string()))?;
    if session.state != SessionState::Pending {
        return Err(RecoveryUnlockAuthoringError::SessionNotPending);
    }
    let recovery_secret_ref =
        DidUrl::new(recovery_secret_ref.trim().to_owned()).map_err(|error| {
            RecoveryUnlockAuthoringError::InvalidRecoverySecretRef(error.to_owned())
        })?;
    let model_generation_ref = match session.identity_model {
        RecoveryIdentityModel::CrossSigning => {
            let generation = session
                .ssk_generation
                .and_then(std::num::NonZeroU64::new)
                .ok_or_else(|| {
                    RecoveryUnlockAuthoringError::InvalidSession(
                        "cross-signing session omits ssk_generation".to_owned(),
                    )
                })?;
            RecoveryModelGenerationRef::CrossSigning(generation)
        }
        RecoveryIdentityModel::EnrollmentAuthority => {
            RecoveryModelGenerationRef::EnrollmentAuthority(
                session
                    .current_device_generation_ref
                    .clone()
                    .ok_or_else(|| {
                        RecoveryUnlockAuthoringError::InvalidSession(
                            "enrollment-authority session omits current_device_generation_ref"
                                .to_owned(),
                        )
                    })?,
            )
        }
    };
    let proof_body = BTreeMap::from([
        ("alg".to_owned(), Value::String("Ed25519".to_owned())),
        (
            "challenge".to_owned(),
            serde_json::to_value(&session.challenge)
                .expect("challenge serialization is infallible"),
        ),
        (
            "kind".to_owned(),
            Value::String("recovery_unlock".to_owned()),
        ),
        (
            "recovery_secret_ref".to_owned(),
            Value::String(recovery_secret_ref.as_str().to_owned()),
        ),
        (
            "verification_method".to_owned(),
            Value::String(recovery_secret_ref.as_str().to_owned()),
        ),
    ]);
    let transcript = GenericRecoveryTranscript {
        schema: "ak.identity.recovery_proof.v1".to_owned(),
        kind: RecoveryProofKind::RecoveryUnlock,
        principal_id: session.principal_id.clone(),
        requesting_device_id: session.requesting_device_id.clone(),
        trust_domain: session.trust_domain.clone(),
        policy_id: session.policy_id.clone(),
        policy_version: session.policy_version,
        recovery_session_id: session.recovery_session_id.clone(),
        identity_model: session.identity_model,
        model_generation_ref,
        publication_authority_context_digest: session.publication_authority_context_digest.clone(),
        challenge: session.challenge.clone(),
        expires_at: session.expires_at,
        created_at: session.created_at,
        proof_body,
    };
    transcript
        .validate()
        .map_err(|error| RecoveryUnlockAuthoringError::InvalidSession(error.to_string()))?;
    Ok(transcript)
}

/// Author a role-separated Ed25519 `recovery_unlock` proof from an already
/// derived identity recovery schedule.
///
/// This function intentionally accepts [`IdentityRecoveryKeyMaterial`] rather
/// than an arbitrary signing key, preventing callers from substituting the
/// identity root or backup-HPKE key. The returned wire proof contains only
/// public data and a signature; secret material remains in the zeroizing key
/// schedule owned by the caller.
pub fn build_recovery_unlock_proof(
    session: &RecoverySessionState,
    recovery_secret_ref: &str,
    key_material: &IdentityRecoveryKeyMaterial,
) -> Result<RecoverySessionProof, RecoveryUnlockAuthoringError> {
    let transcript = recovery_unlock_transcript(session, recovery_secret_ref)?;
    let transcript_bytes = arkret_canonical::canonical_json_bytes(&transcript)
        .map_err(|error| RecoveryUnlockAuthoringError::Canonicalization(error.to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_UNLOCK_BINDING_DOMAIN);
    hasher.update(recovery_secret_ref.trim().as_bytes());
    hasher.update(&transcript_bytes);
    let unlock_commitment = Hash::new(format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|error| RecoveryUnlockAuthoringError::InvalidProofField(error.to_string()))?;

    let signing_key = SigningKey::from_bytes(&key_material.recovery_proof_seed);
    let signature = signing_key.sign(&transcript_bytes);
    let proof = RecoverySessionUnlockProof {
        kind: RecoverySessionUnlockProofKind::RecoveryUnlock,
        challenge: session.challenge.clone(),
        recovery_secret_ref: NonEmptyString::new(recovery_secret_ref.trim().to_owned())
            .map_err(|error| RecoveryUnlockAuthoringError::InvalidProofField(error.to_owned()))?,
        verification_method: DidUrl::new(recovery_secret_ref.trim().to_owned())
            .map_err(|error| RecoveryUnlockAuthoringError::InvalidProofField(error.to_owned()))?,
        alg: NonEmptyString::new("Ed25519")
            .map_err(|error| RecoveryUnlockAuthoringError::InvalidProofField(error.to_owned()))?,
        unlock_commitment,
        signature: Base64UrlString::new(arkret_canonical::base64url_encode(signature.to_bytes()))
            .map_err(|error| {
            RecoveryUnlockAuthoringError::InvalidProofField(error.to_owned())
        })?,
    };
    Ok(RecoverySessionProof::RecoveryUnlock(proof))
}

/// RFC 9180 DHKEM(X25519, HKDF-SHA256) raw `LabeledExpand` output before
/// RFC 7748 clamping. This is exposed to make KAT conformance unambiguous.
pub fn derive_hpke_x25519_raw_private_key(
    ikm: &[u8],
) -> Result<[u8; 32], IdentityRecoveryKdfError> {
    let mut labeled_ikm = Vec::with_capacity(7 + HPKE_X25519_KEM_SUITE_ID.len() + 7 + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(HPKE_X25519_KEM_SUITE_ID);
    labeled_ikm.extend_from_slice(b"dkp_prk");
    labeled_ikm.extend_from_slice(ikm);
    let (_, hkdf) = hkdf::Hkdf::<Sha256>::extract(Some(&[]), &labeled_ikm);

    let mut labeled_info = Vec::with_capacity(2 + 7 + HPKE_X25519_KEM_SUITE_ID.len() + 2);
    labeled_info.extend_from_slice(&32u16.to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(HPKE_X25519_KEM_SUITE_ID);
    labeled_info.extend_from_slice(b"sk");
    let mut output = [0u8; 32];
    hkdf.expand(&labeled_info, &mut output)
        .map_err(|_| IdentityRecoveryKdfError::HkdfExpand)?;
    labeled_ikm.zeroize();
    labeled_info.zeroize();
    Ok(output)
}

pub fn ed25519_public_multikey(public_key: &[u8; 32]) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(public_key)
}

pub fn x25519_public_multikey(public_key: &[u8; 32]) -> String {
    multikey(&X25519_MULTICODEC_PREFIX, public_key)
}

/// `Base58BTC(multihash(sha2-256, UTF8(root multikey)))`, with no multibase
/// prefix on the returned hash.
pub fn did_webvh_next_key_hash(root_public_key_multikey: &str) -> String {
    arkret_canonical::sha256_multihash_base58btc(root_public_key_multikey.as_bytes())
}

fn expand_root(
    hkdf: &hkdf::Hkdf<Sha256>,
    generation: u64,
) -> Result<[u8; 32], IdentityRecoveryKdfError> {
    let mut info = Vec::with_capacity(ROOT_INFO.len() + 8);
    info.extend_from_slice(ROOT_INFO);
    info.extend_from_slice(&generation.to_be_bytes());
    let result = expand_fixed(hkdf, &info);
    info.zeroize();
    result
}

fn expand_fixed(
    hkdf: &hkdf::Hkdf<Sha256>,
    info: &[u8],
) -> Result<[u8; 32], IdentityRecoveryKdfError> {
    let mut output = [0u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| IdentityRecoveryKdfError::HkdfExpand)?;
    Ok(output)
}

fn multikey(prefix: &[u8; 2], public_key: &[u8; 32]) -> String {
    let mut bytes = [0u8; 34];
    bytes[..2].copy_from_slice(prefix);
    bytes[2..].copy_from_slice(public_key);
    format!("z{}", arkret_canonical::multibase::encode_base58btc(bytes))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    use serde_json::json;

    use super::*;

    fn recovery_session(identity_model: &str) -> RecoverySessionState {
        let mut value = json!({
            "schema": "ak.schema.recovery_session.v1",
            "recovery_session_id": "ak:recovery_session:01964137-0000-7000-8000-0000000000aa",
            "principal_id": "did:web:alice.example",
            "requesting_device_id": "ak:device:01964137-0000-7000-8000-000000000099",
            "trust_domain": "ak:trust_domain:soland.local",
            "policy_id": "ak:policy:01964137-0000-7000-8000-0000000000bb",
            "policy_version": 3,
            "identity_model": identity_model,
            "challenge": "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm8",
            "state": "pending",
            "created_at": "2026-07-27T00:00:00.000Z",
            "updated_at": "2026-07-27T00:00:00.000Z",
            "expires_at": "2026-07-27T00:15:00.000Z"
        });
        let scope_ref = json!({
            "kind": "realm",
            "realm_id": "ak:realm:01964137-0000-7000-8000-000000000088"
        });
        if identity_model == "cross_signing" {
            value["ssk_generation"] = json!(7);
            let authority_set_policy = json!({
                "schema": "ak.schema.authority_set_policy.v1",
                "authority_set_id": "ak.authority_set.recovery_cross_signing.v1",
                "policy_kind": "principal_control",
                "scope_ref": scope_ref,
                "source": {
                    "source_kind": "cross_signing_publish",
                    "source_ref": "ak:cross_signing_publish:7",
                    "source_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "generation_ref": "7"
                },
                "authorization_rules": [{
                    "rule_id": "cross_signing",
                    "issuer_role": "cross_signing_self_signing",
                    "allowed_actions": [
                        "ak.device.authorize",
                        "ak.device.list_update"
                    ],
                    "issuers": [{
                        "verification_method": "did:web:alice.example#self-signing-7"
                    }],
                    "threshold": 1
                }]
            });
            let authority_set_digest =
                arkret_canonical::canonical_sha256(&authority_set_policy).unwrap();
            value["publication_authority_context"] = json!({
                "identity_model": "cross_signing",
                "basis_ref": "ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "scope_ref": scope_ref,
                "authority_set_ref": {
                    "authority_set_id": "ak.authority_set.recovery_cross_signing.v1",
                    "authority_set_digest": authority_set_digest
                },
                "authority_set_policy": authority_set_policy,
                "allowed_actions": [
                    "ak.device.authorize",
                    "ak.device.list_update"
                ]
            });
        } else {
            value["current_device_generation_ref"] = json!("12-zQmGeneration");
            value["device_generation_status"] = json!("active");
            value["registry_head"] =
                json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            value["accepted_seal_frontier"] = json!(null);
            let authority_set_policy = json!({
                "schema": "ak.schema.authority_set_policy.v1",
                "authority_set_id": "ak.authority_set.recovery_identity_reanchor.v1",
                "policy_kind": "principal_control",
                "scope_ref": scope_ref,
                "source": {
                    "source_kind": "recovery_policy",
                    "source_ref": "ak:policy:01964137-0000-7000-8000-000000000077",
                    "source_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "generation_ref": "1"
                },
                "authorization_rules": [{
                    "rule_id": "recovery_unlock",
                    "issuer_role": "identity_recovery",
                    "allowed_actions": ["ak.device.reanchor"],
                    "issuers": [{
                        "verification_method": "did:web:alice.example#identity-recovery-12"
                    }],
                    "threshold": 1
                }]
            });
            let authority_set_digest =
                arkret_canonical::canonical_sha256(&authority_set_policy).unwrap();
            value["publication_authority_context"] = json!({
                "identity_model": "enrollment_authority",
                "basis_ref": "ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "scope_ref": scope_ref,
                "authority_set_ref": {
                    "authority_set_id": "ak.authority_set.recovery_identity_reanchor.v1",
                    "authority_set_digest": authority_set_digest
                },
                "authority_set_policy": authority_set_policy,
                "allowed_actions": ["ak.device.reanchor"]
            });
        }
        value["publication_authority_context_digest"] = Value::String(
            arkret_canonical::canonical_sha256(&value["publication_authority_context"]).unwrap(),
        );
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn recovery_unlock_authoring_binds_snapshot_and_uses_recovery_proof_key() {
        let material = derive_identity_recovery_key_material_from_bip39(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "",
            0,
        )
        .unwrap();
        let session = recovery_session("cross_signing");
        let recovery_secret_ref = "did:web:alice.example#recovery-proof-0";
        let transcript = recovery_unlock_transcript(&session, recovery_secret_ref).unwrap();
        assert_eq!(transcript.schema, "ak.identity.recovery_proof.v1");
        assert_eq!(transcript.kind, RecoveryProofKind::RecoveryUnlock);
        assert_eq!(
            transcript.model_generation_ref,
            RecoveryModelGenerationRef::CrossSigning(std::num::NonZeroU64::new(7).unwrap())
        );
        assert_eq!(
            transcript.proof_body["recovery_secret_ref"],
            recovery_secret_ref
        );
        assert!(!transcript.proof_body.contains_key("signature"));
        assert!(!transcript.proof_body.contains_key("unlock_commitment"));

        let proof = build_recovery_unlock_proof(&session, recovery_secret_ref, &material).unwrap();
        let RecoverySessionProof::RecoveryUnlock(proof) = proof else {
            panic!("expected recovery_unlock proof");
        };
        let bytes = arkret_canonical::canonical_json_bytes(&transcript).unwrap();
        let signature_bytes = arkret_canonical::base64url_decode(proof.signature.as_str()).unwrap();
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        VerifyingKey::from_bytes(&material.recovery_proof_public_key)
            .unwrap()
            .verify(&bytes, &signature)
            .expect("role-separated recovery-proof key verifies");
        assert!(
            VerifyingKey::from_bytes(&material.root_public_key)
                .unwrap()
                .verify(&bytes, &signature)
                .is_err(),
            "identity root key must not substitute for recovery-proof"
        );
        let backup_hpke_substitution_rejected =
            VerifyingKey::from_bytes(&material.backup_hpke_public_key)
                .map_or(true, |key| key.verify(&bytes, &signature).is_err());
        assert!(
            backup_hpke_substitution_rejected,
            "backup-HPKE key must not substitute for recovery-proof"
        );

        let mut hasher = Sha256::new();
        hasher.update(RECOVERY_UNLOCK_BINDING_DOMAIN);
        hasher.update(recovery_secret_ref.as_bytes());
        hasher.update(&bytes);
        assert_eq!(
            proof.unlock_commitment.as_str(),
            format!("sha256:{}", hex::encode(hasher.finalize()))
        );
    }

    #[test]
    fn recovery_unlock_authoring_uses_b_model_generation_snapshot() {
        let session = recovery_session("enrollment_authority");
        let transcript =
            recovery_unlock_transcript(&session, "did:web:alice.example#recovery-proof-0").unwrap();
        assert_eq!(
            transcript.model_generation_ref,
            RecoveryModelGenerationRef::EnrollmentAuthority(
                NonEmptyString::new("12-zQmGeneration").unwrap()
            )
        );
    }

    #[test]
    fn recovery_unlock_authoring_rejects_terminal_session() {
        let mut session = recovery_session("cross_signing");
        session.state = SessionState::Expired;
        assert!(matches!(
            recovery_unlock_transcript(&session, "did:web:alice.example#recovery-proof-0"),
            Err(RecoveryUnlockAuthoringError::SessionNotPending)
        ));
    }

    #[test]
    fn raw_uniform_secret_matches_normative_known_answer() {
        let secret: Vec<u8> = (0u8..32).collect();
        let output = derive_identity_recovery_key_material(&secret, 0).unwrap();
        assert_eq!(
            hex::encode(output.prk),
            "5ff5f79aa72a247d0e3bbd5c2c66b4e0df32be9aa31fa18858e78d2db41f4565"
        );
        assert_eq!(
            hex::encode(output.root_seed),
            "f0c2e49bfdf7b5f1e549fd02e5615c699214ce640c0e6662d0bb4a0436ceec08"
        );
        assert_eq!(
            hex::encode(output.next_root_seed),
            "bdbc1938b4cc03522c2df7f989fce5f5680816cbcca94ef18030a2d448bd0cc8"
        );
        assert_eq!(
            hex::encode(output.recovery_proof_seed),
            "89b49c82dd34e8dc2df97e0253adc64668f8ebe862f34e8afd65a4f96a9ac460"
        );
        assert_eq!(
            hex::encode(output.backup_hpke_ikm),
            "d88f4ccfa46b377d6c3a69797fab007a198fc8799feffdff8d3115c155e562f1"
        );
        assert_eq!(
            hex::encode(output.root_public_key),
            "3e814bc0e1e955b0ef2c69d0cdd17e2f2285b7fcc1fe61ae2c06b1676112243b"
        );
        assert_eq!(
            output.root_public_key_multikey,
            "z6MkifFfyDctvY9FahpFQUhpzfRq61pWRKL8L5NtZHS4teFL"
        );
        assert_eq!(
            hex::encode(output.next_root_public_key),
            "32e707c4698a0bc0311ffaf220ccbce81d0f5e7069cd87b54196077a02849676"
        );
        assert_eq!(
            output.next_root_public_key_multikey,
            "z6MkhsxkjJkU3TE6qmVBz5vKvRLCTtsU24aef1fVYNXZRsUH"
        );
        assert_eq!(
            hex::encode(output.recovery_proof_public_key),
            "20f51b3b92d8eebb48c173f3b731acf9977f723d0ddffa66f43590f8dd8b0ff4"
        );
        assert_eq!(
            output.recovery_proof_public_key_multikey,
            "z6Mkgfus8Z5Cz3Az7fthBXJnjyxGbXz5d6PhK6f74ydoH1W3"
        );
        assert_eq!(
            hex::encode(output.backup_hpke_derived_private_key),
            "a544154ac9fa66b100ef81aac4646cb2219d1b2d543267d655ee8f9a93983efe"
        );
        assert_eq!(
            hex::encode(output.backup_hpke_serialized_private_key),
            "a044154ac9fa66b100ef81aac4646cb2219d1b2d543267d655ee8f9a93983e7e"
        );
        assert_eq!(
            hex::encode(output.backup_hpke_public_key),
            "d6b62463f35e292735477b8bafa89e226fdfe445a136d46919a7606969664234"
        );
        assert_eq!(
            output.backup_hpke_public_key_multikey,
            "z6LSr8KVwSrjSa7Bj6KagU93mSi8zQM6VfmmUoTb8xXJFEr7"
        );
        assert_eq!(
            output.next_root_key_hash,
            "QmPoFdu3Rs82D3zweenEWfX1TqsruL5bV9H5ynbp5NPKs3"
        );
    }

    #[test]
    fn bip39_case_matches_normative_known_answer() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let secret = bip39_identity_recovery_secret(mnemonic, "TREZOR").unwrap();
        assert_eq!(
            hex::encode(secret),
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
        );
        let output =
            derive_identity_recovery_key_material_from_bip39(mnemonic, "TREZOR", 0).unwrap();
        assert_eq!(
            hex::encode(output.prk),
            "ea4093da71b200d87080ba1cac7bb21881fd6ea0b8278181681c881a871c3d89"
        );
        assert_eq!(
            hex::encode(output.root_seed),
            "7ff7ae2a20caa53098484b1327a7a7f342e6435499ec9be025c2cb640f4ed3ad"
        );
        assert_eq!(
            hex::encode(output.next_root_seed),
            "fc87a5a0872114810f4fdf50a8e298a3aa671b0522d17b3f3e24ce20f3e7bffb"
        );
        assert_eq!(
            hex::encode(output.recovery_proof_seed),
            "5c8be4e6273db48462fd9bbdf39c61b03e15495ceb299e04af198090f0171d42"
        );
        assert_eq!(
            hex::encode(output.backup_hpke_ikm),
            "576d246fe84963831b11bfb6ea2de14759d384cfcc01bb7a8ccff54146fe4fd1"
        );
        assert_eq!(
            hex::encode(output.root_public_key),
            "ec4157798183be05275e55a89947b801ebfa3fb11c612d172c0730427355866b"
        );
        assert_eq!(
            output.root_public_key_multikey,
            "z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ"
        );
        assert_eq!(
            hex::encode(output.next_root_public_key),
            "7bf94b3b25288c1c973f40e2ed7baa776ea6e42b6b9353f3a742c094d98db793"
        );
        assert_eq!(
            output.next_root_public_key_multikey,
            "z6MknoCfkzmsoi3R98zoM8gNdsnQsouJQCaCYoeVJ6VkquSi"
        );
        assert_eq!(
            hex::encode(output.recovery_proof_public_key),
            "891220be7a6f9cab8b5b473ea6d4d34f5795d8cace835e87b7302607f49dd8ff"
        );
        assert_eq!(
            output.recovery_proof_public_key_multikey,
            "z6MkogKw38hXxUkpMWitoBubBGHZzeGrQJ4oHF36iegUbmpA"
        );
        assert_eq!(
            hex::encode(output.backup_hpke_derived_private_key),
            "4192a3e60a3859ff3b8504dcba5e655e46426afe16b55390d283ab3e17e37cb8"
        );
        assert_eq!(
            hex::encode(output.backup_hpke_serialized_private_key),
            "4092a3e60a3859ff3b8504dcba5e655e46426afe16b55390d283ab3e17e37c78"
        );
        assert_eq!(
            hex::encode(output.backup_hpke_public_key),
            "df788d7169420382ba1358ff083c77f48a8d98cf4b6f08efdc2555af8f41b06f"
        );
        assert_eq!(
            output.backup_hpke_public_key_multikey,
            "z6LSriWhVBzW9Vz2PvqbieSz7Aa2hPLzTKJuDwXTMKFeomeW"
        );
        assert_eq!(
            output.next_root_key_hash,
            "QmRavXTE9UUsrZCFT7ofELiVmUTZksxGLeetVC2Zv4dapA"
        );
    }
}
