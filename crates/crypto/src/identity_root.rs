//! Recovery-secret key schedule and recovery-proof authoring for principal identity roots.

use arkret_models_crypto::{
    GenericRecoveryProofBody, GenericRecoveryTranscript, RecoveryFactorSignatureAlgorithm,
    RecoveryProofKind, RecoverySessionProof, RecoverySessionState, RecoverySessionUnlockProof,
    RecoverySessionUnlockProofKind, RecoveryUnlockProofBody, SessionState,
};
use arkret_wire::{Base64UrlString, DidUrl, DomainSeparationId, Hash, NonEmptyString};
use ed25519_dalek::{Signer as _, SigningKey};
use hpke::{Kem, Serializable};
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
    #[error("identity recovery mnemonic entropy must be exactly 32 bytes")]
    InvalidMnemonicEntropyLength,
    #[error("identity recovery mnemonic entropy generation failed: {0}")]
    Entropy(String),
    #[error("identity recovery root generation overflow")]
    RootGenerationOverflow,
    #[error("identity recovery HKDF expansion failed")]
    HkdfExpand,
    #[error("identity recovery HPKE derivation disagrees with the RFC 9180 implementation")]
    HpkeDerivationMismatch,
}

/// Generate the canonical English 24-word BIP-39 presentation of a fresh
/// 256-bit identity recovery secret.
pub fn generate_bip39_identity_recovery_mnemonic() -> Result<String, IdentityRecoveryKdfError> {
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy)
        .map_err(|error| IdentityRecoveryKdfError::Entropy(error.to_string()))?;
    let result = format_bip39_identity_recovery_mnemonic(&entropy);
    entropy.zeroize();
    result
}

/// Render exactly 32 bytes of recovery entropy as an English 24-word BIP-39
/// mnemonic. This is the user-facing path named by key-management.md §3.3.
pub fn format_bip39_identity_recovery_mnemonic(
    entropy: &[u8],
) -> Result<String, IdentityRecoveryKdfError> {
    let entropy: &[u8; 32] = entropy
        .try_into()
        .map_err(|_| IdentityRecoveryKdfError::InvalidMnemonicEntropyLength)?;
    let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy)
        .map_err(|error| IdentityRecoveryKdfError::InvalidMnemonic(error.to_string()))?;
    Ok(mnemonic.words().collect::<Vec<_>>().join(" "))
}

/// Parse and return the canonical lower-case, single-space English 24-word
/// BIP-39 presentation accepted by the identity recovery KDF.
pub fn normalize_bip39_identity_recovery_mnemonic(
    input: &str,
) -> Result<String, IdentityRecoveryKdfError> {
    let collapsed = input.split_whitespace().collect::<Vec<_>>().join(" ");
    let mnemonic =
        bip39::Mnemonic::parse_in(bip39::Language::English, collapsed.to_ascii_lowercase())
            .map_err(|error| IdentityRecoveryKdfError::InvalidMnemonic(error.to_string()))?;
    if mnemonic.word_count() != 24 {
        return Err(IdentityRecoveryKdfError::MnemonicMustHave24Words);
    }
    Ok(mnemonic.words().collect::<Vec<_>>().join(" "))
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
    let normalized = normalize_bip39_identity_recovery_mnemonic(mnemonic_utf8)?;
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, normalized)
        .map_err(|error| IdentityRecoveryKdfError::InvalidMnemonic(error.to_string()))?;
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
    let model_generation_ref = session.current_device_generation_ref;
    let proof_body = GenericRecoveryProofBody::RecoveryUnlock(RecoveryUnlockProofBody {
        kind: RecoverySessionUnlockProofKind::RecoveryUnlock,
        challenge: session.challenge.clone(),
        recovery_secret_ref: NonEmptyString::new(recovery_secret_ref.as_str().to_owned())
            .map_err(|error| RecoveryUnlockAuthoringError::InvalidProofField(error.to_owned()))?,
        verification_method: recovery_secret_ref.clone(),
        signature_algorithm: RecoveryFactorSignatureAlgorithm::Ed25519,
    });
    let transcript = GenericRecoveryTranscript {
        schema: DomainSeparationId::IDENTITY_RECOVERY_PROOF_V1.to_owned(),
        kind: RecoveryProofKind::RecoveryUnlock,
        request_id: session.request_id.clone(),
        session_grant_id: session.session_grant_id.clone(),
        session_grant_cnf_jkt: session.session_grant_cnf_jkt.clone(),
        account_id: session.account_id.clone(),
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
        signature_algorithm: NonEmptyString::new("Ed25519")
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
    use super::*;

    #[test]
    fn mnemonic_helpers_share_one_canonical_24_word_representation() {
        let mnemonic = format_bip39_identity_recovery_mnemonic(&[0u8; 32]).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 24);
        let noisy = mnemonic
            .split_whitespace()
            .map(str::to_ascii_uppercase)
            .collect::<Vec<_>>()
            .join("   ");
        assert_eq!(
            normalize_bip39_identity_recovery_mnemonic(&noisy).unwrap(),
            mnemonic
        );
        assert_eq!(
            bip39_identity_recovery_secret(&noisy, "").unwrap(),
            bip39_identity_recovery_secret(&mnemonic, "").unwrap()
        );
    }

    #[test]
    fn mnemonic_formatter_rejects_non_256_bit_entropy() {
        assert!(matches!(
            format_bip39_identity_recovery_mnemonic(&[0u8; 16]),
            Err(IdentityRecoveryKdfError::InvalidMnemonicEntropyLength)
        ));
    }
}
