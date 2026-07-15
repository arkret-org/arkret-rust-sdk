//! Recovery-secret key schedule for principal identity roots.

use ed25519_dalek::SigningKey;
use hpke::{Kem, Serializable};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const EXTRACT_SALT: &[u8] = b"arkret-identity-recovery-kdf-v1";
const ROOT_INFO: &[u8] = b"arkret/did-update/root/v1";
const RECOVERY_PROOF_INFO: &[u8] = b"arkret/recovery-proof/v1";
const BACKUP_HPKE_INFO: &[u8] = b"arkret/backup-hpke/v1";
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
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
    multikey(&ED25519_MULTICODEC_PREFIX, public_key)
}

pub fn x25519_public_multikey(public_key: &[u8; 32]) -> String {
    multikey(&X25519_MULTICODEC_PREFIX, public_key)
}

/// `Base58BTC(multihash(sha2-256, UTF8(root multikey)))`, with no multibase
/// prefix on the returned hash.
pub fn did_webvh_next_key_hash(root_public_key_multikey: &str) -> String {
    let digest = arkret_canonical::canonical::sha256_bytes(root_public_key_multikey.as_bytes());
    let mut multihash = Vec::with_capacity(34);
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(&digest);
    arkret_core::encode_base58btc(&multihash)
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
    format!("z{}", arkret_core::encode_base58btc(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

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
