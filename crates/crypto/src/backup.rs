//! Client-side crypto for `cx.schema.key_backup.v1` envelopes.
//!
//! Spec: `crypto-media/key-management.md` §7 (Key Backup), §8 (Threshold
//! Recovery) and `crypto-media/devices-and-auth.md` §4.1 (Encrypted Cloud
//! Vault).
//!
//! The functions in this module are deliberately small and pure — they
//! take and return owned buffers, never touch the network, the
//! filesystem, or the DOM, and round-trip identically on every Rust
//! target the SDK supports (native + wasm32).
//!
//! End-to-end the spec mandates **three cryptographically isolated
//! backup classes** (`did_recovery`, `secret_storage`, `mls_history`);
//! the [`build_key_backup_envelope`] helper composes the typed
//! [`KeyBackup`] wire object so the caller cannot accidentally swap
//! domains. The HKDF info string is generated via
//! [`contrix_core::BackupClass::hkdf_info`] so the KDF subdomain stays
//! in lockstep with the wire schema.
//!
//! ```no_run
//! use contrix_crypto::backup::{derive_vault_kek, encrypt_vault, build_key_backup_envelope};
//! use contrix_core::BackupClass;
//!
//! let kek = derive_vault_kek(b"correct horse battery staple")?;
//! let ct = encrypt_vault(&kek, br#"{"recovery":"..."}"#)?;
//! let envelope = build_key_backup_envelope(
//!     "cx:backup:01964137-0000-7000-8000-000000000000".parse()?,
//!     "did:webvh:alice.example".parse()?,
//!     None,
//!     BackupClass::SecretStorage,
//!     "kb_1",
//!     &kek,
//!     &ct,
//!     &[("recovery_secret", None)],
//! )?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as B64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use chrono::Utc;
use getrandom::fill;
use serde_json::json;
use sha2::{Digest, Sha256};

use contrix_core::{
    BackupClass, BackupId, DeviceId, Did, KeyBackup, KeyBackupAead, KeyBackupContentItem,
    KeyBackupEncryption, KeyBackupKdf, KeyBackupRecipientMethod,
};

/// Argon2id parameters used by the Encrypted Cloud Vault. We pick the
/// OWASP-recommended values that complete in a couple of seconds on a
/// typical laptop but are still memory-hard enough to make offline
/// passphrase guessing expensive.
///
/// * `m_cost` 65 536 KiB = 64 MiB
/// * `t_cost` 3 iterations
/// * `p_cost` 4 parallel lanes
/// * 32-byte output (XChaCha20-Poly1305 key)
///
/// 128 MiB / t=3 / p=4 is only reachable on native; the browser fails
/// most allocations above ~64 MiB. We pick the lower bound on both
/// targets so the same parameters round-trip cross-platform.
pub const VAULT_ARGON2_M_KIB: u32 = 65_536;
pub const VAULT_ARGON2_T: u32 = 3;
pub const VAULT_ARGON2_P: u32 = 4;
pub const VAULT_KDF_OUTPUT_LEN: usize = 32;

/// Length of the random salt fed to Argon2id. 16 bytes (128 bits) is the
/// argon2 crate's documented minimum and matches OWASP guidance.
pub const VAULT_SALT_LEN: usize = 16;

/// Length of the XChaCha20-Poly1305 nonce. The X-variant takes a 24-byte
/// (192-bit) nonce, large enough for a random nonce to be safely used
/// without a counter.
pub const VAULT_NONCE_LEN: usize = 24;

/// Length of the high-entropy Recovery Key in bytes. 32 bytes = 256 bits
/// of entropy; encoded as five groups of six base32-style characters
/// this gives the user a memorable, copy-pasteable string.
pub const RECOVERY_KEY_BYTES: usize = 32;

/// Backup version tag used by [`build_key_backup_envelope`] when the
/// caller has no preference. Matches the JSON-schema pattern
/// `kb_[A-Za-z0-9_-]+` so future codec evolution stays explicit.
pub const DEFAULT_BACKUP_VERSION: &str = "kb_1";

/// Outcome of [`derive_vault_kek`]: the KEK plus the parameters that
/// generated it. The parameters round-trip into the backup envelope so
/// any future device can reproduce the KDF given just the passphrase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultKek {
    pub key: [u8; VAULT_KDF_OUTPUT_LEN],
    pub salt: [u8; VAULT_SALT_LEN],
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

/// Outcome of [`encrypt_vault`]: the ciphertext (Poly1305 tag appended
/// by the AEAD), the random nonce, and base64-encoded views of both so
/// the caller can hand them straight to [`build_key_backup_envelope`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultCiphertext {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; VAULT_NONCE_LEN],
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub salt_b64: String,
    pub digest_sha256: String,
}

/// Stretch a user passphrase into a 32-byte key under Argon2id with a
/// fresh random salt. Returns the KEK alongside the salt so the caller
/// can store the salt as backup metadata.
pub fn derive_vault_kek(passphrase: &[u8]) -> Result<VaultKek> {
    let mut salt = [0u8; VAULT_SALT_LEN];
    fill(&mut salt).map_err(|err| anyhow!("salt rng: {err}"))?;
    derive_vault_kek_with_salt(passphrase, &salt)
}

/// Variant of [`derive_vault_kek`] with caller-supplied salt — used both
/// in tests (deterministic vectors) and on the recovery path when a
/// previously stored backup is being decrypted.
pub fn derive_vault_kek_with_salt(
    passphrase: &[u8],
    salt: &[u8; VAULT_SALT_LEN],
) -> Result<VaultKek> {
    let params = Params::new(VAULT_ARGON2_M_KIB, VAULT_ARGON2_T, VAULT_ARGON2_P, None)
        .map_err(|err| anyhow!("argon2 params: {err}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; VAULT_KDF_OUTPUT_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|err| anyhow!("argon2 hash: {err}"))?;
    Ok(VaultKek {
        key,
        salt: *salt,
        m_kib: VAULT_ARGON2_M_KIB,
        t: VAULT_ARGON2_T,
        p: VAULT_ARGON2_P,
    })
}

/// Encrypt vault plaintext under the KEK with XChaCha20-Poly1305 and a
/// fresh random nonce. The returned struct carries everything the
/// backup envelope needs (ciphertext, nonce, salt, sha256 digest).
pub fn encrypt_vault(kek: &VaultKek, plaintext: &[u8]) -> Result<VaultCiphertext> {
    let cipher = XChaCha20Poly1305::new((&kek.key).into());
    let mut nonce_bytes = [0u8; VAULT_NONCE_LEN];
    fill(&mut nonce_bytes).map_err(|err| anyhow!("nonce rng: {err}"))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|err| anyhow!("xchacha20poly1305 encrypt: {err}"))?;
    let digest = Sha256::digest(&ciphertext);
    Ok(VaultCiphertext {
        ciphertext_b64: B64.encode(&ciphertext),
        nonce_b64: B64.encode(nonce_bytes),
        salt_b64: B64.encode(kek.salt),
        digest_sha256: format!("sha256:{}", hex_lower(&digest)),
        ciphertext,
        nonce: nonce_bytes,
    })
}

/// Decrypt a previously produced vault ciphertext. Returns an error if
/// the passphrase is wrong (AEAD tag mismatch) or any input is
/// malformed. Used by the "restore from backup" flow and by every test
/// that wants to round-trip an envelope.
pub fn decrypt_vault(
    passphrase: &[u8],
    salt_b64: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> Result<Vec<u8>> {
    let salt_bytes = B64.decode(salt_b64.trim_end_matches('=')).context("salt base64")?;
    let salt: [u8; VAULT_SALT_LEN] =
        salt_bytes.try_into().map_err(|_| anyhow!("salt must be {VAULT_SALT_LEN} bytes"))?;
    let nonce_bytes = B64.decode(nonce_b64.trim_end_matches('=')).context("nonce base64")?;
    let nonce_array: [u8; VAULT_NONCE_LEN] =
        nonce_bytes.try_into().map_err(|_| anyhow!("nonce must be {VAULT_NONCE_LEN} bytes"))?;
    let ciphertext =
        B64.decode(ciphertext_b64.trim_end_matches('=')).context("ciphertext base64")?;
    let kek = derive_vault_kek_with_salt(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&kek.key).into());
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce_array), ciphertext.as_slice())
        .map_err(|_| anyhow!("vault decrypt failed: wrong passphrase or corrupt ciphertext"))?;
    Ok(plaintext)
}

/// Generate a fresh Recovery Key as a human-readable string of
/// Crockford-base32-style groups (alphabet `0-9 + A-Z` minus `I/L/O/U`
/// to avoid look-alikes). 32 random bytes (256 bits) are encoded as 50
/// characters in five-character groups separated by `-`.
pub fn generate_recovery_key() -> Result<String> {
    let mut bytes = [0u8; RECOVERY_KEY_BYTES];
    fill(&mut bytes).map_err(|err| anyhow!("recovery key rng: {err}"))?;
    Ok(format_recovery_key(&bytes))
}

/// Render the recovery-key string from raw bytes — split out so the
/// generator is testable without consuming entropy.
pub fn format_recovery_key(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;
    let mut groups: Vec<String> = Vec::with_capacity(8);
    let mut current = String::with_capacity(5);
    for &b in bytes {
        bits = (bits << 8) | u64::from(b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((bits >> nbits) & 0x1F) as usize;
            current.push(ALPHABET[idx] as char);
            if current.len() == 5 {
                groups.push(std::mem::take(&mut current));
            }
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups.join("-")
}

/// SHA-256 the recovery key (UTF-8) and return `"sha256:<hex>"`. Only
/// the digest is persisted on disk so the plaintext is gone the moment
/// the user dismisses the "copy / print" affordance.
pub fn fingerprint_recovery_key(recovery_key: &str) -> String {
    let digest = Sha256::digest(recovery_key.as_bytes());
    format!("sha256:{}", hex_lower(&digest))
}

/// Heuristic passphrase strength on a 0..=5 scale. Pure function so a
/// UI can call it on every keystroke without touching state.
pub fn estimate_passphrase_strength(passphrase: &str) -> u8 {
    if passphrase.is_empty() {
        return 0;
    }
    let mut score = 0i32;
    let len = passphrase.chars().count();
    score += match len {
        0..=7 => 0,
        8..=11 => 1,
        12..=15 => 2,
        16..=23 => 3,
        _ => 4,
    };
    let mut classes = 0;
    if passphrase.chars().any(|c| c.is_ascii_lowercase()) {
        classes += 1;
    }
    if passphrase.chars().any(|c| c.is_ascii_uppercase()) {
        classes += 1;
    }
    if passphrase.chars().any(|c| c.is_ascii_digit()) {
        classes += 1;
    }
    if passphrase.chars().any(|c| !c.is_ascii_alphanumeric()) {
        classes += 1;
    }
    score += match classes {
        4 | 3 => 1,
        _ => 0,
    };
    score.clamp(0, 5) as u8
}

/// Build a typed [`KeyBackup`] envelope from a previously produced
/// [`VaultCiphertext`]. `contents` is `(item_type, optional secret_id)`.
/// The KDF parameters and HKDF info reflect [`BackupClass::hkdf_info`]
/// so the envelope respects the spec's three-domain isolation
/// (key-management.md §7.1).
#[allow(clippy::too_many_arguments)]
pub fn build_key_backup_envelope(
    backup_id: BackupId,
    actor_id: Did,
    device_id: Option<DeviceId>,
    backup_class: BackupClass,
    backup_version: &str,
    kek: &VaultKek,
    ciphertext: &VaultCiphertext,
    contents: &[(&str, Option<&str>)],
) -> Result<KeyBackup> {
    if !backup_version.starts_with("kb_") {
        return Err(anyhow!(
            "backup_version must match the kb_<id> pattern (got {backup_version:?})"
        ));
    }
    let kdf_params = json!({
        "memory_kib": kek.m_kib,
        "iterations": kek.t,
        "parallelism": kek.p,
        "hkdf_info": backup_class.hkdf_info("envelope"),
    });
    let kdf = KeyBackupKdf {
        name: "argon2id".to_owned(),
        salt: ciphertext.salt_b64.clone(),
        params: kdf_params,
        degraded_profile_reason: None,
        extra: Default::default(),
    };
    let aead = KeyBackupAead {
        name: "xchacha20_poly1305".to_owned(),
        nonce: ciphertext.nonce_b64.clone(),
        extra: Default::default(),
    };
    let encryption = KeyBackupEncryption {
        recipient_method: KeyBackupRecipientMethod::PassphraseKdf,
        recipient_key_ref: None,
        kdf: Some(kdf),
        aead,
        key_commitment: Some(format!("sha256:{}", hex_lower(&commitment_digest(&kek.key)))),
        extra: Default::default(),
    };
    let contents: Vec<KeyBackupContentItem> = contents
        .iter()
        .map(|(item_type, secret_id)| KeyBackupContentItem {
            item_type: (*item_type).to_owned(),
            space_id: None,
            mls_group_id: None,
            epoch: None,
            first_event_id: None,
            last_event_id: None,
            secret_id: secret_id.map(|s| s.to_owned()),
            extra: Default::default(),
        })
        .collect();
    Ok(KeyBackup {
        backup_id,
        actor_id,
        device_id,
        backup_class,
        mixed_secret_storage: false,
        backup_version: backup_version.to_owned(),
        created_at: Utc::now(),
        updated_at: None,
        expires_at: None,
        encryption,
        contents,
        ciphertext: ciphertext.ciphertext_b64.clone(),
        ciphertext_digest: ciphertext.digest_sha256.clone(),
        plaintext_commitment: None,
        auth_data: None,
        retention: None,
        extra: Default::default(),
    })
}

/// Key commitment used by the AEAD envelope (spec §7.2). Local fast
/// rejection of a wrong passphrase: `sha256(HKDF(key,
/// info="contrix-key-backup-commitment-v1"))` collapses to
/// `sha256(key || "contrix-key-backup-commitment-v1")` because we don't
/// need a stretching pass here — the key is already the KDF output.
fn commitment_digest(key: &[u8; VAULT_KDF_OUTPUT_LEN]) -> Vec<u8> {
    static INFO: OnceLock<&'static [u8]> = OnceLock::new();
    let info = *INFO.get_or_init(|| b"contrix-key-backup-commitment-v1".as_slice());
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(info);
    hasher.finalize().to_vec()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_is_deterministic_under_fixed_salt() {
        let salt = [42u8; VAULT_SALT_LEN];
        let a = derive_vault_kek_with_salt(b"correct horse battery staple", &salt).unwrap();
        let b = derive_vault_kek_with_salt(b"correct horse battery staple", &salt).unwrap();
        assert_eq!(a.key, b.key);
        assert_eq!(a.m_kib, VAULT_ARGON2_M_KIB);
        assert_eq!(a.t, VAULT_ARGON2_T);
        assert_eq!(a.p, VAULT_ARGON2_P);
    }

    #[test]
    fn argon2id_differs_under_different_salt() {
        let a = derive_vault_kek_with_salt(b"hunter2", &[1u8; VAULT_SALT_LEN]).unwrap();
        let b = derive_vault_kek_with_salt(b"hunter2", &[2u8; VAULT_SALT_LEN]).unwrap();
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let kek = derive_vault_kek_with_salt(b"open sesame", &[7u8; VAULT_SALT_LEN]).unwrap();
        let plaintext = br#"{"device_sk":"opaque"}"#;
        let ct = encrypt_vault(&kek, plaintext).unwrap();
        let recovered =
            decrypt_vault(b"open sesame", &ct.salt_b64, &ct.nonce_b64, &ct.ciphertext_b64).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_rejects_wrong_passphrase() {
        let kek = derive_vault_kek_with_salt(b"first", &[3u8; VAULT_SALT_LEN]).unwrap();
        let ct = encrypt_vault(&kek, b"payload").unwrap();
        let err =
            decrypt_vault(b"second", &ct.salt_b64, &ct.nonce_b64, &ct.ciphertext_b64).unwrap_err();
        assert!(err.to_string().contains("vault decrypt failed"));
    }

    #[test]
    fn recovery_key_format_is_grouped() {
        let key = format_recovery_key(&[0xFFu8; RECOVERY_KEY_BYTES]);
        let groups: Vec<&str> = key.split('-').collect();
        assert!(groups.len() >= 5);
        for g in &groups {
            assert!(!g.is_empty());
            for c in g.chars() {
                let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
                assert!(alphabet.contains(&(c as u8)), "non-alphabet char: {c}");
            }
        }
    }

    #[test]
    fn fingerprint_is_stable_and_hex() {
        let fp = fingerprint_recovery_key("EAGLE-HARP-SUNDAY-ROOK-9F2C-Q1A0");
        assert!(fp.starts_with("sha256:"));
        assert_eq!(fp.len(), "sha256:".len() + 64);
        assert!(fp.chars().skip("sha256:".len()).all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fp, fingerprint_recovery_key("EAGLE-HARP-SUNDAY-ROOK-9F2C-Q1A0"));
    }

    #[test]
    fn passphrase_strength_grows_with_length_and_classes() {
        assert_eq!(estimate_passphrase_strength(""), 0);
        assert!(
            estimate_passphrase_strength("short")
                < estimate_passphrase_strength("longerpassphrase")
        );
        assert!(
            estimate_passphrase_strength("alllowercaseonly")
                < estimate_passphrase_strength("Alllowercaseonly1!")
        );
        assert_eq!(estimate_passphrase_strength("Correct horse battery staple 9!"), 5);
    }

    #[test]
    fn envelope_carries_kdf_aead_and_commitment() {
        let kek = derive_vault_kek_with_salt(b"pp", &[5u8; VAULT_SALT_LEN]).unwrap();
        let ct = encrypt_vault(&kek, b"hello").unwrap();
        let envelope = build_key_backup_envelope(
            "cx:backup:01964137-0000-7000-8000-000000000000".parse().unwrap(),
            "did:webvh:alice.example".parse().unwrap(),
            None,
            BackupClass::SecretStorage,
            "kb_1",
            &kek,
            &ct,
            &[("recovery_secret", Some("vault_payload"))],
        )
        .unwrap();
        assert_eq!(envelope.backup_class, BackupClass::SecretStorage);
        assert_eq!(envelope.encryption.aead.name, "xchacha20_poly1305");
        assert!(envelope.encryption.kdf.is_some());
        let kdf = envelope.encryption.kdf.as_ref().unwrap();
        assert_eq!(kdf.name, "argon2id");
        assert_eq!(kdf.salt, ct.salt_b64);
        assert_eq!(kdf.params["memory_kib"], VAULT_ARGON2_M_KIB);
        assert_eq!(kdf.params["iterations"], VAULT_ARGON2_T);
        assert_eq!(kdf.params["parallelism"], VAULT_ARGON2_P);
        assert_eq!(kdf.params["hkdf_info"], "contrix-key-backup/secret_storage/envelope/v1");
        assert_eq!(envelope.ciphertext, ct.ciphertext_b64);
        assert_eq!(envelope.ciphertext_digest, ct.digest_sha256);
        assert!(envelope.encryption.key_commitment.is_some());
        assert_eq!(envelope.contents.len(), 1);
        assert_eq!(envelope.contents[0].item_type, "recovery_secret");
    }

    #[test]
    fn envelope_rejects_bad_version_tag() {
        let kek = derive_vault_kek_with_salt(b"pp", &[5u8; VAULT_SALT_LEN]).unwrap();
        let ct = encrypt_vault(&kek, b"x").unwrap();
        let err = build_key_backup_envelope(
            "cx:backup:01964137-0000-7000-8000-000000000000".parse().unwrap(),
            "did:webvh:alice.example".parse().unwrap(),
            None,
            BackupClass::SecretStorage,
            "1",
            &kek,
            &ct,
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains("backup_version"));
    }
}
