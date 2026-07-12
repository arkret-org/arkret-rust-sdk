//! Client-side crypto for `ak.schema.key_backup.v1` envelopes.
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
//! This module builds passphrase-KDF envelopes for recovery and secret
//! storage. MLS history snapshots use `secret_storage_key` or
//! `recovery_public_key` envelopes in the application runtime and must not use
//! this passphrase builder.
//!
//! ```no_run
//! use arkret_core::BackupClass;
//! use arkret_crypto::backup::{build_key_backup_envelope, derive_vault_kek};
//!
//! let kek = derive_vault_kek(b"correct horse battery staple")?;
//! let envelope = build_key_backup_envelope(
//!     "ak:backup:01964137-0000-7000-8000-000000000000".parse()?,
//!     "did:webvh:alice.example".parse()?,
//!     None,
//!     BackupClass::SecretStorage,
//!     "kb_1",
//!     &kek,
//!     br#"{"recovery":"..."}"#,
//!     &[("recovery_secret", None)],
//! )?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use arkret_canonical::canonical::{
    canonical_json_bytes, canonical_sha256, format_timestamp_canonical, sha256_digest, sha256_hex,
};
use arkret_core::{
    BackupClass, BackupId, DeviceId, Did, Hash, KeyBackup, KeyBackupAead, KeyBackupContentItem,
    KeyBackupDomainSeparation, KeyBackupDomainSeparationAad, KeyBackupEncryption,
    KeyBackupFrontierRef, KeyBackupKdf, KeyBackupRecipientMethod, base64url_decode,
    base64url_encode,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chrono::{SubsecRound, Utc};
use getrandom::fill;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::KeyBackupError;

type HmacSha256 = Hmac<Sha256>;

/// Module-local result alias: every public `backup` API returns the typed
/// [`KeyBackupError`] (SDK-HYG-01) rather than `anyhow::Error`.
type Result<T> = std::result::Result<T, KeyBackupError>;

/// AEAD profile id for the XChaCha20-Poly1305 envelope produced by this
/// module (key-management.md §7.2). Binds nonce length (24), tag length
/// (16) and the AAD construction below.
pub const VAULT_AEAD_PROFILE: &str = "ak.aead.xchacha20_poly1305.v1";

/// `ak.schema.key_backup.v1` schema id, bound into the AEAD AAD so a
/// ciphertext cannot be replayed under a different schema (§7.1).
pub const VAULT_SCHEMA_ID: &str = "ak.schema.key_backup.v1";

/// Length of the producer-generated `aead.nonce_salt` in bytes. Spec
/// requires at least 128 bits; we use 16 bytes (128 bits).
pub const VAULT_NONCE_SALT_LEN: usize = 16;

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

/// Outcome of [`derive_vault_kek`]: the **root unlock key** plus the
/// parameters that generated it. The parameters round-trip into the
/// backup envelope so any future device can reproduce the KDF given just
/// the passphrase.
///
/// `key` is the bare Argon2id output — the *root* key. Per
/// key-management.md §7.1 it MUST NOT be used directly as an AEAD key;
/// AEAD/nonce/commitment subkeys are derived from it via HKDF with
/// domain-separated `info` strings (see [`derive_aead_subkey`] etc.).
///
/// The struct zeroizes `key` on drop and renders its `Debug` with the
/// key redacted so it never leaks into logs or backtraces.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct VaultKek {
    pub key: [u8; VAULT_KDF_OUTPUT_LEN],
    #[zeroize(skip)]
    pub salt: [u8; VAULT_SALT_LEN],
    #[zeroize(skip)]
    pub m_kib: u32,
    #[zeroize(skip)]
    pub t: u32,
    #[zeroize(skip)]
    pub p: u32,
}

impl std::fmt::Debug for VaultKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKek")
            .field("key", &"<redacted>")
            .field("salt", &self.salt)
            .field("m_kib", &self.m_kib)
            .field("t", &self.t)
            .field("p", &self.p)
            .finish()
    }
}

/// Outcome of [`encrypt_vault`]: the ciphertext (Poly1305 tag appended
/// by the AEAD), the deterministic nonce + producer salt, and the
/// base64url-encoded views the caller hands straight to
/// [`build_key_backup_envelope`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultCiphertext {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; VAULT_NONCE_LEN],
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub nonce_salt_b64: String,
    pub salt_b64: String,
    pub digest_sha256: String,
}

/// Stretch a user passphrase into a 32-byte key under Argon2id with a
/// fresh random salt. Returns the KEK alongside the salt so the caller
/// can store the salt as backup metadata.
pub fn derive_vault_kek(passphrase: &[u8]) -> Result<VaultKek> {
    let mut salt = [0u8; VAULT_SALT_LEN];
    fill(&mut salt).map_err(|err| KeyBackupError::Rng(format!("salt rng: {err}")))?;
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
        .map_err(|err| KeyBackupError::Kdf(format!("argon2 params: {err}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; VAULT_KDF_OUTPUT_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|err| KeyBackupError::Kdf(format!("argon2 hash: {err}")))?;
    Ok(VaultKek {
        key,
        salt: *salt,
        m_kib: VAULT_ARGON2_M_KIB,
        t: VAULT_ARGON2_T,
        p: VAULT_ARGON2_P,
    })
}

/// Envelope-identity binding for a `passphrase_kdf` key backup. The same
/// values are committed into both the AEAD AAD (§7.1) and the
/// deterministic nonce derivation transcript (§7.2), so a ciphertext
/// cannot be replayed under a different domain, subject, schema or
/// content type.
///
/// `created_at` is truncated to whole seconds so it round-trips byte-for-byte
/// through the envelope's canonical timestamp (`YYYY-MM-DDTHH:MM:SSZ`); a
/// verifier reconstructs the same transcript from the persisted envelope.
#[derive(Clone, Debug)]
pub struct VaultBinding {
    pub backup_id: BackupId,
    pub actor_id: Did,
    pub device_id: Option<DeviceId>,
    pub backup_class: BackupClass,
    pub backup_version: String,
    pub created_at: chrono::DateTime<Utc>,
    /// Item types carried by this envelope (`contents[].item_type`),
    /// bound into the AAD so a ciphertext cannot be relabelled.
    pub item_types: Vec<String>,
}

impl VaultBinding {
    /// The wire token for this envelope's `backup_class` (the snake_case
    /// value used in the AAD / nonce transcript and the envelope itself).
    fn backup_class_wire(&self) -> &'static str {
        match self.backup_class {
            BackupClass::DidRecovery => "did_recovery",
            BackupClass::SecretStorage => "secret_storage",
            BackupClass::MlsHistory => "mls_history",
        }
    }

    /// HKDF subkey derived from the root unlock key with a
    /// domain-separated `info`. Per §7.1 each `backup_class` derives in
    /// its own domain so compromising one domain cannot unlock another.
    /// Public so conformance KAT runners can pin the intermediate bytes
    /// (`key-backup-hardening-fixture.json` passphrase_kdf_kat case).
    pub fn subkey(&self, root: &[u8; VAULT_KDF_OUTPUT_LEN], subdomain: &str) -> [u8; 32] {
        derive_subkey(root, self.backup_class.hkdf_info(subdomain).as_bytes())
    }

    /// Canonical-JSON bytes of the §7.2 deterministic-nonce transcript.
    /// Shared by [`Self::derive_nonce`] and conformance vector generation
    /// so the fixture transcript can never drift from the code path.
    pub fn nonce_transcript_canonical_bytes(&self, nonce_salt_b64: &str) -> Result<Vec<u8>> {
        // Transcript field names follow the authoritative normative code
        // block in key-management.md §7.2 (L566-582): the AEAD fields are
        // the *flat* keys `aead` (= aead.name), `aead_profile` and
        // `nonce_salt`, NOT dotted `aead.name`. canonical_json re-sorts by
        // key so declaration order is irrelevant.
        let transcript = json!({
            "backup_id": self.backup_id.as_str(),
            "actor_id": self.actor_id.as_str(),
            "device_id": self.device_id.as_ref().map(|d| d.as_str()),
            "backup_class": self.backup_class_wire(),
            "backup_version": self.backup_version,
            "created_at": format_timestamp_canonical(self.created_at.trunc_subsecs(0)),
            "aead": "xchacha20_poly1305",
            "aead_profile": VAULT_AEAD_PROFILE,
            "nonce_salt": nonce_salt_b64,
        });
        canonical_json_bytes(&transcript)
            .map_err(|err| KeyBackupError::Canonical(format!("nonce transcript: {err}")))
    }

    /// Deterministic AEAD nonce per §7.2:
    /// `HMAC-SHA256(HKDF(root, "...aead-nonce-v1"), canonical_json(transcript))[0:24]`.
    /// The transcript field order matches the authoritative
    /// `key-backup.schema.json` `aead.nonce` description.
    pub fn derive_nonce(
        &self,
        root: &[u8; VAULT_KDF_OUTPUT_LEN],
        nonce_salt_b64: &str,
    ) -> Result<[u8; VAULT_NONCE_LEN]> {
        let nonce_key = derive_subkey(root, b"arkret-key-backup-aead-nonce-v1");
        let transcript_bytes = self.nonce_transcript_canonical_bytes(nonce_salt_b64)?;
        let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&nonce_key)
            .map_err(|err| KeyBackupError::Kdf(format!("nonce hmac key: {err}")))?;
        mac.update(&transcript_bytes);
        let tag = mac.finalize().into_bytes();
        let mut nonce = [0u8; VAULT_NONCE_LEN];
        nonce.copy_from_slice(&tag[..VAULT_NONCE_LEN]);
        Ok(nonce)
    }

    /// AEAD AAD per §7.1: canonical JSON over the domain/subject/schema
    /// binding fields. Bound to the ciphertext so envelope metadata
    /// cannot be tampered with post-encryption. Public for conformance
    /// KAT verification.
    pub fn aad(&self) -> Result<Vec<u8>> {
        let aad = json!({
            "actor_id": self.actor_id.as_str(),
            "device_id": self.device_id.as_ref().map(|d| d.as_str()),
            "backup_class": self.backup_class_wire(),
            "backup_version": self.backup_version,
            "item_types": self.item_types,
            "created_at": format_timestamp_canonical(self.created_at.trunc_subsecs(0)),
            "schema": VAULT_SCHEMA_ID,
        });
        canonical_json_bytes(&aad)
            .map_err(|err| KeyBackupError::Canonical(format!("aead aad: {err}")))
    }
}

/// HKDF-SHA256 subkey derivation with an explicit `info` and no salt
/// (the root key already carries full entropy from Argon2id). Public so
/// conformance KAT runners can pin the intermediate subkey bytes.
pub fn derive_subkey(root: &[u8; VAULT_KDF_OUTPUT_LEN], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut out = [0u8; 32];
    // `expand` only fails when the output length exceeds 255*HashLen; 32
    // bytes is always valid, so this never errors.
    hk.expand(info, &mut out).expect("hkdf expand 32 bytes");
    out
}

/// Encrypt vault plaintext for a specific envelope binding.
///
/// Derives the per-domain AEAD subkey via HKDF (never reuses the bare
/// Argon2id output as the AEAD key, §7.1), generates the producer
/// `nonce_salt`, derives the deterministic nonce (§7.2), and binds the
/// envelope identity as AEAD AAD (§7.1).
pub fn encrypt_vault(
    kek: &VaultKek,
    binding: &VaultBinding,
    plaintext: &[u8],
) -> Result<VaultCiphertext> {
    let mut nonce_salt = [0u8; VAULT_NONCE_SALT_LEN];
    fill(&mut nonce_salt).map_err(|err| KeyBackupError::Rng(format!("nonce_salt rng: {err}")))?;
    encrypt_vault_with_nonce_salt(kek, binding, plaintext, &nonce_salt)
}

/// Variant of [`encrypt_vault`] with a caller-supplied producer
/// `nonce_salt`. Production callers MUST use [`encrypt_vault`] (fresh
/// random salt); this entry point exists so deterministic conformance
/// KAT vectors (`ak.vector.key_backup.passphrase_kdf_kat.v1`) can be
/// generated and re-verified byte-for-byte from the same code path.
pub fn encrypt_vault_with_nonce_salt(
    kek: &VaultKek,
    binding: &VaultBinding,
    plaintext: &[u8],
    nonce_salt: &[u8; VAULT_NONCE_SALT_LEN],
) -> Result<VaultCiphertext> {
    let nonce_salt_b64 = base64url_encode(nonce_salt);

    let mut aead_key = binding.subkey(&kek.key, "aead");
    let cipher = XChaCha20Poly1305::new((&aead_key).into());
    let nonce_bytes = binding.derive_nonce(&kek.key, &nonce_salt_b64)?;
    let nonce = XNonce::from(nonce_bytes);
    let aad = binding.aad()?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|err| KeyBackupError::Aead(format!("xchacha20poly1305 encrypt: {err}")))?;
    aead_key.zeroize();
    Ok(VaultCiphertext {
        ciphertext_b64: base64url_encode(&ciphertext),
        nonce_b64: base64url_encode(nonce_bytes),
        nonce_salt_b64,
        salt_b64: base64url_encode(kek.salt),
        digest_sha256: sha256_digest(&ciphertext),
        ciphertext,
        nonce: nonce_bytes,
    })
}

/// Decrypt a previously produced vault ciphertext.
///
/// Re-derives the root key from the passphrase + salt, derives the
/// per-domain AEAD subkey, recomputes the deterministic nonce and
/// rejects a mismatch against the envelope's `nonce`/`nonce_salt`
/// (§7.2), then AEAD-decrypts with the same binding as AAD. Returns an
/// error if the passphrase is wrong (AEAD tag mismatch) or any input is
/// malformed.
///
/// The recovered plaintext is key material (§7.5: destroy reconstruction
/// context immediately), so it is returned wrapped in [`Zeroizing`] and
/// erased from memory on drop.
pub fn decrypt_vault(
    passphrase: &[u8],
    binding: &VaultBinding,
    salt_b64: &str,
    nonce_b64: &str,
    nonce_salt_b64: &str,
    ciphertext_b64: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let salt_bytes = base64url_decode(salt_b64.trim_end_matches('='))
        .map_err(|err| KeyBackupError::Encoding(format!("salt base64: {err}")))?;
    let salt: [u8; VAULT_SALT_LEN] = salt_bytes
        .try_into()
        .map_err(|_| KeyBackupError::Encoding(format!("salt must be {VAULT_SALT_LEN} bytes")))?;
    let nonce_bytes = base64url_decode(nonce_b64.trim_end_matches('='))
        .map_err(|err| KeyBackupError::Encoding(format!("nonce base64: {err}")))?;
    let nonce_array: [u8; VAULT_NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| KeyBackupError::Encoding(format!("nonce must be {VAULT_NONCE_LEN} bytes")))?;
    let ciphertext = base64url_decode(ciphertext_b64.trim_end_matches('='))
        .map_err(|err| KeyBackupError::Encoding(format!("ciphertext base64: {err}")))?;
    let kek = derive_vault_kek_with_salt(passphrase, &salt)?;

    // §7.2: receiver MUST recompute the nonce and reject a mismatch.
    let expected_nonce = binding.derive_nonce(&kek.key, nonce_salt_b64)?;
    if expected_nonce != nonce_array {
        return Err(KeyBackupError::Aead(
            "vault decrypt failed: nonce derivation mismatch (schema_violation)".to_owned(),
        ));
    }

    let mut aead_key = binding.subkey(&kek.key, "aead");
    let cipher = XChaCha20Poly1305::new((&aead_key).into());
    let aad = binding.aad()?;
    let nonce = XNonce::from(nonce_array);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext.as_slice(),
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| {
            KeyBackupError::Aead(
                "vault decrypt failed: wrong passphrase or corrupt ciphertext".to_owned(),
            )
        });
    aead_key.zeroize();
    plaintext
}

/// Generate a fresh Recovery Key as a human-readable string of
/// Crockford-base32-style groups (alphabet `0-9 + A-Z` minus `I/L/O/U`
/// to avoid lookalikes). 32 random bytes (256 bits) are encoded as 50
/// characters in five-character groups separated by `-`.
pub fn generate_recovery_key() -> Result<String> {
    let mut bytes = [0u8; RECOVERY_KEY_BYTES];
    fill(&mut bytes).map_err(|err| KeyBackupError::Rng(format!("recovery key rng: {err}")))?;
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
    sha256_digest(recovery_key.as_bytes())
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

/// Build a typed `ak.schema.key_backup.v1` envelope, encrypting
/// `plaintext` against the envelope's own identity binding.
///
/// `contents` is `(item_type, optional secret_id)`. The AEAD key, nonce
/// and key commitment are all HKDF-derived from the root unlock key with
/// domain-separated `info` strings, the AEAD AAD binds the envelope
/// identity, and the nonce is deterministically derived with a fresh
/// producer `nonce_salt` — honouring key-management.md §7.1/§7.2.
#[allow(clippy::too_many_arguments)]
pub fn build_key_backup_envelope(
    backup_id: BackupId,
    actor_id: Did,
    device_id: Option<DeviceId>,
    backup_class: BackupClass,
    backup_version: &str,
    kek: &VaultKek,
    plaintext: &[u8],
    contents: &[(&str, Option<&str>)],
) -> Result<KeyBackup> {
    if backup_class == BackupClass::MlsHistory {
        return Err(KeyBackupError::InvalidInput(
            "mls_history backups must use secret_storage_key or recovery_public_key envelopes"
                .to_owned(),
        ));
    }
    if !backup_version.starts_with("kb_") {
        return Err(KeyBackupError::InvalidInput(format!(
            "backup_version must match the kb_<id> pattern (got {backup_version:?})"
        )));
    }

    // Truncate to whole seconds so the binding's canonical timestamp
    // round-trips byte-for-byte through the persisted `created_at`.
    let created_at = Utc::now().trunc_subsecs(0);
    let binding = VaultBinding {
        backup_id: backup_id.clone(),
        actor_id: actor_id.clone(),
        device_id: device_id.clone(),
        backup_class,
        backup_version: backup_version.to_owned(),
        created_at,
        item_types: contents
            .iter()
            .map(|(item_type, _)| (*item_type).to_owned())
            .collect(),
    };
    let ciphertext = encrypt_vault(kek, &binding, plaintext)?;

    let kdf_params = json!({
        "memory_kib": kek.m_kib,
        "iterations": kek.t,
        "parallelism": kek.p,
        "hkdf_info": backup_class.hkdf_info("aead"),
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
        aead_profile: Some(VAULT_AEAD_PROFILE.to_owned()),
        nonce_salt: Some(ciphertext.nonce_salt_b64.clone()),
        nonce: Some(ciphertext.nonce_b64.clone()),
        enc: None,
        extra: Default::default(),
    };
    let encryption = KeyBackupEncryption {
        recipient_method: KeyBackupRecipientMethod::PassphraseKdf,
        recipient_key_ref: None,
        kdf: Some(kdf),
        aead,
        key_commitment: Some(format!(
            "sha256:{}",
            sha256_hex(&commitment_digest(&kek.key, backup_class))
        )),
        // Symmetric passphrase_kdf path: the HPKE-suite selector applies only to
        // recipient_method=recovery_public_key, so it is omitted here.
        hpke_suite: None,
        extra: Default::default(),
    };
    let domain_separation = KeyBackupDomainSeparation {
        hkdf_info: backup_class.hkdf_info("aead"),
        subdomain: "aead".to_owned(),
        aead_aad: KeyBackupDomainSeparationAad {
            schema: VAULT_SCHEMA_ID.to_owned(),
            actor_id: actor_id.clone(),
            device_id: device_id
                .as_ref()
                .map(|device_id| device_id.as_str().to_owned())
                .unwrap_or_default(),
            backup_class,
            backup_version: backup_version.to_owned(),
            created_at,
            item_types: binding.item_types.clone(),
            recipient_method: None,
            recipient_key_ref: None,
            extra: Default::default(),
        },
        extra: Default::default(),
    };
    let contents: Vec<KeyBackupContentItem> = contents
        .iter()
        .map(|(item_type, secret_id)| KeyBackupContentItem {
            item_type: (*item_type).to_owned(),
            realm_id: None,
            mls_group_id: None,
            epoch: None,
            first_event_id: None,
            last_event_id: None,
            secret_id: secret_id.map(|s| s.to_owned()),
            secret_version: None,
            extra: Default::default(),
        })
        .collect();
    // Per `key-backup.schema.json` (required: series_id, series_seq) every
    // envelope MUST carry `series_id` + `series_seq`. This helper produces a
    // genesis envelope by minting a fresh series_id and seq=0; successors are
    // built with `build_key_backup_successor_envelope`.
    let series_id =
        arkret_core::BackupSeriesId::new(arkret_core::new_prefixed_uuid7("ak:backup_series:"))
            .map_err(|err| {
                KeyBackupError::InvalidInput(format!("failed to mint backup_series id: {err}"))
            })?;
    Ok(KeyBackup {
        backup_id,
        actor_id,
        device_id,
        backup_class,
        mixed_secret_storage: false,
        backup_version: backup_version.to_owned(),
        created_at,
        updated_at: None,
        expires_at: None,
        encryption,
        domain_separation,
        contents,
        ciphertext: ciphertext.ciphertext_b64.clone(),
        ciphertext_digest: ciphertext.digest_sha256.clone(),
        plaintext_commitment: None,
        auth_data: None,
        retention: None,
        series_id,
        series_seq: 0,
        supersedes: None,
        supersedes_digest: None,
        frontier_ref: None,
        recovery_policy_ref: None,
        extra: Default::default(),
    })
}

/// Build a successor envelope in an existing key-backup series.
///
/// The successor inherits actor/device/class from `predecessor`, increments
/// `series_seq`, and binds the predecessor by both `backup_id` and
/// canonical predecessor-envelope digest. Callers supply the new plaintext and
/// the current originating-key frontier reference.
#[allow(clippy::too_many_arguments)]
pub fn build_key_backup_successor_envelope(
    backup_id: BackupId,
    predecessor: &KeyBackup,
    backup_version: &str,
    kek: &VaultKek,
    plaintext: &[u8],
    contents: &[(&str, Option<&str>)],
    frontier_ref: impl Into<String>,
) -> Result<KeyBackup> {
    if backup_id == predecessor.backup_id {
        return Err(KeyBackupError::InvalidInput(
            "successor backup_id must differ from predecessor".to_owned(),
        ));
    }
    let frontier_digest = frontier_ref.into();
    if frontier_digest.trim().is_empty() {
        return Err(KeyBackupError::InvalidInput(
            "successor frontier_ref must not be empty".to_owned(),
        ));
    }
    let frontier_digest = Hash::new(frontier_digest).map_err(|err| {
        KeyBackupError::InvalidInput(format!(
            "successor frontier_ref.frontier_digest invalid: {err}"
        ))
    })?;
    let mut successor = build_key_backup_envelope(
        backup_id,
        predecessor.actor_id.clone(),
        predecessor.device_id.clone(),
        predecessor.backup_class,
        backup_version,
        kek,
        plaintext,
        contents,
    )?;
    successor.series_id = predecessor.series_id.clone();
    successor.series_seq = predecessor
        .series_seq
        .checked_add(1)
        .ok_or_else(|| KeyBackupError::InvalidInput("successor series_seq overflow".to_owned()))?;
    successor.supersedes = Some(predecessor.backup_id.clone());
    successor.supersedes_digest = Some(key_backup_supersedes_digest(predecessor)?);
    successor.frontier_ref = Some(KeyBackupFrontierRef {
        frontier_digest,
        seal_ref: None,
        ssk_generation: None,
    });
    Ok(successor)
}

fn key_backup_supersedes_digest(predecessor: &KeyBackup) -> Result<String> {
    let mut canonical = serde_json::to_value(predecessor).map_err(|err| {
        KeyBackupError::Canonical(format!(
            "serialize predecessor key backup for supersedes_digest: {err}"
        ))
    })?;
    if let Some(auth_data) = canonical
        .get_mut("auth_data")
        .and_then(serde_json::Value::as_object_mut)
    {
        auth_data.remove("signature");
    }
    canonical_sha256(&canonical).map_err(|err| {
        KeyBackupError::Canonical(format!(
            "hash predecessor key backup for supersedes_digest: {err}"
        ))
    })
}

/// Key commitment used by the AEAD envelope (spec §7.2):
/// `SHA256(HKDF(root, info))`. The `info` is domain-separated per
/// `backup_class` so commitments cannot be reused across domains (§7.1: a
/// derived key, commitment key or wrap key for one domain must not be used
/// directly in another domain). Public for conformance KAT verification.
pub fn commitment_digest(root: &[u8; VAULT_KDF_OUTPUT_LEN], backup_class: BackupClass) -> Vec<u8> {
    let mut commitment_key = derive_subkey(root, backup_class.hkdf_info("commitment").as_bytes());
    let digest = arkret_canonical::canonical::sha256_bytes(&commitment_key).to_vec();
    commitment_key.zeroize();
    digest
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

    fn test_binding(class: BackupClass, item: &str) -> VaultBinding {
        VaultBinding {
            backup_id: "ak:backup:01964137-0000-7000-8000-000000000000"
                .parse()
                .unwrap(),
            actor_id: "did:webvh:alice.example".parse().unwrap(),
            device_id: None,
            backup_class: class,
            backup_version: "kb_1".to_owned(),
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            item_types: vec![item.to_owned()],
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let kek = derive_vault_kek_with_salt(b"open sesame", &[7u8; VAULT_SALT_LEN]).unwrap();
        let plaintext = br#"{"device_sk":"opaque"}"#;
        let binding = test_binding(BackupClass::SecretStorage, "recovery_secret");
        let ct = encrypt_vault(&kek, &binding, plaintext).unwrap();
        let recovered = decrypt_vault(
            b"open sesame",
            &binding,
            &ct.salt_b64,
            &ct.nonce_b64,
            &ct.nonce_salt_b64,
            &ct.ciphertext_b64,
        )
        .unwrap();
        assert_eq!(*recovered, plaintext);
    }

    #[test]
    fn decrypt_rejects_wrong_passphrase() {
        let kek = derive_vault_kek_with_salt(b"first", &[3u8; VAULT_SALT_LEN]).unwrap();
        let binding = test_binding(BackupClass::SecretStorage, "recovery_secret");
        let ct = encrypt_vault(&kek, &binding, b"payload").unwrap();
        let err = decrypt_vault(
            b"second",
            &binding,
            &ct.salt_b64,
            &ct.nonce_b64,
            &ct.nonce_salt_b64,
            &ct.ciphertext_b64,
        )
        .unwrap_err();
        assert!(err.to_string().contains("vault decrypt failed"));
    }

    #[test]
    fn decrypt_rejects_tampered_binding() {
        // §7.1: AAD binds the envelope identity, so changing the
        // backup_class (cross-domain replay) MUST fail AEAD.
        let kek = derive_vault_kek_with_salt(b"pp", &[9u8; VAULT_SALT_LEN]).unwrap();
        let binding = test_binding(BackupClass::SecretStorage, "recovery_secret");
        let ct = encrypt_vault(&kek, &binding, b"secret").unwrap();
        let mut tampered = binding.clone();
        tampered.backup_class = BackupClass::DidRecovery;
        let err = decrypt_vault(
            b"pp",
            &tampered,
            &ct.salt_b64,
            &ct.nonce_b64,
            &ct.nonce_salt_b64,
            &ct.ciphertext_b64,
        )
        .unwrap_err();
        assert!(err.to_string().contains("vault decrypt failed"));
    }

    #[test]
    fn decrypt_rejects_nonce_mismatch() {
        // §7.2: receiver recomputes the nonce and rejects a mismatch.
        let kek = derive_vault_kek_with_salt(b"pp", &[4u8; VAULT_SALT_LEN]).unwrap();
        let binding = test_binding(BackupClass::SecretStorage, "recovery_secret");
        let ct = encrypt_vault(&kek, &binding, b"secret").unwrap();
        let bad_nonce = base64url_encode([0u8; VAULT_NONCE_LEN]);
        let err = decrypt_vault(
            b"pp",
            &binding,
            &ct.salt_b64,
            &bad_nonce,
            &ct.nonce_salt_b64,
            &ct.ciphertext_b64,
        )
        .unwrap_err();
        assert!(err.to_string().contains("nonce derivation mismatch"));
    }

    #[test]
    fn nonce_is_deterministic_for_fixed_transcript() {
        let kek = derive_vault_kek_with_salt(b"pp", &[1u8; VAULT_SALT_LEN]).unwrap();
        let binding = test_binding(BackupClass::SecretStorage, "recovery_secret");
        let salt_b64 = base64url_encode([2u8; VAULT_NONCE_SALT_LEN]);
        let a = binding.derive_nonce(&kek.key, &salt_b64).unwrap();
        let b = binding.derive_nonce(&kek.key, &salt_b64).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn aead_subkey_differs_from_root_and_across_domains() {
        let kek = derive_vault_kek_with_salt(b"pp", &[1u8; VAULT_SALT_LEN]).unwrap();
        let ss = test_binding(BackupClass::SecretStorage, "x").subkey(&kek.key, "aead");
        let dr = test_binding(BackupClass::DidRecovery, "x").subkey(&kek.key, "aead");
        assert_ne!(ss, kek.key, "aead key must not reuse bare argon2 output");
        assert_ne!(ss, dr, "domains must derive distinct aead keys");
    }

    #[test]
    fn commitment_is_domain_isolated() {
        let kek = derive_vault_kek_with_salt(b"pp", &[1u8; VAULT_SALT_LEN]).unwrap();
        let ss = commitment_digest(&kek.key, BackupClass::SecretStorage);
        let dr = commitment_digest(&kek.key, BackupClass::DidRecovery);
        assert_ne!(ss, dr, "commitment must differ across backup classes");
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
        assert!(
            fp.chars()
                .skip("sha256:".len())
                .all(|c| c.is_ascii_hexdigit())
        );
        assert_eq!(
            fp,
            fingerprint_recovery_key("EAGLE-HARP-SUNDAY-ROOK-9F2C-Q1A0")
        );
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
        assert_eq!(
            estimate_passphrase_strength("Correct horse battery staple 9!"),
            5
        );
    }

    #[test]
    fn envelope_carries_kdf_aead_and_commitment() {
        let kek = derive_vault_kek_with_salt(b"pp", &[5u8; VAULT_SALT_LEN]).unwrap();
        let envelope = build_key_backup_envelope(
            "ak:backup:01964137-0000-7000-8000-000000000000"
                .parse()
                .unwrap(),
            "did:webvh:alice.example".parse().unwrap(),
            None,
            BackupClass::SecretStorage,
            "kb_1",
            &kek,
            b"hello",
            &[("recovery_secret", Some("vault_payload"))],
        )
        .unwrap();
        assert_eq!(envelope.backup_class, BackupClass::SecretStorage);
        assert_eq!(envelope.encryption.aead.name, "xchacha20_poly1305");
        assert_eq!(
            envelope.encryption.aead.aead_profile.as_deref(),
            Some("ak.aead.xchacha20_poly1305.v1")
        );
        assert!(envelope.encryption.aead.nonce_salt.is_some());
        assert!(envelope.encryption.aead.nonce.is_some());
        assert!(envelope.encryption.kdf.is_some());
        let kdf = envelope.encryption.kdf.as_ref().unwrap();
        assert_eq!(kdf.name, "argon2id");
        assert_eq!(kdf.params["memory_kib"], VAULT_ARGON2_M_KIB);
        assert_eq!(kdf.params["iterations"], VAULT_ARGON2_T);
        assert_eq!(kdf.params["parallelism"], VAULT_ARGON2_P);
        assert_eq!(
            kdf.params["hkdf_info"],
            "arkret-key-backup/secret_storage/aead/v1"
        );
        assert!(envelope.encryption.key_commitment.is_some());
        assert_eq!(envelope.contents.len(), 1);
        assert_eq!(envelope.contents[0].item_type, "recovery_secret");
    }

    #[test]
    fn full_envelope_round_trips_through_decrypt() {
        // Reconstruct the binding from the persisted envelope, exactly as
        // a verifier would, and confirm AEAD/nonce verification succeeds.
        let kek = derive_vault_kek_with_salt(b"sesame", &[6u8; VAULT_SALT_LEN]).unwrap();
        let plaintext = br#"{"self_signing_key":"opaque"}"#;
        let envelope = build_key_backup_envelope(
            "ak:backup:01964137-0000-7000-8000-000000000003"
                .parse()
                .unwrap(),
            "did:webvh:bob.example".parse().unwrap(),
            None,
            BackupClass::SecretStorage,
            "kb_1",
            &kek,
            plaintext,
            &[("self_signing_key", Some("self_signing_key"))],
        )
        .unwrap();
        let aead = &envelope.encryption.aead;
        let binding = VaultBinding {
            backup_id: envelope.backup_id.clone(),
            actor_id: envelope.actor_id.clone(),
            device_id: envelope.device_id.clone(),
            backup_class: envelope.backup_class,
            backup_version: envelope.backup_version.clone(),
            created_at: envelope.created_at,
            item_types: envelope
                .contents
                .iter()
                .map(|c| c.item_type.clone())
                .collect(),
        };
        let recovered = decrypt_vault(
            b"sesame",
            &binding,
            envelope.encryption.kdf.as_ref().unwrap().salt.as_str(),
            aead.nonce.as_deref().unwrap(),
            aead.nonce_salt.as_deref().unwrap(),
            envelope.ciphertext.as_str(),
        )
        .unwrap();
        assert_eq!(*recovered, plaintext);
    }

    #[test]
    fn successor_envelope_binds_predecessor_and_frontier() {
        let kek = derive_vault_kek_with_salt(b"pp", &[5u8; VAULT_SALT_LEN]).unwrap();
        let genesis = build_key_backup_envelope(
            "ak:backup:01964137-0000-7000-8000-000000000001"
                .parse()
                .unwrap(),
            "did:webvh:alice.example".parse().unwrap(),
            None,
            BackupClass::SecretStorage,
            "kb_1",
            &kek,
            b"genesis",
            &[("recovery_secret", Some("genesis"))],
        )
        .unwrap();
        let successor = build_key_backup_successor_envelope(
            "ak:backup:01964137-0000-7000-8000-000000000002"
                .parse()
                .unwrap(),
            &genesis,
            "kb_2",
            &kek,
            b"successor",
            &[("recovery_secret", Some("successor"))],
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        assert_eq!(successor.series_id, genesis.series_id);
        assert_eq!(successor.series_seq, genesis.series_seq + 1);
        assert_eq!(successor.supersedes.as_ref(), Some(&genesis.backup_id));
        let expected_supersedes_digest = key_backup_supersedes_digest(&genesis).unwrap();
        assert_eq!(
            successor.supersedes_digest.as_deref(),
            Some(expected_supersedes_digest.as_str())
        );
        assert_ne!(
            successor.supersedes_digest.as_deref(),
            Some(genesis.ciphertext_digest.as_str())
        );
        assert_eq!(
            successor
                .frontier_ref
                .as_ref()
                .map(|frontier| frontier.frontier_digest.as_str()),
            Some("sha256:2222222222222222222222222222222222222222222222222222222222222222")
        );
    }

    #[test]
    fn envelope_rejects_bad_version_tag() {
        let kek = derive_vault_kek_with_salt(b"pp", &[5u8; VAULT_SALT_LEN]).unwrap();
        let err = build_key_backup_envelope(
            "ak:backup:01964137-0000-7000-8000-000000000000"
                .parse()
                .unwrap(),
            "did:webvh:alice.example".parse().unwrap(),
            None,
            BackupClass::SecretStorage,
            "1",
            &kek,
            b"x",
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains("backup_version"));
    }

    #[test]
    fn passphrase_envelope_builder_rejects_mls_history() {
        let kek = derive_vault_kek_with_salt(b"pp", &[5u8; VAULT_SALT_LEN]).unwrap();
        let err = build_key_backup_envelope(
            "ak:backup:01964137-0000-7000-8000-000000000000"
                .parse()
                .unwrap(),
            "did:webvh:alice.example".parse().unwrap(),
            None,
            BackupClass::MlsHistory,
            "kb_1",
            &kek,
            b"x",
            &[("mls_group_state", Some("snapshot"))],
        )
        .unwrap_err();
        assert!(err.to_string().contains("secret_storage_key"));
    }
}
