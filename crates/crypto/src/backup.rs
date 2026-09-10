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
//! use arkret_crypto::backup::{build_key_backup_envelope, derive_vault_kek};
//! use arkret_models_crypto::{BackupKind, SecretStorageItemKind, SecretStorageSecret};
//! use arkret_wire::{AccountId, ActorId};
//!
//! let kek = derive_vault_kek(b"correct horse battery staple")?;
//! let envelope = build_key_backup_envelope(
//!     "ak:backup:01964137-0000-7000-8000-000000000000".parse()?,
//!     ActorId::account(AccountId::new(
//!         "ak:did_core:webvh:z6mkfixture".parse()?,
//!         "ak:did_core:web:station.example".parse()?,
//!     )),
//!     None,
//!     BackupKind::SecretStorage,
//!     "kb_1",
//!     "recovery_vault",
//!     &kek,
//!     vec![SecretStorageSecret {
//!         item_kind: SecretStorageItemKind::PrivateAccountState,
//!         secret_id: "account-state".to_owned(),
//!         secret_b64u: "c2VjcmV0".to_owned(),
//!         secret_generation: None,
//!         extra: Default::default(),
//!     }],
//! )?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use arkret_canonical::canonical::{
    canonical_json_bytes, canonical_sha256, format_timestamp_canonical, sha256_digest, sha256_hex,
};
use arkret_models_crypto::key_backup::{
    BackupKind, KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupContentIndex,
    KeyBackupDomainSeparation, KeyBackupEncryption, KeyBackupFrontierRef, KeyBackupKdf,
    KeyBackupKdfName, KeyBackupKdfParams, KeyBackupRecipientMethod,
};
use arkret_models_crypto::{
    KeyBackupKeybag, KeyBackupPlaintext, SecretStorageContentIndex, SecretStorageSecret,
};
use arkret_wire::{
    AEAD_PROFILE_XCHACHA20_POLY1305_V1, ActorId, BackupId, Base64UrlString, DeviceId, Hash,
    XExtensionMap,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Utc};
use getrandom::fill;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::KeyBackupError;

type HmacSha256 = Hmac<Sha256>;

/// Module-local result alias: every public `backup` API returns the typed
/// [`KeyBackupError`] (SDK-HYG-01) rather than `anyhow::Error`.
type Result<T> = std::result::Result<T, KeyBackupError>;

/// `ak.schema.key_backup.v1` schema id, bound into the AEAD AAD so a
/// ciphertext cannot be replayed under a different schema (§7.1).
pub const VAULT_SCHEMA_ID: &str = arkret_wire::SchemaId::KEY_BACKUP_V1;

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

/// Length of the high-entropy backup-passphrase input in bytes.
///
/// This is not the identity recovery-secret representation from
/// `key-management.md` §3.3. The standard identity recovery path lives in
/// `crate::identity_root` and uses either a 24-word BIP-39 seed or decoded
/// raw secret bytes.
pub const BACKUP_PASSPHRASE_BYTES: usize = 32;

/// Outcome of [`derive_vault_kek`]: the **root unlock key** plus the
/// parameters that generated it. The parameters round-trip into the
/// backup envelope so any future device can reproduce the KDF given just
/// the passphrase.
///
/// `key` is the bare Argon2id output — the *root* key. Per
/// key-management.md §7.1 it MUST NOT be used directly as an AEAD key;
/// AEAD/nonce/commitment subkeys are derived from it via HKDF with
/// domain-separated `info` strings (see `derive_aead_subkey` etc.).
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
    pub subdomain: String,
    pub actor_id: ActorId,
    pub device_id: Option<DeviceId>,
    pub backup_kind: BackupKind,
    pub backup_version: String,
    pub created_at: DateTime<Utc>,
    pub item_kinds: Vec<String>,
    pub recipient_method: KeyBackupRecipientMethod,
    pub recipient_key_ref: Option<String>,
    pub aead_aad_extensions: XExtensionMap,
}

impl VaultBinding {
    /// The wire token for this envelope's `backup_kind` (the snake_case
    /// value used in the AAD / nonce transcript and the envelope itself).
    fn backup_class_wire(&self) -> &'static str {
        match self.backup_kind {
            BackupKind::SecretStorage => "secret_storage",
            BackupKind::MlsHistory => "mls_history",
        }
    }

    /// HKDF subkey derived from the root unlock key with a
    /// domain-separated `info`. Per §7.1 each `backup_kind` derives in
    /// its own domain so compromising one domain cannot unlock another.
    /// Public so conformance KAT runners can pin the intermediate bytes
    /// (`key-backup-hardening-fixture.json` passphrase_kdf_kat case).
    pub fn subkey(&self, root: &[u8; VAULT_KDF_OUTPUT_LEN], subdomain: &str) -> [u8; 32] {
        derive_subkey(root, self.backup_kind.hkdf_info(subdomain).as_bytes())
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
            "actor_id": self.actor_id,
            "device_id": self.device_id.as_ref().map(DeviceId::as_str),
            "backup_kind": self.backup_class_wire(),
            "backup_version": self.backup_version.as_str(),
            "created_at": format_timestamp_canonical(self.created_at),
            "aead": "xchacha20_poly1305",
            "aead_profile": AEAD_PROFILE_XCHACHA20_POLY1305_V1,
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
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&nonce_key)
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
        let mut item_kinds = self.item_kinds.clone();
        item_kinds.sort_unstable();
        item_kinds.dedup();
        let mut aad = Map::new();
        aad.insert(
            "schema".to_owned(),
            Value::String(VAULT_SCHEMA_ID.to_owned()),
        );
        aad.insert(
            "actor_id".to_owned(),
            serde_json::to_value(&self.actor_id)
                .map_err(|error| KeyBackupError::Canonical(error.to_string()))?,
        );
        aad.insert(
            "device_id".to_owned(),
            self.device_id
                .as_ref()
                .map(|device_id| Value::String(device_id.as_str().to_owned()))
                .unwrap_or(Value::Null),
        );
        aad.insert(
            "backup_kind".to_owned(),
            Value::String(self.backup_class_wire().to_owned()),
        );
        aad.insert(
            "backup_version".to_owned(),
            Value::String(self.backup_version.clone()),
        );
        aad.insert(
            "created_at".to_owned(),
            Value::String(format_timestamp_canonical(self.created_at)),
        );
        aad.insert(
            "item_kinds".to_owned(),
            Value::Array(item_kinds.into_iter().map(Value::String).collect()),
        );
        aad.insert(
            "recipient_method".to_owned(),
            serde_json::to_value(self.recipient_method)
                .map_err(|err| KeyBackupError::Canonical(format!("aead aad: {err}")))?,
        );
        if let Some(recipient_key_ref) = &self.recipient_key_ref {
            aad.insert(
                "recipient_key_ref".to_owned(),
                Value::String(recipient_key_ref.clone()),
            );
        }
        for (key, value) in self.aead_aad_extensions.as_map() {
            if aad.insert(key.clone(), value.clone()).is_some() {
                return Err(KeyBackupError::InvalidInput(format!(
                    "key backup AAD extension collides with fixed field {key:?}"
                )));
            }
        }
        canonical_json_bytes(&Value::Object(aad))
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

    let mut aead_key = binding.subkey(&kek.key, &binding.subdomain);
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

    let mut aead_key = binding.subkey(&kek.key, &binding.subdomain);
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

/// Open a typed `passphrase_kdf` key-backup envelope and enforce every
/// producer/receiver invariant owned by the SDK: recipient method, ciphertext
/// digest, key commitment, deterministic nonce, domain binding, and AEAD tag.
fn decrypt_key_backup_envelope_bytes(
    passphrase: &[u8],
    envelope: &KeyBackup,
) -> Result<Zeroizing<Vec<u8>>> {
    if envelope.encryption.recipient_method != KeyBackupRecipientMethod::PassphraseKdf {
        return Err(KeyBackupError::InvalidInput(
            "key backup is not a passphrase_kdf envelope".to_owned(),
        ));
    }
    let domain = &envelope.domain_separation;
    if domain.subdomain.trim().is_empty() {
        return Err(KeyBackupError::InvalidInput(
            "key backup domain separation mismatch".to_owned(),
        ));
    }
    let kdf = envelope.encryption.kdf.as_ref().ok_or_else(|| {
        KeyBackupError::InvalidInput("passphrase_kdf envelope is missing kdf".to_owned())
    })?;
    let salt = kdf.salt.as_str();
    let nonce =
        envelope.encryption.aead.nonce.as_ref().ok_or_else(|| {
            KeyBackupError::InvalidInput("key backup is missing nonce".to_owned())
        })?;
    let nonce_salt = envelope
        .encryption
        .aead
        .nonce_salt
        .as_ref()
        .ok_or_else(|| {
            KeyBackupError::InvalidInput("key backup is missing nonce_salt".to_owned())
        })?;
    let ciphertext = base64url_decode(envelope.ciphertext.trim_end_matches('='))
        .map_err(|error| KeyBackupError::Encoding(format!("ciphertext base64: {error}")))?;
    let actual_digest = sha256_digest(&ciphertext);
    if actual_digest != envelope.ciphertext_digest {
        return Err(KeyBackupError::InvalidInput(
            "key backup ciphertext_digest mismatch".to_owned(),
        ));
    }
    let salt_bytes = base64url_decode(salt.trim_end_matches('='))
        .map_err(|error| KeyBackupError::Encoding(format!("salt base64: {error}")))?;
    let salt_array: [u8; VAULT_SALT_LEN] = salt_bytes
        .try_into()
        .map_err(|_| KeyBackupError::Encoding(format!("salt must be {VAULT_SALT_LEN} bytes")))?;
    let kek = derive_vault_kek_with_salt(passphrase, &salt_array)?;
    let expected_commitment = format!(
        "sha256:{}",
        sha256_hex(commitment_digest(&kek.key, envelope.backup_kind))
    );
    if envelope.encryption.key_commitment.as_deref() != Some(expected_commitment.as_str()) {
        return Err(KeyBackupError::InvalidInput(
            "key backup key_commitment mismatch".to_owned(),
        ));
    }
    decrypt_vault(
        passphrase,
        &vault_binding_from_envelope(envelope),
        salt,
        nonce.as_str(),
        nonce_salt.as_str(),
        &envelope.ciphertext,
    )
}

fn vault_binding_from_envelope(envelope: &KeyBackup) -> VaultBinding {
    VaultBinding {
        backup_id: envelope.backup_id.clone(),
        subdomain: envelope.domain_separation.subdomain.clone(),
        actor_id: envelope.actor_id.clone(),
        device_id: envelope.device_id.clone(),
        backup_kind: envelope.backup_kind,
        backup_version: envelope.backup_version.clone(),
        created_at: envelope.created_at,
        item_kinds: envelope
            .contents
            .iter()
            .map(|item| item.item_kind().to_owned())
            .collect(),
        recipient_method: envelope.encryption.recipient_method,
        recipient_key_ref: envelope.encryption.recipient_key_ref.clone(),
        aead_aad_extensions: envelope.domain_separation.aead_aad_extensions.clone(),
    }
}

/// Derive the sole §7.2 AEAD/HPKE AAD from a typed key-backup envelope.
/// No fixed AAD member is accepted from the wire.
pub fn key_backup_aead_aad(envelope: &KeyBackup) -> Result<Vec<u8>> {
    vault_binding_from_envelope(envelope).aad()
}

/// Open a `passphrase_kdf` envelope as its closed, typed plaintext keybag and
/// verify the decrypted identity and public-metadata binding before returning
/// any secret material to the caller.
pub fn decrypt_key_backup_envelope(
    passphrase: &[u8],
    envelope: &KeyBackup,
) -> Result<KeyBackupPlaintext> {
    let plaintext = decrypt_key_backup_envelope_bytes(passphrase, envelope)?;
    let keybag = serde_json::from_slice::<KeyBackupPlaintext>(&plaintext).map_err(|error| {
        KeyBackupError::Encoding(format!(
            "decrypted key backup is not ak.schema.key_backup_plaintext.v1: {error}"
        ))
    })?;
    keybag
        .validate_for_envelope(envelope)
        .map_err(|error| KeyBackupError::InvalidInput(error.to_string()))?;
    Ok(keybag)
}

/// Render all input bits as Crockford-base32-style groups. A 32-byte input
/// becomes 52 characters (plus separators), with the final partial group
/// zero-padded rather than discarded.
pub fn format_backup_passphrase(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;
    let mut groups: Vec<String> = Vec::with_capacity(11);
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
    if nbits > 0 {
        let idx = ((bits << (5 - nbits)) & 0x1F) as usize;
        current.push(ALPHABET[idx] as char);
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups.join("-")
}

/// Build a typed `ak.schema.key_backup.v1` genesis envelope from closed
/// plaintext items. The SDK constructs the canonical
/// `ak.schema.key_backup_plaintext.v1` keybag and its public `contents` index
/// from the same values, preventing caller-controlled metadata drift.
///
/// The AEAD key, nonce
/// and key commitment are all HKDF-derived from the root unlock key with
/// domain-separated `info` strings, the AEAD AAD binds the envelope
/// identity, and the nonce is deterministically derived with a fresh
/// producer `nonce_salt` — honouring key-management.md §7.1/§7.2.
#[allow(clippy::too_many_arguments)]
pub fn build_key_backup_envelope(
    backup_id: BackupId,
    actor_id: ActorId,
    device_id: Option<DeviceId>,
    backup_kind: BackupKind,
    backup_version: &str,
    subdomain: &str,
    kek: &VaultKek,
    items: Vec<SecretStorageSecret>,
) -> Result<KeyBackup> {
    build_key_backup_envelope_with_extensions(
        backup_id,
        actor_id,
        device_id,
        backup_kind,
        backup_version,
        subdomain,
        XExtensionMap::default(),
        kek,
        items,
    )
}

/// Build a genesis envelope whose derived AEAD AAD includes the supplied
/// closed `x_*` extension map. Fixed AAD members remain SDK-derived and cannot
/// be overridden by callers.
#[allow(clippy::too_many_arguments)]
pub fn build_key_backup_envelope_with_extensions(
    backup_id: BackupId,
    actor_id: ActorId,
    device_id: Option<DeviceId>,
    backup_kind: BackupKind,
    backup_version: &str,
    subdomain: &str,
    aead_aad_extensions: XExtensionMap,
    kek: &VaultKek,
    items: Vec<SecretStorageSecret>,
) -> Result<KeyBackup> {
    let series_id =
        arkret_wire::BackupSeriesId::new(arkret_wire::new_prefixed_uuid7("ak:backup_series:"))
            .map_err(|err| {
                KeyBackupError::InvalidInput(format!("failed to mint backup_series id: {err}"))
            })?;
    build_key_backup_envelope_in_series(
        backup_id,
        actor_id,
        device_id,
        backup_kind,
        backup_version,
        subdomain,
        aead_aad_extensions,
        kek,
        items,
        series_id,
        0,
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_key_backup_envelope_in_series(
    backup_id: BackupId,
    actor_id: ActorId,
    device_id: Option<DeviceId>,
    backup_kind: BackupKind,
    backup_version: &str,
    subdomain: &str,
    aead_aad_extensions: XExtensionMap,
    kek: &VaultKek,
    items: Vec<SecretStorageSecret>,
    series_id: arkret_wire::BackupSeriesId,
    series_seq: u64,
    supersedes_id: Option<BackupId>,
    supersedes_digest: Option<String>,
    frontier_ref: Option<KeyBackupFrontierRef>,
) -> Result<KeyBackup> {
    if backup_kind == BackupKind::MlsHistory {
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
    if subdomain.trim().is_empty() {
        return Err(KeyBackupError::InvalidInput(
            "key backup subdomain must not be empty".to_owned(),
        ));
    }
    if items.is_empty() {
        return Err(KeyBackupError::InvalidInput(
            "key backup plaintext items must not be empty".to_owned(),
        ));
    }
    for item in &items {
        item.validate()
            .map_err(|error| KeyBackupError::InvalidInput(error.to_string()))?;
    }

    let contents = items
        .iter()
        .map(|item| {
            Ok(KeyBackupContentIndex::SecretStorage(
                SecretStorageContentIndex {
                    item_kind: item.item_kind,
                    realm_id: None,
                    from_epoch: None,
                    to_epoch: None,
                    secret_id: Some(item.secret_id.clone()),
                    secret_version: item
                        .secret_version()
                        .map_err(|error| KeyBackupError::InvalidInput(error.to_string()))?,
                    extra: Default::default(),
                },
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let plaintext = KeyBackupPlaintext {
        schema: KeyBackupPlaintext::SCHEMA.to_owned(),
        backup_id: backup_id.clone(),
        series_id: series_id.clone(),
        series_seq,
        keybag: KeyBackupKeybag::SecretStorage { items },
        extra: Default::default(),
    };
    let plaintext_bytes = canonical_json_bytes(&plaintext)
        .map_err(|error| KeyBackupError::Canonical(error.to_string()))?;

    // Truncate to whole seconds so the binding's canonical timestamp
    // round-trips byte-for-byte through the persisted `created_at`.
    let created_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let binding = VaultBinding {
        backup_id: backup_id.clone(),
        subdomain: subdomain.to_owned(),
        actor_id: actor_id.clone(),
        device_id: device_id.clone(),
        backup_kind,
        backup_version: backup_version.to_owned(),
        created_at,
        item_kinds: contents
            .iter()
            .map(|item| item.item_kind().to_owned())
            .collect(),
        recipient_method: KeyBackupRecipientMethod::PassphraseKdf,
        recipient_key_ref: None,
        aead_aad_extensions: aead_aad_extensions.clone(),
    };
    let ciphertext = encrypt_vault(kek, &binding, &plaintext_bytes)?;

    let kdf = KeyBackupKdf {
        name: KeyBackupKdfName::Argon2id,
        salt: Base64UrlString::new(ciphertext.salt_b64.clone())
            .map_err(|error| KeyBackupError::InvalidInput(error.to_owned()))?,
        params: KeyBackupKdfParams {
            memory_kib: Some(u64::from(kek.m_kib)),
            iterations: Some(u64::from(kek.t)),
            parallelism: Some(u64::from(kek.p)),
            digest_algorithm: None,
            extra: Default::default(),
        },
        degraded_profile_reason: None,
        extra: Default::default(),
    };
    let aead = KeyBackupAead {
        name: KeyBackupAeadName::Xchacha20Poly1305,
        aead_profile: Some(AEAD_PROFILE_XCHACHA20_POLY1305_V1.to_owned()),
        nonce_salt: Some(
            Base64UrlString::new(ciphertext.nonce_salt_b64.clone())
                .map_err(|error| KeyBackupError::InvalidInput(error.to_owned()))?,
        ),
        nonce: Some(
            Base64UrlString::new(ciphertext.nonce_b64.clone())
                .map_err(|error| KeyBackupError::InvalidInput(error.to_owned()))?,
        ),
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
            sha256_hex(commitment_digest(&kek.key, backup_kind))
        )),
        // Symmetric passphrase_kdf path: the HPKE-suite selector applies only to
        // recipient_method=recovery_public_key, so it is omitted here.
        hpke_suite: None,
        extra: Default::default(),
    };
    let domain_separation = KeyBackupDomainSeparation {
        subdomain: subdomain.to_owned(),
        aead_aad_extensions,
    };
    let envelope = KeyBackup {
        backup_id,
        actor_id,
        device_id,
        backup_kind,
        mixed_secret_storage: false,
        backup_version: backup_version.to_owned(),
        created_at,
        updated_at: None,
        expires_at: None,
        encryption,
        domain_separation,
        contents,
        ciphertext: ciphertext.ciphertext_b64.clone(),
        ciphertext_digest: ciphertext.digest_sha256,
        plaintext_commitment: None,
        auth_data: None,
        retention: None,
        series_id,
        series_seq,
        supersedes_id,
        supersedes_digest,
        frontier_ref,
        recovery_policy_ref: None,
        extra: Default::default(),
    };
    plaintext
        .validate_for_envelope(&envelope)
        .map_err(|error| KeyBackupError::InvalidInput(error.to_string()))?;
    Ok(envelope)
}

/// Build a successor envelope in an existing key-backup series.
///
/// The successor inherits actor/class/series from `predecessor`, binds the
/// current producing device, increments `series_seq`, and binds the
/// predecessor by both `backup_id` and canonical predecessor-envelope digest.
/// The SDK constructs the successor keybag only after the final
/// device/series/supersedes/frontier metadata is fixed, so encryption can never
/// bind predecessor metadata and mutate it afterward.
#[allow(clippy::too_many_arguments)]
pub fn build_key_backup_successor_envelope(
    backup_id: BackupId,
    predecessor: &KeyBackup,
    device_id: Option<DeviceId>,
    backup_version: &str,
    kek: &VaultKek,
    items: Vec<SecretStorageSecret>,
    frontier_ref: impl Into<String>,
    device_generation_ref: u64,
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
    let series_seq = predecessor
        .series_seq
        .checked_add(1)
        .ok_or_else(|| KeyBackupError::InvalidInput("successor series_seq overflow".to_owned()))?;
    let supersedes_digest = key_backup_supersedes_digest(predecessor)?;
    let frontier_ref = KeyBackupFrontierRef {
        frontier_digest,
        seal_ref: None,
        device_generation_ref,
    };
    build_key_backup_envelope_in_series(
        backup_id,
        predecessor.actor_id.clone(),
        device_id,
        predecessor.backup_kind,
        backup_version,
        &predecessor.domain_separation.subdomain,
        predecessor.domain_separation.aead_aad_extensions.clone(),
        kek,
        items,
        predecessor.series_id.clone(),
        series_seq,
        Some(predecessor.backup_id.clone()),
        Some(supersedes_digest),
        Some(frontier_ref),
    )
}

fn key_backup_supersedes_digest(predecessor: &KeyBackup) -> Result<String> {
    let mut canonical = serde_json::to_value(predecessor).map_err(|err| {
        KeyBackupError::Canonical(format!(
            "serialize predecessor key backup for supersedes_digest: {err}"
        ))
    })?;
    if let Some(auth_data) = canonical
        .get_mut("auth_data")
        .and_then(Value::as_object_mut)
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
/// `backup_kind` so commitments cannot be reused across domains (§7.1: a
/// derived key, commitment key or wrap key for one domain must not be used
/// directly in another domain). Public for conformance KAT verification.
pub fn commitment_digest(root: &[u8; VAULT_KDF_OUTPUT_LEN], backup_kind: BackupKind) -> Vec<u8> {
    let mut commitment_key = derive_subkey(root, backup_kind.hkdf_info("commitment").as_bytes());
    let digest = arkret_canonical::canonical::sha256_bytes(commitment_key).to_vec();
    commitment_key.zeroize();
    digest
}

#[cfg(test)]
mod key_backup_envelope_tests {
    use arkret_models_crypto::SecretStorageItemKind;

    use super::*;

    #[test]
    fn backup_passphrase_encoding_preserves_the_final_entropy_bit() {
        let zeros = [0u8; BACKUP_PASSPHRASE_BYTES];
        let mut final_bit = zeros;
        final_bit[BACKUP_PASSPHRASE_BYTES - 1] = 1;

        let encoded_zeros = format_backup_passphrase(&zeros);
        let encoded_final_bit = format_backup_passphrase(&final_bit);
        assert_eq!(encoded_zeros.replace('-', "").len(), 52);
        assert_eq!(encoded_final_bit.replace('-', "").len(), 52);
        assert_ne!(encoded_zeros, encoded_final_bit);
    }

    /// The keybag is the only place the `backup_kind` branch, the branch-only
    /// `effective_scope` and the `x_` extension namespace meet, so the seal path
    /// is not proof that a receiver can read what it wrote. Cover the full
    /// build → seal → open → bind round trip.
    #[test]
    fn a_secret_storage_envelope_round_trips_through_its_own_opener() {
        let kek = derive_vault_kek(b"correct horse battery staple").unwrap();
        let envelope = build_key_backup_envelope(
            "ak:backup:01964137-0000-7000-8000-000000000000"
                .parse()
                .unwrap(),
            ActorId::account(arkret_wire::AccountId::new(
                "ak:did_core:webvh:z6mkfixture".parse().unwrap(),
                "ak:did_core:web:station.example".parse().unwrap(),
            )),
            None,
            BackupKind::SecretStorage,
            "kb_1",
            "recovery_vault",
            &kek,
            vec![SecretStorageSecret {
                item_kind: SecretStorageItemKind::PrivateAccountState,
                secret_id: "account-state".to_owned(),
                secret_b64u: "c2VjcmV0".to_owned(),
                secret_generation: Some(3),
                extra: Default::default(),
            }],
        )
        .unwrap();

        let opened =
            decrypt_key_backup_envelope(b"correct horse battery staple", &envelope).unwrap();
        assert_eq!(opened.backup_id, envelope.backup_id);
        assert_eq!(opened.keybag.backup_kind(), BackupKind::SecretStorage);
        let KeyBackupKeybag::SecretStorage { items } = &opened.keybag else {
            panic!("a secret_storage envelope must open as a secret_storage keybag");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].secret_b64u, "c2VjcmV0");
        assert_eq!(
            items[0].item_kind,
            SecretStorageItemKind::PrivateAccountState
        );
        assert_eq!(envelope.contents[0].secret_version(), Some(3));

        let mut other_station = envelope;
        other_station.actor_id = ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:webvh:z6mkfixture".parse().unwrap(),
            "ak:did_core:web:other-station.example".parse().unwrap(),
        ));
        assert!(
            decrypt_key_backup_envelope(b"correct horse battery staple", &other_station).is_err()
        );
    }

    #[test]
    fn derived_aad_sorts_and_deduplicates_item_kinds_and_preserves_extensions() {
        let mut extensions = XExtensionMap::default();
        extensions
            .insert("x_vendor", json!({"policy":"strict"}))
            .unwrap();
        let binding = VaultBinding {
            backup_id: "ak:backup:01964137-0000-7000-8000-000000000000"
                .parse()
                .unwrap(),
            subdomain: "recovery_vault".to_owned(),
            actor_id: ActorId::account(arkret_wire::AccountId::new(
                "ak:did_core:webvh:z6mkfixture".parse().unwrap(),
                "ak:did_core:web:station.example".parse().unwrap(),
            )),
            device_id: None,
            backup_kind: BackupKind::SecretStorage,
            backup_version: "kb_1".to_owned(),
            created_at: "2026-08-24T00:00:00Z".parse().unwrap(),
            item_kinds: vec![
                "private_account_state".to_owned(),
                "account_data_namespace_key".to_owned(),
                "private_account_state".to_owned(),
            ],
            recipient_method: KeyBackupRecipientMethod::PassphraseKdf,
            recipient_key_ref: None,
            aead_aad_extensions: extensions,
        };
        let aad = String::from_utf8(binding.aad().unwrap()).unwrap();
        assert_eq!(
            aad,
            r#"{"actor_id":{"account_id":{"principal_id":"ak:did_core:webvh:z6mkfixture","station_id":"ak:did_core:web:station.example"},"kind":"account"},"backup_kind":"secret_storage","backup_version":"kb_1","created_at":"2026-08-24T00:00:00.000Z","device_id":null,"item_kinds":["account_data_namespace_key","private_account_state"],"recipient_method":"passphrase_kdf","schema":"ak.schema.key_backup.v1","x_vendor":{"policy":"strict"}}"#
        );

        let mut without_extension = binding;
        without_extension.aead_aad_extensions = XExtensionMap::default();
        let aad = String::from_utf8(without_extension.aad().unwrap()).unwrap();
        assert!(!aad.contains("x_vendor"));
    }
}
