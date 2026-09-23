//! Client-side `ak.schema.key_backup.v1` crypto: passphrase KDF, AEAD, the
//! sole AAD construction, envelope assembly and the producer signature.
//!
//! The whole `passphrase_kdf` envelope lives here on purpose. `key-management.md`
//! §7.2 fixes one AAD construction that sealer and opener MUST both run, and one
//! signing transcript (`RFC8785_JCS(envelope minus auth_data.signature)`). Both
//! are byte-exact agreements between producer and verifier, so they are built
//! once by the SDK rather than re-derived by every host: a host that assembled
//! its own envelope would be re-implementing those byte rules and would drift
//! from every other host at the first optional member.

use argon2::{Algorithm, Argon2, Params, Version};
use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use arkret_canonical::canonical::{
    canonical_json_bytes, format_timestamp_canonical, normalize_timestamp_canonical, sha256_digest,
};
use arkret_models_crypto::artifacts_keys::{KeyBackupPlaintext, SecretStorageSecret};
use arkret_models_crypto::key_backup::{
    BackupKind, KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupAuthData,
    KeyBackupDomainSeparation, KeyBackupEncryption, KeyBackupKdf, KeyBackupKdfName,
    KeyBackupKdfParams, KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm,
    KeyBackupSourceCommitRef, SecretStorageContentIndex, SecretStorageItemKind,
};
use arkret_wire::{
    ActorId, BackupId, BackupSeriesId, Base64UrlString, DeviceId, DidUrl, EventId, Hash,
    XExtensionMap,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Utc};
use getrandom::fill;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::KeyBackupError;

type HmacSha256 = Hmac<Sha256>;
type Result<T> = std::result::Result<T, KeyBackupError>;

pub const VAULT_SCHEMA_ID: &str = arkret_wire::SchemaId::KEY_BACKUP_V1;
pub const VAULT_NONCE_SALT_LEN: usize = 16;
pub const VAULT_ARGON2_M_KIB: u32 = 65_536;
pub const VAULT_ARGON2_T: u32 = 3;
pub const VAULT_ARGON2_P: u32 = 4;
pub const VAULT_KDF_OUTPUT_LEN: usize = 32;
pub const VAULT_SALT_LEN: usize = 16;
pub const VAULT_NONCE_LEN: usize = 24;
pub const BACKUP_PASSPHRASE_BYTES: usize = 32;

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
    #[zeroize(skip)]
    pub kdf_name: KeyBackupKdfName,
    #[zeroize(skip)]
    pub digest_algorithm: Option<arkret_models_crypto::key_backup::KeyBackupKdfDigestAlgorithm>,
    #[zeroize(skip)]
    pub degraded_profile_reason: Option<String>,
}

impl std::fmt::Debug for VaultKek {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VaultKek")
            .field("key", &"<redacted>")
            .field("salt", &self.salt)
            .field("m_kib", &self.m_kib)
            .field("t", &self.t)
            .field("p", &self.p)
            .field("kdf_name", &self.kdf_name)
            .finish()
    }
}

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

pub fn derive_vault_kek(passphrase: &[u8]) -> Result<VaultKek> {
    let mut salt = [0u8; VAULT_SALT_LEN];
    fill(&mut salt).map_err(|error| KeyBackupError::Rng(format!("salt rng: {error}")))?;
    derive_vault_kek_with_salt(passphrase, &salt)
}

pub fn derive_vault_kek_with_salt(
    passphrase: &[u8],
    salt: &[u8; VAULT_SALT_LEN],
) -> Result<VaultKek> {
    std::str::from_utf8(passphrase)
        .map_err(|_| KeyBackupError::InvalidInput("passphrase must be UTF-8".to_owned()))?;
    let params = Params::new(VAULT_ARGON2_M_KIB, VAULT_ARGON2_T, VAULT_ARGON2_P, None)
        .map_err(|error| KeyBackupError::Kdf(format!("argon2 params: {error}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; VAULT_KDF_OUTPUT_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|error| KeyBackupError::Kdf(format!("argon2 hash: {error}")))?;
    Ok(VaultKek {
        key,
        salt: *salt,
        m_kib: VAULT_ARGON2_M_KIB,
        t: VAULT_ARGON2_T,
        p: VAULT_ARGON2_P,
        kdf_name: KeyBackupKdfName::Argon2id,
        digest_algorithm: None,
        degraded_profile_reason: None,
    })
}

pub fn derive_vault_kek_from_kdf(passphrase: &[u8], kdf: &KeyBackupKdf) -> Result<VaultKek> {
    std::str::from_utf8(passphrase)
        .map_err(|_| KeyBackupError::InvalidInput("passphrase must be UTF-8".to_owned()))?;
    kdf.validate().map_err(KeyBackupError::InvalidInput)?;
    let salt: [u8; VAULT_SALT_LEN] = base64url_decode(kdf.salt.as_str())
        .map_err(|error| KeyBackupError::Encoding(format!("salt base64: {error}")))?
        .try_into()
        .map_err(|_| KeyBackupError::Encoding(format!("salt must be {VAULT_SALT_LEN} bytes")))?;
    match kdf.name {
        KeyBackupKdfName::Argon2id => {
            let m = u32::try_from(kdf.params.memory_kib.unwrap())
                .map_err(|_| KeyBackupError::Kdf("argon2 memory_kib overflows u32".to_owned()))?;
            let t = u32::try_from(kdf.params.iterations.unwrap())
                .map_err(|_| KeyBackupError::Kdf("argon2 iterations overflows u32".to_owned()))?;
            let p = u32::try_from(kdf.params.parallelism.unwrap())
                .map_err(|_| KeyBackupError::Kdf("argon2 parallelism overflows u32".to_owned()))?;
            let params = Params::new(m, t, p, Some(VAULT_KDF_OUTPUT_LEN))
                .map_err(|error| KeyBackupError::Kdf(format!("argon2 params: {error}")))?;
            let mut key = [0u8; VAULT_KDF_OUTPUT_LEN];
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(passphrase, &salt, &mut key)
                .map_err(|error| KeyBackupError::Kdf(format!("argon2 hash: {error}")))?;
            Ok(VaultKek {
                key,
                salt,
                m_kib: m,
                t,
                p,
                kdf_name: KeyBackupKdfName::Argon2id,
                digest_algorithm: None,
                degraded_profile_reason: None,
            })
        }
        KeyBackupKdfName::Pbkdf2 => {
            let iterations = u32::try_from(kdf.params.iterations.unwrap())
                .map_err(|_| KeyBackupError::Kdf("pbkdf2 iterations overflows u32".to_owned()))?;
            let mut key = [0u8; VAULT_KDF_OUTPUT_LEN];
            macro_rules! pbkdf2_hmac {
                ($digest:ty) => {{
                    let mut mac = <Hmac<$digest> as KeyInit>::new_from_slice(passphrase)
                        .map_err(|error| KeyBackupError::Kdf(format!("pbkdf2 key: {error}")))?;
                    Mac::update(&mut mac, &salt);
                    Mac::update(&mut mac, &1u32.to_be_bytes());
                    let mut u = mac.finalize().into_bytes().to_vec();
                    let mut block = u.clone();
                    for _ in 1..iterations {
                        let mut mac = <Hmac<$digest> as KeyInit>::new_from_slice(passphrase)
                            .map_err(|error| KeyBackupError::Kdf(format!("pbkdf2 key: {error}")))?;
                        Mac::update(&mut mac, &u);
                        u = mac.finalize().into_bytes().to_vec();
                        for (dst, src) in block.iter_mut().zip(&u) {
                            *dst ^= src;
                        }
                    }
                    key.copy_from_slice(&block[..VAULT_KDF_OUTPUT_LEN]);
                }};
            }
            match kdf.params.digest_algorithm.unwrap() {
                arkret_models_crypto::key_backup::KeyBackupKdfDigestAlgorithm::Sha256 => {
                    pbkdf2_hmac!(Sha256)
                }
                arkret_models_crypto::key_backup::KeyBackupKdfDigestAlgorithm::Sha384 => {
                    pbkdf2_hmac!(Sha384)
                }
                arkret_models_crypto::key_backup::KeyBackupKdfDigestAlgorithm::Sha512 => {
                    pbkdf2_hmac!(Sha512)
                }
            }
            Ok(VaultKek {
                key,
                salt,
                m_kib: 0,
                t: iterations,
                p: 0,
                kdf_name: KeyBackupKdfName::Pbkdf2,
                digest_algorithm: kdf.params.digest_algorithm,
                degraded_profile_reason: kdf.degraded_profile_reason.clone(),
            })
        }
    }
}

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
    fn backup_class_wire(&self) -> &'static str {
        self.backup_kind.as_str()
    }

    pub fn subkey(&self, root: &[u8; VAULT_KDF_OUTPUT_LEN], subdomain: &str) -> [u8; 32] {
        derive_subkey(root, self.backup_kind.hkdf_info(subdomain).as_bytes())
    }

    pub fn nonce_transcript_canonical_bytes(&self, nonce_salt_b64: &str) -> Result<Vec<u8>> {
        canonical_json_bytes(&json!({
            "backup_id": self.backup_id.as_str(),
            "actor_id": self.actor_id,
            "device_id": self.device_id.as_ref().map(DeviceId::as_str),
            "backup_kind": self.backup_class_wire(),
            "backup_version": self.backup_version,
            "created_at": format_timestamp_canonical(self.created_at),
            "aead": "xchacha20_poly1305",
            "aead_profile": arkret_wire::AEAD_PROFILE_XCHACHA20_POLY1305_V1,
            "nonce_salt": nonce_salt_b64,
        }))
        .map_err(|error| KeyBackupError::Canonical(format!("nonce transcript: {error}")))
    }

    pub fn derive_nonce(
        &self,
        root: &[u8; VAULT_KDF_OUTPUT_LEN],
        nonce_salt_b64: &str,
    ) -> Result<[u8; VAULT_NONCE_LEN]> {
        let nonce_key = derive_subkey(root, b"arkret-key-backup-aead-nonce-v1");
        let transcript = self.nonce_transcript_canonical_bytes(nonce_salt_b64)?;
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&nonce_key)
            .map_err(|error| KeyBackupError::Kdf(format!("nonce hmac key: {error}")))?;
        Mac::update(&mut mac, &transcript);
        let tag = mac.finalize().into_bytes();
        let mut nonce = [0u8; VAULT_NONCE_LEN];
        nonce.copy_from_slice(&tag[..VAULT_NONCE_LEN]);
        Ok(nonce)
    }

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
                .map_err(|error| KeyBackupError::Canonical(error.to_string()))?,
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
            .map_err(|error| KeyBackupError::Canonical(format!("aead aad: {error}")))
    }
}

pub fn derive_subkey(root: &[u8; VAULT_KDF_OUTPUT_LEN], info: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, root);
    let mut output = [0u8; 32];
    hkdf.expand(info, &mut output)
        .expect("32-byte HKDF expansion is valid");
    output
}

pub fn encrypt_vault(
    kek: &VaultKek,
    binding: &VaultBinding,
    plaintext: &[u8],
) -> Result<VaultCiphertext> {
    let mut nonce_salt = [0u8; VAULT_NONCE_SALT_LEN];
    fill(&mut nonce_salt)
        .map_err(|error| KeyBackupError::Rng(format!("nonce_salt rng: {error}")))?;
    encrypt_vault_with_nonce_salt(kek, binding, plaintext, &nonce_salt)
}

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
    let aad = binding.aad()?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|error| KeyBackupError::Aead(format!("vault encrypt: {error}")))?;
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

pub fn decrypt_vault(
    passphrase: &[u8],
    binding: &VaultBinding,
    salt_b64: &str,
    nonce_b64: &str,
    nonce_salt_b64: &str,
    ciphertext_b64: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let salt: [u8; VAULT_SALT_LEN] = base64url_decode(salt_b64.trim_end_matches('='))
        .map_err(|error| KeyBackupError::Encoding(format!("salt base64: {error}")))?
        .try_into()
        .map_err(|_| KeyBackupError::Encoding(format!("salt must be {VAULT_SALT_LEN} bytes")))?;
    let kek = derive_vault_kek_with_salt(passphrase, &salt)?;
    decrypt_vault_with_root(&kek.key, binding, nonce_b64, nonce_salt_b64, ciphertext_b64)
}

pub fn decrypt_vault_with_kdf(
    passphrase: &[u8],
    kdf: &KeyBackupKdf,
    binding: &VaultBinding,
    nonce_b64: &str,
    nonce_salt_b64: &str,
    ciphertext_b64: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let kek = derive_vault_kek_from_kdf(passphrase, kdf)?;
    decrypt_vault_with_root(&kek.key, binding, nonce_b64, nonce_salt_b64, ciphertext_b64)
}

fn decrypt_vault_with_root(
    root: &[u8; VAULT_KDF_OUTPUT_LEN],
    binding: &VaultBinding,
    nonce_b64: &str,
    nonce_salt_b64: &str,
    ciphertext_b64: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let nonce: [u8; VAULT_NONCE_LEN] = base64url_decode(nonce_b64.trim_end_matches('='))
        .map_err(|error| KeyBackupError::Encoding(format!("nonce base64: {error}")))?
        .try_into()
        .map_err(|_| KeyBackupError::Encoding(format!("nonce must be {VAULT_NONCE_LEN} bytes")))?;
    let ciphertext = base64url_decode(ciphertext_b64.trim_end_matches('='))
        .map_err(|error| KeyBackupError::Encoding(format!("ciphertext base64: {error}")))?;
    if binding.derive_nonce(root, nonce_salt_b64)? != nonce {
        return Err(KeyBackupError::Aead(
            "vault decrypt failed: nonce derivation mismatch".to_owned(),
        ));
    }

    let mut aead_key = binding.subkey(root, &binding.subdomain);
    let cipher = XChaCha20Poly1305::new((&aead_key).into());
    let aad = binding.aad()?;
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| KeyBackupError::Aead("vault decrypt failed".to_owned()));
    aead_key.zeroize();
    plaintext
}

pub fn format_backup_passphrase(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut bits = 0u64;
    let mut bit_count = 0u32;
    let mut groups = Vec::with_capacity(11);
    let mut current = String::with_capacity(5);
    for &byte in bytes {
        bits = (bits << 8) | u64::from(byte);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            current.push(ALPHABET[((bits >> bit_count) & 0x1f) as usize] as char);
            if current.len() == 5 {
                groups.push(std::mem::take(&mut current));
            }
        }
    }
    if bit_count > 0 {
        current.push(ALPHABET[((bits << (5 - bit_count)) & 0x1f) as usize] as char);
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups.join("-")
}

pub fn commitment_digest(root: &[u8; VAULT_KDF_OUTPUT_LEN], backup_kind: BackupKind) -> Vec<u8> {
    let mut key = derive_subkey(root, backup_kind.hkdf_info("commitment").as_bytes());
    let digest = arkret_canonical::canonical::sha256_bytes(key).to_vec();
    key.zeroize();
    digest
}

/// The wire form of [`commitment_digest`]: the value an envelope carries in
/// `encryption.key_commitment`. Producer and opener derive it from the same
/// helper so the published commitment is exactly the digest this module
/// computes, never a second, separately-hashed encoding of it.
pub fn key_commitment_value(
    root: &[u8; VAULT_KDF_OUTPUT_LEN],
    backup_kind: BackupKind,
) -> Result<Hash> {
    Hash::new(format!(
        "sha256:{}",
        hex::encode(commitment_digest(root, backup_kind))
    ))
    .map_err(|error| KeyBackupError::InvalidInput(format!("key commitment digest: {error}")))
}

/// Closed device authorization for a key-backup envelope. The producing device
/// is fixed before the envelope is sealed; `KeyBackup::validate` re-checks that
/// the top-level `device_id`, when present, names this same device.
#[derive(Clone, Debug)]
pub struct KeyBackupAuthBinding {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub device_authorize_event_id: EventId,
}

/// Raw detached signer over the §7.2 envelope transcript
/// (`RFC8785_JCS(envelope minus auth_data.signature)`). The caller owns key
/// custody; this module owns the bytes that get signed.
pub type KeyBackupSignFn<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>>;

/// Occupies `auth_data.signature` while the envelope's own signing transcript
/// is computed. §7.2 removes that member from the transcript, so this value can
/// never reach the signed bytes, and it is replaced by the producer signature
/// before any envelope leaves this module.
const UNSIGNED_SIGNATURE_PLACEHOLDER: &str = "AA";

fn item_kind_wire(kind: SecretStorageItemKind) -> Result<String> {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| {
            KeyBackupError::Canonical(
                "secret storage item_kind does not serialize to a wire string".to_owned(),
            )
        })
}

fn base64url_field(value: &str) -> Result<Base64UrlString> {
    Base64UrlString::new(value.to_owned())
        .map_err(|error| KeyBackupError::Encoding(format!("base64url field: {error}")))
}

/// Rebuild the exact [`VaultBinding`] an envelope was sealed under, from the
/// envelope alone. Every AAD input is read back off the wire object, so an
/// opener can never bind different metadata than the sealer published.
fn vault_binding_from_envelope(envelope: &KeyBackup) -> Result<VaultBinding> {
    Ok(VaultBinding {
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
            .map(|index| item_kind_wire(index.item_kind))
            .collect::<Result<Vec<_>>>()?,
        recipient_method: envelope.encryption.recipient_method,
        recipient_key_ref: envelope.encryption.recipient_key_ref.clone(),
        aead_aad_extensions: envelope.domain_separation.aead_aad_extensions.clone(),
    })
}

/// The sole §7.2 AEAD/HPKE additional authenticated data for a typed
/// key-backup envelope.
///
/// Fixed members are derived from the envelope, never accepted from a caller
/// list; `contents[].item_kind` is sorted bytewise and deduplicated, and only
/// the closed `x_*` extension map may add members.
pub fn key_backup_aead_aad(envelope: &KeyBackup) -> Result<Vec<u8>> {
    vault_binding_from_envelope(envelope)?.aad()
}

/// Open a `passphrase_kdf` envelope and return its typed plaintext keybag.
///
/// Every producer/receiver invariant this module owns is enforced before any
/// secret is returned: envelope shape, recipient method, KDF and AEAD profile,
/// `ciphertext_digest`, key commitment, deterministic nonce, the §7.2 AAD, the
/// AEAD tag, and finally that the decrypted keybag matches the public
/// `contents` index it was published with.
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
    if keybag.backup_kind != envelope.backup_kind {
        return Err(KeyBackupError::InvalidInput(
            "decrypted keybag backup_kind differs from its envelope".to_owned(),
        ));
    }
    keybag
        .validate_against(&envelope.contents)
        .map_err(|error| KeyBackupError::InvalidInput(error.to_string()))?;
    Ok(keybag)
}

fn decrypt_key_backup_envelope_bytes(
    passphrase: &[u8],
    envelope: &KeyBackup,
) -> Result<Zeroizing<Vec<u8>>> {
    envelope
        .validate()
        .map_err(|error| KeyBackupError::InvalidInput(error.to_string()))?;
    if envelope.encryption.recipient_method != KeyBackupRecipientMethod::PassphraseKdf {
        return Err(KeyBackupError::InvalidInput(
            "key backup is not a passphrase_kdf envelope".to_owned(),
        ));
    }
    let kdf = envelope.encryption.kdf.as_ref().ok_or_else(|| {
        KeyBackupError::InvalidInput("passphrase_kdf envelope is missing kdf".to_owned())
    })?;
    if envelope.encryption.aead.name != KeyBackupAeadName::Xchacha20Poly1305 {
        return Err(KeyBackupError::InvalidInput(
            "passphrase_kdf envelopes use the XChaCha20-Poly1305 AEAD profile".to_owned(),
        ));
    }
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

    let ciphertext_bytes = base64url_decode(envelope.ciphertext.as_str().trim_end_matches('='))
        .map_err(|error| KeyBackupError::Encoding(format!("ciphertext base64: {error}")))?;
    if sha256_digest(&ciphertext_bytes) != envelope.ciphertext_digest.as_str() {
        return Err(KeyBackupError::InvalidInput(
            "key backup ciphertext_digest mismatch".to_owned(),
        ));
    }

    let kek = derive_vault_kek_from_kdf(passphrase, kdf)?;
    if envelope.encryption.key_commitment.as_ref()
        != Some(&key_commitment_value(&kek.key, envelope.backup_kind)?)
    {
        return Err(KeyBackupError::InvalidInput(
            "key backup key_commitment mismatch".to_owned(),
        ));
    }

    decrypt_vault_with_root(
        &kek.key,
        &vault_binding_from_envelope(envelope)?,
        nonce.as_str(),
        nonce_salt.as_str(),
        envelope.ciphertext.as_str(),
    )
}

/// Build and sign a genesis `passphrase_kdf` envelope from closed plaintext
/// items.
///
/// The SDK derives the public `contents` index and the canonical
/// `ak.schema.key_backup_plaintext.v1` keybag from the same values, so
/// caller-controlled metadata can never drift from what was actually sealed.
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
    auth: &KeyBackupAuthBinding,
    sign: KeyBackupSignFn<'_>,
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
        auth,
        sign,
        None,
    )
}

/// Build and sign a genesis envelope whose AAD additionally covers the closed
/// `x_*` extension map. Fixed AAD members stay SDK-derived and cannot be
/// overridden or shadowed by an extension.
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
    auth: &KeyBackupAuthBinding,
    sign: KeyBackupSignFn<'_>,
    source_commit_ref: Option<KeyBackupSourceCommitRef>,
) -> Result<KeyBackup> {
    let series_id = BackupSeriesId::new(arkret_wire::new_prefixed_uuid7("ak:backup_series:"))
        .map_err(|error| {
            KeyBackupError::InvalidInput(format!("failed to mint backup_series id: {error}"))
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
        auth,
        sign,
        series_id,
        0,
        None,
        None,
        source_commit_ref,
    )
}

/// Build and sign the next envelope of an existing series.
///
/// The successor inherits actor, class, subdomain, extension map and series
/// from `predecessor`, increments `series_seq`, and binds the predecessor by
/// both `backup_id` and the digest of the predecessor's own §7.2 signing
/// transcript — so a successor cannot be re-pointed at a different prior
/// envelope without breaking the chain.
#[allow(clippy::too_many_arguments)]
pub fn build_key_backup_successor_envelope(
    backup_id: BackupId,
    predecessor: &KeyBackup,
    device_id: Option<DeviceId>,
    backup_version: &str,
    kek: &VaultKek,
    items: Vec<SecretStorageSecret>,
    auth: &KeyBackupAuthBinding,
    sign: KeyBackupSignFn<'_>,
    source_commit_ref: Option<KeyBackupSourceCommitRef>,
) -> Result<KeyBackup> {
    if backup_id == predecessor.backup_id {
        return Err(KeyBackupError::InvalidInput(
            "successor backup_id must differ from predecessor".to_owned(),
        ));
    }
    if source_commit_ref
        .as_ref()
        .is_some_and(|source| source.device_generation_ref == 0)
    {
        return Err(KeyBackupError::InvalidInput(
            "successor source_commit_ref.device_generation_ref must be positive".to_owned(),
        ));
    }
    let series_seq = predecessor
        .series_seq
        .checked_add(1)
        .ok_or_else(|| KeyBackupError::InvalidInput("successor series_seq overflow".to_owned()))?;
    let supersedes_digest = key_backup_supersedes_digest(predecessor)?;
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
        auth,
        sign,
        predecessor.series_id.clone(),
        series_seq,
        Some(predecessor.backup_id.clone()),
        Some(supersedes_digest),
        source_commit_ref,
    )
}

/// Digest of the predecessor's §7.2 signing transcript. Using the transcript
/// itself — rather than an ad-hoc projection — means `supersedes_digest`
/// covers exactly the bytes the predecessor's producing device signed.
fn key_backup_supersedes_digest(predecessor: &KeyBackup) -> Result<Hash> {
    let transcript = predecessor.signing_payload_bytes().map_err(|error| {
        KeyBackupError::Canonical(format!("predecessor key backup transcript: {error}"))
    })?;
    Hash::new(sha256_digest(&transcript)).map_err(|error| {
        KeyBackupError::Canonical(format!("predecessor key backup digest: {error}"))
    })
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
    auth: &KeyBackupAuthBinding,
    sign: KeyBackupSignFn<'_>,
    series_id: BackupSeriesId,
    series_seq: u64,
    supersedes_id: Option<BackupId>,
    supersedes_digest: Option<Hash>,
    source_commit_ref: Option<KeyBackupSourceCommitRef>,
) -> Result<KeyBackup> {
    if source_commit_ref
        .as_ref()
        .is_some_and(|source| source.device_generation_ref == 0)
    {
        return Err(KeyBackupError::InvalidInput(
            "source_commit_ref.device_generation_ref must be positive".to_owned(),
        ));
    }
    if items.is_empty() {
        return Err(KeyBackupError::InvalidInput(
            "key backup plaintext items must not be empty".to_owned(),
        ));
    }
    if device_id.as_ref().is_some_and(|id| id != &auth.device_id) {
        return Err(KeyBackupError::InvalidInput(
            "key backup device_id must name the signing device".to_owned(),
        ));
    }
    let domain_separation = KeyBackupDomainSeparation {
        subdomain: subdomain.to_owned(),
        aead_aad_extensions,
    };
    domain_separation
        .validate()
        .map_err(|error| KeyBackupError::InvalidInput(error.to_string()))?;

    let contents = items
        .iter()
        .map(|item| {
            item.validate()
                .map_err(|error| KeyBackupError::InvalidInput(error.to_string()))?;
            Ok(SecretStorageContentIndex {
                item_kind: item.item_kind,
                secret_id: item.secret_id.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let plaintext = KeyBackupPlaintext { backup_kind, items };
    plaintext
        .validate_against(&contents)
        .map_err(|error| KeyBackupError::InvalidInput(error.to_string()))?;
    let plaintext_bytes =
        Zeroizing::new(canonical_json_bytes(&plaintext).map_err(|error| {
            KeyBackupError::Canonical(format!("key backup plaintext: {error}"))
        })?);

    // Truncate to the canonical timestamp resolution so the AAD binding
    // round-trips byte-for-byte through the persisted `created_at`.
    let created_at = normalize_timestamp_canonical(Utc::now());
    let binding = VaultBinding {
        backup_id: backup_id.clone(),
        subdomain: domain_separation.subdomain.clone(),
        actor_id: actor_id.clone(),
        device_id: device_id.clone(),
        backup_kind,
        backup_version: backup_version.to_owned(),
        created_at,
        item_kinds: contents
            .iter()
            .map(|index| item_kind_wire(index.item_kind))
            .collect::<Result<Vec<_>>>()?,
        recipient_method: KeyBackupRecipientMethod::PassphraseKdf,
        recipient_key_ref: None,
        aead_aad_extensions: domain_separation.aead_aad_extensions.clone(),
    };
    let ciphertext = encrypt_vault(kek, &binding, &plaintext_bytes)?;

    let encryption = KeyBackupEncryption {
        recipient_method: KeyBackupRecipientMethod::PassphraseKdf,
        recipient_key_ref: None,
        // The HPKE suite selector applies only to recipient_method =
        // recovery_public_key, so the symmetric path omits it.
        hpke_suite: None,
        kdf: Some(KeyBackupKdf {
            name: kek.kdf_name,
            salt: base64url_field(&ciphertext.salt_b64)?,
            params: KeyBackupKdfParams {
                memory_kib: (kek.kdf_name == KeyBackupKdfName::Argon2id)
                    .then_some(u64::from(kek.m_kib)),
                iterations: Some(u64::from(kek.t)),
                parallelism: (kek.kdf_name == KeyBackupKdfName::Argon2id)
                    .then_some(u64::from(kek.p)),
                digest_algorithm: kek.digest_algorithm,
                extra: XExtensionMap::default(),
            },
            degraded_profile_reason: kek.degraded_profile_reason.clone(),
            extra: XExtensionMap::default(),
        }),
        aead: KeyBackupAead {
            name: KeyBackupAeadName::Xchacha20Poly1305,
            aead_profile: Some(arkret_wire::AEAD_PROFILE_XCHACHA20_POLY1305_V1.to_owned()),
            nonce_salt: Some(base64url_field(&ciphertext.nonce_salt_b64)?),
            nonce: Some(base64url_field(&ciphertext.nonce_b64)?),
            enc: None,
            extra: XExtensionMap::default(),
        },
        key_commitment: Some(key_commitment_value(&kek.key, backup_kind)?),
        extra: XExtensionMap::default(),
    };

    let mut envelope = KeyBackup {
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
        ciphertext: base64url_field(&ciphertext.ciphertext_b64)?,
        ciphertext_digest: Hash::new(ciphertext.digest_sha256).map_err(|error| {
            KeyBackupError::Canonical(format!("key backup ciphertext digest: {error}"))
        })?,
        plaintext_commitment: None,
        auth_data: KeyBackupAuthData {
            device_id: auth.device_id.clone(),
            verification_method: auth.verification_method.clone(),
            signature_algorithm: auth.signature_algorithm,
            signature: base64url_field(UNSIGNED_SIGNATURE_PLACEHOLDER)?,
            device_authorize_event_id: auth.device_authorize_event_id.clone(),
        },
        retention: None,
        series_id,
        series_seq,
        supersedes_id,
        supersedes_digest,
        source_commit_ref,
        recovery_policy_ref: None,
        extra: XExtensionMap::default(),
    };

    let transcript = envelope.signing_payload_bytes().map_err(|error| {
        KeyBackupError::Canonical(format!("key backup signing transcript: {error}"))
    })?;
    let signature = sign(&transcript)?;
    if signature.is_empty() {
        return Err(KeyBackupError::InvalidInput(
            "key backup producer signature must not be empty".to_owned(),
        ));
    }
    envelope.auth_data.signature = base64url_field(&base64url_encode(&signature))?;
    envelope
        .validate()
        .map_err(|error| KeyBackupError::InvalidInput(error.to_string()))?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> VaultBinding {
        VaultBinding {
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
            item_kinds: vec!["private_account_state".to_owned()],
            recipient_method: KeyBackupRecipientMethod::PassphraseKdf,
            recipient_key_ref: None,
            aead_aad_extensions: XExtensionMap::default(),
        }
    }

    #[test]
    fn vault_round_trip_and_binding_rejection() {
        let kek = derive_vault_kek_with_salt(b"passphrase", &[7u8; VAULT_SALT_LEN]).unwrap();
        let binding = binding();
        let encrypted =
            encrypt_vault_with_nonce_salt(&kek, &binding, b"secret", &[9u8; 16]).unwrap();
        let opened = decrypt_vault(
            b"passphrase",
            &binding,
            &encrypted.salt_b64,
            &encrypted.nonce_b64,
            &encrypted.nonce_salt_b64,
            &encrypted.ciphertext_b64,
        )
        .unwrap();
        assert_eq!(&*opened, b"secret");

        let mut changed = binding;
        changed.backup_version = "kb_2".to_owned();
        assert!(
            decrypt_vault(
                b"passphrase",
                &changed,
                &encrypted.salt_b64,
                &encrypted.nonce_b64,
                &encrypted.nonce_salt_b64,
                &encrypted.ciphertext_b64,
            )
            .is_err()
        );
    }

    #[test]
    fn passphrase_encoding_keeps_final_entropy_bit() {
        let zeros = [0u8; BACKUP_PASSPHRASE_BYTES];
        let mut final_bit = zeros;
        final_bit[BACKUP_PASSPHRASE_BYTES - 1] = 1;
        assert_ne!(
            format_backup_passphrase(&zeros),
            format_backup_passphrase(&final_bit)
        );
    }

    const DEVICE: &str = "ak:device:01964137-0000-7000-8000-0000000000d1";
    const AUTHORIZE_EVENT: &str = "ak:event:AQNy1zG98lAoTz0YOf-2Yp2-GXeJioPlyg8nW6qxW-OB";
    const PASSPHRASE: &[u8] = b"correct horse battery staple";

    fn actor() -> ActorId {
        ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:webvh:z6mkfixture".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ))
    }

    fn auth() -> KeyBackupAuthBinding {
        KeyBackupAuthBinding {
            device_id: DEVICE.parse().unwrap(),
            verification_method: DidUrl::new("did:web:station.example#device-1").unwrap(),
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            device_authorize_event_id: AUTHORIZE_EVENT.parse().unwrap(),
        }
    }

    /// Stand-in for the caller's device key: it records the exact transcript
    /// the module asked it to sign, so tests can assert what was covered.
    fn recording_signer(
        seen: &std::cell::RefCell<Vec<Vec<u8>>>,
    ) -> impl Fn(&[u8]) -> Result<Vec<u8>> {
        move |transcript: &[u8]| {
            seen.borrow_mut().push(transcript.to_vec());
            Ok(arkret_canonical::canonical::sha256_bytes(transcript).to_vec())
        }
    }

    fn items() -> Vec<SecretStorageSecret> {
        vec![
            SecretStorageSecret {
                item_kind: SecretStorageItemKind::PrivateAccountState,
                secret_id: "account.state".to_owned(),
                secret_b64u: Base64UrlString::new("c2VjcmV0LW9uZQ".to_owned()).unwrap(),
                secret_generation: Some(3),
                extra: XExtensionMap::default(),
            },
            SecretStorageSecret {
                item_kind: SecretStorageItemKind::MlsAccountSecret,
                secret_id: "mls.account".to_owned(),
                secret_b64u: Base64UrlString::new("c2VjcmV0LXR3bw".to_owned()).unwrap(),
                secret_generation: None,
                extra: XExtensionMap::default(),
            },
        ]
    }

    fn source_commit_ref() -> KeyBackupSourceCommitRef {
        KeyBackupSourceCommitRef {
            realm_commit_id: "ak:realm_commit:AQNy1zG98lAoTz0YOf-2Yp2-GXeJioPlyg8nW6qxW-OB"
                .parse()
                .unwrap(),
            device_generation_ref: 4,
        }
    }

    fn genesis(kek: &VaultKek, seen: &std::cell::RefCell<Vec<Vec<u8>>>) -> KeyBackup {
        let sign = recording_signer(seen);
        build_key_backup_envelope(
            "ak:backup:01964137-0000-7000-8000-000000000001"
                .parse()
                .unwrap(),
            actor(),
            Some(DEVICE.parse().unwrap()),
            BackupKind::SecretStorage,
            "kb_1",
            "recovery_vault",
            kek,
            items(),
            &auth(),
            &sign,
        )
        .unwrap()
    }

    #[test]
    fn genesis_envelope_round_trips_through_decrypt() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let envelope = genesis(&kek, &seen);

        assert_eq!(envelope.series_seq, 0);
        assert!(envelope.supersedes_id.is_none() && envelope.supersedes_digest.is_none());
        assert_eq!(envelope.contents.len(), 2);

        let opened = decrypt_key_backup_envelope(PASSPHRASE, &envelope).unwrap();
        assert_eq!(opened.backup_kind, BackupKind::SecretStorage);
        assert_eq!(opened.items.len(), 2);
        assert_eq!(opened.items[0].secret_id, "account.state");
        assert_eq!(opened.items[1].secret_id, "mls.account");

        // A different passphrase must fail before the AEAD, on the commitment.
        assert!(decrypt_key_backup_envelope(b"wrong passphrase", &envelope).is_err());
    }

    #[test]
    fn pbkdf2_envelope_uses_wire_parameters_and_commitment() {
        let kdf = KeyBackupKdf {
            name: KeyBackupKdfName::Pbkdf2,
            salt: Base64UrlString::new("AAECAwQFBgcICQoLDA0ODw").unwrap(),
            params: KeyBackupKdfParams {
                memory_kib: None,
                iterations: Some(600_000),
                parallelism: None,
                digest_algorithm: Some(
                    arkret_models_crypto::key_backup::KeyBackupKdfDigestAlgorithm::Sha512,
                ),
                extra: XExtensionMap::default(),
            },
            degraded_profile_reason: Some("platform_memory_hard_kdf_unavailable".to_owned()),
            extra: XExtensionMap::default(),
        };
        let kek = derive_vault_kek_from_kdf(PASSPHRASE, &kdf).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let envelope = genesis(&kek, &seen);
        assert!(decrypt_key_backup_envelope(PASSPHRASE, &envelope).is_ok());
        let mut changed = envelope.clone();
        changed.encryption.kdf.as_mut().unwrap().params.iterations = Some(600_001);
        assert!(decrypt_key_backup_envelope(PASSPHRASE, &changed).is_err());
        let mut changed = envelope;
        changed.encryption.key_commitment =
            Some(Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap());
        assert!(decrypt_key_backup_envelope(PASSPHRASE, &changed).is_err());
    }

    #[test]
    fn contents_index_is_required_nonempty_and_closed() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let envelope = genesis(&kek, &seen);
        let wire = serde_json::to_value(&envelope).unwrap();
        assert_eq!(wire["contents"][0]["secret_id"], "account.state");
        assert!(wire["contents"][0].get("secret_version").is_none());
        assert!(serde_json::from_value::<KeyBackup>(wire.clone()).is_ok());

        let mut missing = wire.clone();
        missing.as_object_mut().unwrap().remove("contents");
        assert!(serde_json::from_value::<KeyBackup>(missing).is_err());

        let mut empty = wire.clone();
        empty["contents"] = serde_json::json!([]);
        assert!(serde_json::from_value::<KeyBackup>(empty).is_err());
        let mut empty = envelope.clone();
        empty.contents.clear();
        assert!(empty.validate().is_err());
        assert!(empty.signing_payload_bytes().is_err());
        assert!(serde_json::to_value(&empty).is_err());

        let mut unregistered = wire.clone();
        unregistered["contents"][0]["secret_version"] = serde_json::json!(3);
        assert!(serde_json::from_value::<KeyBackup>(unregistered).is_err());

        let mut no_identity = wire;
        no_identity["contents"][0]
            .as_object_mut()
            .unwrap()
            .remove("secret_id");
        assert!(serde_json::from_value::<KeyBackup>(no_identity).is_err());
    }

    #[test]
    fn recovery_public_key_requires_a_positive_recovery_policy_ref() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let mut envelope = genesis(&kek, &seen);
        envelope.encryption.recipient_method = KeyBackupRecipientMethod::RecoveryPublicKey;
        envelope.encryption.recipient_key_ref =
            Some("did:web:alice.example#backup-hpke".to_owned());
        envelope.encryption.kdf = None;
        envelope.recovery_policy_ref = None;

        assert!(
            envelope
                .validate()
                .unwrap_err()
                .to_string()
                .contains("requires recovery_policy_ref")
        );

        envelope.recovery_policy_ref = Some(arkret_models_crypto::RecoveryPolicyRef {
            policy_id: arkret_wire::PolicyId::new("ak:policy:01964137-0000-7000-8000-000000000077")
                .unwrap(),
            policy_version: 0,
        });
        assert!(
            envelope
                .validate()
                .unwrap_err()
                .to_string()
                .contains("version must be positive")
        );

        envelope
            .recovery_policy_ref
            .as_mut()
            .unwrap()
            .policy_version = 1;
        let wire = serde_json::to_value(&envelope).unwrap();
        assert_eq!(wire["recovery_policy_ref"]["policy_version"], 1);
    }

    #[test]
    fn producer_signature_covers_the_envelope_minus_its_own_signature() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let envelope = genesis(&kek, &seen);

        let signed = seen.into_inner();
        assert_eq!(signed.len(), 1, "exactly one transcript is signed");
        // Installing the real signature must not move the transcript: §7.2
        // removes `auth_data.signature` from the signed bytes.
        assert_eq!(signed[0], envelope.signing_payload_bytes().unwrap());
        assert_ne!(
            envelope.auth_data.signature.as_str(),
            UNSIGNED_SIGNATURE_PLACEHOLDER,
            "the placeholder must never survive into a returned envelope"
        );
        let transcript = String::from_utf8(signed[0].clone()).unwrap();
        assert!(!transcript.contains("\"signature\""));
        assert!(transcript.contains("\"ciphertext_digest\""));
        assert!(transcript.contains("\"device_authorize_event_id\""));
    }

    #[test]
    fn aad_is_derived_from_the_envelope_and_binds_its_metadata() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let envelope = genesis(&kek, &seen);

        // The published AAD is exactly what the sealer bound.
        let aad = String::from_utf8(key_backup_aead_aad(&envelope).unwrap()).unwrap();
        assert!(aad.starts_with(r#"{"actor_id":"#));
        assert!(aad.contains(r#""schema":"ak.schema.key_backup.v1""#));
        // item_kinds is sorted bytewise, not left in contents order.
        assert!(aad.contains(r#""item_kinds":["mls_account_secret","private_account_state"]"#));

        // Every fixed AAD member is load-bearing.
        for tamper in [
            |envelope: &mut KeyBackup| envelope.backup_version = "kb_2".to_owned(),
            |envelope: &mut KeyBackup| envelope.device_id = None,
            |envelope: &mut KeyBackup| {
                envelope.contents[0].item_kind = SecretStorageItemKind::RecoveryKeyShare;
            },
        ] {
            let mut tampered = envelope.clone();
            tamper(&mut tampered);
            assert_ne!(
                key_backup_aead_aad(&tampered).unwrap(),
                key_backup_aead_aad(&envelope).unwrap()
            );
            assert!(decrypt_key_backup_envelope(PASSPHRASE, &tampered).is_err());
        }

        // `subdomain` is deliberately NOT an AAD member: §7.2 binds it through
        // the HKDF `info` (`arkret-key-backup/<backup_kind>/<subdomain>/v1`),
        // so rewriting it yields the same AAD but a different AEAD key.
        let mut rebranded = envelope.clone();
        rebranded.domain_separation.subdomain = "other_vault".to_owned();
        assert_eq!(
            key_backup_aead_aad(&rebranded).unwrap(),
            key_backup_aead_aad(&envelope).unwrap()
        );
        assert!(decrypt_key_backup_envelope(PASSPHRASE, &rebranded).is_err());
    }

    #[test]
    fn auth_data_device_binding_is_enforced_before_any_secret_is_returned() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let envelope = genesis(&kek, &seen);

        let mut tampered = envelope;
        tampered.auth_data.device_id = "ak:device:01964137-0000-7000-8000-0000000000d2"
            .parse()
            .unwrap();
        assert!(decrypt_key_backup_envelope(PASSPHRASE, &tampered).is_err());

        // The builder refuses the same disagreement up front.
        let sign = recording_signer(&seen);
        assert!(
            build_key_backup_envelope(
                "ak:backup:01964137-0000-7000-8000-00000000000f"
                    .parse()
                    .unwrap(),
                actor(),
                Some(
                    "ak:device:01964137-0000-7000-8000-0000000000d2"
                        .parse()
                        .unwrap()
                ),
                BackupKind::SecretStorage,
                "kb_1",
                "recovery_vault",
                &kek,
                items(),
                &auth(),
                &sign,
            )
            .is_err()
        );
    }

    #[test]
    fn ciphertext_digest_mismatch_is_rejected() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let envelope = genesis(&kek, &seen);

        let mut tampered = envelope.clone();
        tampered.ciphertext_digest = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        let error = decrypt_key_backup_envelope(PASSPHRASE, &tampered).unwrap_err();
        assert!(error.to_string().contains("ciphertext_digest mismatch"));

        // Rewriting both ciphertext and its digest still fails on the AEAD tag.
        let mut swapped = envelope;
        let forged = base64url_encode(b"not the sealed vault");
        swapped.ciphertext_digest =
            Hash::new(sha256_digest(base64url_decode(&forged).unwrap())).unwrap();
        swapped.ciphertext = Base64UrlString::new(forged).unwrap();
        assert!(decrypt_key_backup_envelope(PASSPHRASE, &swapped).is_err());
    }

    #[test]
    fn key_commitment_is_the_published_form_of_the_commitment_digest() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let envelope = genesis(&kek, &seen);
        assert_eq!(
            envelope
                .encryption
                .key_commitment
                .as_ref()
                .unwrap()
                .as_str(),
            format!(
                "sha256:{}",
                hex::encode(commitment_digest(&kek.key, BackupKind::SecretStorage))
            )
        );

        let mut tampered = envelope;
        tampered.encryption.key_commitment =
            Some(Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap());
        let error = decrypt_key_backup_envelope(PASSPHRASE, &tampered).unwrap_err();
        assert!(error.to_string().contains("key_commitment mismatch"));
    }

    #[test]
    fn successor_links_to_its_predecessor_transcript_and_opens() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let predecessor = genesis(&kek, &seen);

        let sign = recording_signer(&seen);
        let successor = build_key_backup_successor_envelope(
            "ak:backup:01964137-0000-7000-8000-000000000002"
                .parse()
                .unwrap(),
            &predecessor,
            Some(DEVICE.parse().unwrap()),
            "kb_2",
            &kek,
            items(),
            &auth(),
            &sign,
            Some(source_commit_ref()),
        )
        .unwrap();

        assert_eq!(successor.series_id, predecessor.series_id);
        assert_eq!(successor.series_seq, predecessor.series_seq + 1);
        assert_eq!(
            successor.supersedes_id.as_ref(),
            Some(&predecessor.backup_id)
        );
        assert_eq!(
            successor.supersedes_digest.as_ref().unwrap().as_str(),
            sha256_digest(predecessor.signing_payload_bytes().unwrap())
        );
        assert_eq!(
            successor.source_commit_ref.as_ref().unwrap(),
            &source_commit_ref()
        );
        assert_eq!(
            successor.domain_separation.subdomain,
            predecessor.domain_separation.subdomain
        );
        assert!(decrypt_key_backup_envelope(PASSPHRASE, &successor).is_ok());

        let without_source = build_key_backup_successor_envelope(
            "ak:backup:01964137-0000-7000-8000-00000000000e"
                .parse()
                .unwrap(),
            &predecessor,
            Some(DEVICE.parse().unwrap()),
            "kb_2",
            &kek,
            items(),
            &auth(),
            &sign,
            None,
        )
        .unwrap();
        assert!(without_source.source_commit_ref.is_none());
        assert_eq!(without_source.series_seq, predecessor.series_seq + 1);
        assert_eq!(
            without_source.supersedes_id.as_ref(),
            Some(&predecessor.backup_id)
        );
        assert!(without_source.supersedes_digest.is_some());

        // Re-pointing the link at another envelope breaks the chain digest.
        let mut relinked = successor;
        relinked.supersedes_digest = Some(Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap());
        assert_ne!(
            relinked.supersedes_digest.as_ref().unwrap().as_str(),
            sha256_digest(predecessor.signing_payload_bytes().unwrap())
        );

        // A successor may not reuse the predecessor's backup_id.
        assert!(
            build_key_backup_successor_envelope(
                predecessor.backup_id.clone(),
                &predecessor,
                Some(DEVICE.parse().unwrap()),
                "kb_2",
                &kek,
                items(),
                &auth(),
                &sign,
                Some(source_commit_ref()),
            )
            .is_err()
        );
    }

    #[test]
    fn envelope_source_commit_ref_has_the_only_canonical_wire_shape() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let predecessor = genesis(&kek, &seen);
        let sign = recording_signer(&seen);
        let successor = build_key_backup_successor_envelope(
            "ak:backup:01964137-0000-7000-8000-000000000012"
                .parse()
                .unwrap(),
            &predecessor,
            Some(DEVICE.parse().unwrap()),
            "kb_2",
            &kek,
            items(),
            &auth(),
            &sign,
            Some(source_commit_ref()),
        )
        .unwrap();

        let canonical = serde_json::to_value(&successor).unwrap();
        assert!(canonical.get("source_ref").is_none());
        assert_eq!(
            canonical["source_commit_ref"],
            json!({
                "realm_commit_id": source_commit_ref().realm_commit_id,
                "device_generation_ref": 4
            })
        );

        let mut alias = canonical.clone();
        let source = alias
            .as_object_mut()
            .unwrap()
            .remove("source_commit_ref")
            .unwrap();
        alias
            .as_object_mut()
            .unwrap()
            .insert("source_ref".to_owned(), source);
        assert!(serde_json::from_value::<KeyBackup>(alias).is_err());

        let mut full_committed_ref = canonical.clone();
        full_committed_ref["source_commit_ref"] = json!({
            "committed_event_ref": {
                "event_id": AUTHORIZE_EVENT,
                "commit_id": source_commit_ref().realm_commit_id,
                "stream_ref": {
                    "kind": "realm",
                    "realm_id": arkret_wire::RealmId::from_event_id(
                        &AUTHORIZE_EVENT.parse::<EventId>().unwrap()
                    )
                },
                "stream_position": 7
            },
            "device_generation_ref": 4
        });
        assert!(serde_json::from_value::<KeyBackup>(full_committed_ref).is_err());

        let mut string_generation = canonical.clone();
        string_generation["source_commit_ref"]["device_generation_ref"] = json!("4");
        assert!(serde_json::from_value::<KeyBackup>(string_generation).is_err());

        let mut zero_generation = successor;
        zero_generation
            .source_commit_ref
            .as_mut()
            .unwrap()
            .device_generation_ref = 0;
        assert!(zero_generation.validate().is_err());
    }

    #[test]
    fn aad_extensions_enter_the_binding_and_cannot_shadow_fixed_members() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let sign = recording_signer(&seen);
        let mut extensions = XExtensionMap::default();
        extensions
            .insert("x_vault_profile".to_owned(), serde_json::json!("household"))
            .unwrap();

        let envelope = build_key_backup_envelope_with_extensions(
            "ak:backup:01964137-0000-7000-8000-000000000003"
                .parse()
                .unwrap(),
            actor(),
            Some(DEVICE.parse().unwrap()),
            BackupKind::SecretStorage,
            "kb_1",
            "recovery_vault",
            extensions,
            &kek,
            items(),
            &auth(),
            &sign,
            Some(source_commit_ref()),
        )
        .unwrap();

        let aad = String::from_utf8(key_backup_aead_aad(&envelope).unwrap()).unwrap();
        assert!(aad.contains(r#""x_vault_profile":"household""#));
        assert!(decrypt_key_backup_envelope(PASSPHRASE, &envelope).is_ok());

        // Dropping the extension changes the AAD, so the envelope no longer opens.
        let mut stripped = envelope;
        stripped.domain_separation.aead_aad_extensions = XExtensionMap::default();
        assert!(decrypt_key_backup_envelope(PASSPHRASE, &stripped).is_err());
    }

    #[test]
    fn empty_item_set_is_refused() {
        let kek = derive_vault_kek_with_salt(PASSPHRASE, &[7u8; VAULT_SALT_LEN]).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let sign = recording_signer(&seen);
        assert!(
            build_key_backup_envelope(
                "ak:backup:01964137-0000-7000-8000-000000000004"
                    .parse()
                    .unwrap(),
                actor(),
                Some(DEVICE.parse().unwrap()),
                BackupKind::SecretStorage,
                "kb_1",
                "recovery_vault",
                &kek,
                Vec::new(),
                &auth(),
                &sign,
            )
            .is_err()
        );
    }
}
