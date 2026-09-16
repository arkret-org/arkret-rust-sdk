//! Client-side passphrase crypto primitives for `ak.schema.key_backup.v1`.
//!
//! This module deliberately stops below envelope assembly and signing. The
//! caller first fixes current authorization metadata, then constructs the
//! typed envelope from these ciphertext outputs.

use argon2::{Algorithm, Argon2, Params, Version};
use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use arkret_canonical::canonical::{
    canonical_json_bytes, format_timestamp_canonical, sha256_digest,
};
use arkret_models_crypto::key_backup::{BackupKind, KeyBackupRecipientMethod};
use arkret_wire::{ActorId, BackupId, DeviceId, XExtensionMap};
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
    })
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
    let nonce: [u8; VAULT_NONCE_LEN] = base64url_decode(nonce_b64.trim_end_matches('='))
        .map_err(|error| KeyBackupError::Encoding(format!("nonce base64: {error}")))?
        .try_into()
        .map_err(|_| KeyBackupError::Encoding(format!("nonce must be {VAULT_NONCE_LEN} bytes")))?;
    let ciphertext = base64url_decode(ciphertext_b64.trim_end_matches('='))
        .map_err(|error| KeyBackupError::Encoding(format!("ciphertext base64: {error}")))?;
    let kek = derive_vault_kek_with_salt(passphrase, &salt)?;
    if binding.derive_nonce(&kek.key, nonce_salt_b64)? != nonce {
        return Err(KeyBackupError::Aead(
            "vault decrypt failed: nonce derivation mismatch".to_owned(),
        ));
    }

    let mut aead_key = binding.subkey(&kek.key, &binding.subdomain);
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
}
