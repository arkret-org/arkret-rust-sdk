//! Client-side encryption for principal-private Account Data values.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

use crate::{Error, Result};

pub const ACCOUNT_DATA_ENCRYPTED_VALUE_SCHEMA: &str = "ak.schema.account_data_encrypted_value.v1";
pub const ACCOUNT_DATA_ENCRYPTED_VALUE_VERSION: &str = "1.0";
pub const ACCOUNT_DATA_AEAD_PROFILE: &str = "ak.aead.xchacha20_poly1305.v1";
const ACCOUNT_DATA_HKDF_SALT: &[u8] = b"arkret-account-data-value-hkdf-v1";
const ACCOUNT_DATA_NONCE_LEN: usize = 24;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDataEncryptedValueAad {
    pub schema: String,
    pub version: String,
    pub actor_id: String,
    pub data_type: String,
}

impl AccountDataEncryptedValueAad {
    pub fn new(actor_id: impl Into<String>, data_type: impl Into<String>) -> Self {
        Self {
            schema: ACCOUNT_DATA_ENCRYPTED_VALUE_SCHEMA.to_owned(),
            version: ACCOUNT_DATA_ENCRYPTED_VALUE_VERSION.to_owned(),
            actor_id: actor_id.into(),
            data_type: data_type.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDataEncryptedValue {
    pub schema: String,
    pub version: String,
    pub aead_profile: String,
    pub key_ref: String,
    pub nonce: String,
    pub ciphertext: String,
    pub aad: AccountDataEncryptedValueAad,
    pub aad_digest: String,
    pub ciphertext_digest: String,
}

fn protocol_error(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}

fn validate_actor_and_data_type(actor_id: &str, data_type: &str) -> Result<()> {
    let actor_id = actor_id.trim();
    if !actor_id.starts_with("did:") || actor_id.chars().any(char::is_whitespace) {
        return Err(protocol_error("account-data actor_id must be a DID"));
    }
    let pattern = Regex::new(r"^ak\.[a-z0-9_]+(?:\.[a-z0-9_]+)*(?::[A-Za-z0-9_-]+)?$")
        .map_err(|error| Error::Protocol(format!("account-data type regex: {error}")))?;
    if !pattern.is_match(data_type) {
        return Err(protocol_error("account-data data_type is not canonical"));
    }
    Ok(())
}

fn canonical_aad(aad: &AccountDataEncryptedValueAad) -> Result<Vec<u8>> {
    crate::canonical::canonical_json_bytes(aad)
}

pub fn derive_account_data_value_key(
    account_secret: &[u8; 32],
    actor_id: &str,
    data_type: &str,
) -> Result<[u8; 32]> {
    validate_actor_and_data_type(actor_id, data_type)?;
    let info = crate::canonical::canonical_json_bytes(&serde_json::json!({
        "schema": ACCOUNT_DATA_ENCRYPTED_VALUE_SCHEMA,
        "actor_id": actor_id,
        "data_type": data_type,
    }))?;
    let hkdf = Hkdf::<Sha256>::new(Some(ACCOUNT_DATA_HKDF_SALT), account_secret);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| Error::Crypto("account-data HKDF expansion failed".to_owned()))?;
    Ok(key)
}

pub fn seal_account_data_value(
    account_secret: &[u8; 32],
    actor_id: &str,
    data_type: &str,
    plaintext: &Value,
) -> Result<AccountDataEncryptedValue> {
    let mut nonce = [0u8; ACCOUNT_DATA_NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|error| Error::Crypto(format!("account-data nonce generation failed: {error}")))?;
    seal_account_data_value_with_nonce(account_secret, actor_id, data_type, plaintext, nonce)
}

pub fn seal_account_data_value_with_nonce(
    account_secret: &[u8; 32],
    actor_id: &str,
    data_type: &str,
    plaintext: &Value,
    nonce: [u8; ACCOUNT_DATA_NONCE_LEN],
) -> Result<AccountDataEncryptedValue> {
    let key = derive_account_data_value_key(account_secret, actor_id, data_type)?;
    let aad = AccountDataEncryptedValueAad::new(actor_id, data_type);
    let aad_bytes = canonical_aad(&aad)?;
    let plaintext_bytes = crate::canonical::canonical_json_bytes(plaintext)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|error| Error::Crypto(format!("account-data cipher init failed: {error}")))?;
    let nonce_value = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce_value,
            Payload {
                msg: &plaintext_bytes,
                aad: &aad_bytes,
            },
        )
        .map_err(|error| Error::Crypto(format!("account-data encryption failed: {error}")))?;
    Ok(AccountDataEncryptedValue {
        schema: ACCOUNT_DATA_ENCRYPTED_VALUE_SCHEMA.to_owned(),
        version: ACCOUNT_DATA_ENCRYPTED_VALUE_VERSION.to_owned(),
        aead_profile: ACCOUNT_DATA_AEAD_PROFILE.to_owned(),
        key_ref: crate::canonical::sha256_digest(&key),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(&ciphertext),
        aad,
        aad_digest: crate::canonical::sha256_digest(&aad_bytes),
        ciphertext_digest: crate::canonical::sha256_digest(&ciphertext),
    })
}

pub fn validate_account_data_encrypted_value(
    value: &AccountDataEncryptedValue,
    expected_actor_id: &str,
    expected_data_type: &str,
) -> Result<()> {
    validate_actor_and_data_type(expected_actor_id, expected_data_type)?;
    if value.schema != ACCOUNT_DATA_ENCRYPTED_VALUE_SCHEMA
        || value.version != ACCOUNT_DATA_ENCRYPTED_VALUE_VERSION
        || value.aead_profile != ACCOUNT_DATA_AEAD_PROFILE
        || value.aad.schema != ACCOUNT_DATA_ENCRYPTED_VALUE_SCHEMA
        || value.aad.version != ACCOUNT_DATA_ENCRYPTED_VALUE_VERSION
    {
        return Err(protocol_error(
            "unsupported account-data encrypted value envelope",
        ));
    }
    if value.aad.actor_id != expected_actor_id || value.aad.data_type != expected_data_type {
        return Err(protocol_error(
            "account-data encrypted value AAD binding mismatch",
        ));
    }
    let nonce = B64
        .decode(&value.nonce)
        .map_err(|error| protocol_error(format!("account-data nonce base64url: {error}")))?;
    if nonce.len() != ACCOUNT_DATA_NONCE_LEN {
        return Err(protocol_error("account-data nonce must be 24 bytes"));
    }
    let ciphertext = B64
        .decode(&value.ciphertext)
        .map_err(|error| protocol_error(format!("account-data ciphertext base64url: {error}")))?;
    if ciphertext.len() < 16 {
        return Err(protocol_error(
            "account-data ciphertext is shorter than the AEAD tag",
        ));
    }
    let aad_bytes = canonical_aad(&value.aad)?;
    if value.aad_digest != crate::canonical::sha256_digest(&aad_bytes) {
        return Err(protocol_error("account-data AAD digest mismatch"));
    }
    if value.ciphertext_digest != crate::canonical::sha256_digest(&ciphertext) {
        return Err(protocol_error("account-data ciphertext digest mismatch"));
    }
    Ok(())
}

pub fn open_account_data_value(
    account_secret: &[u8; 32],
    expected_actor_id: &str,
    expected_data_type: &str,
    value: &AccountDataEncryptedValue,
) -> Result<Value> {
    validate_account_data_encrypted_value(value, expected_actor_id, expected_data_type)?;
    let key = derive_account_data_value_key(account_secret, expected_actor_id, expected_data_type)?;
    if value.key_ref != crate::canonical::sha256_digest(&key) {
        return Err(protocol_error("account-data key_ref mismatch"));
    }
    let nonce = B64
        .decode(&value.nonce)
        .map_err(|error| protocol_error(format!("account-data nonce base64url: {error}")))?;
    let nonce: [u8; ACCOUNT_DATA_NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| protocol_error("account-data nonce must be 24 bytes"))?;
    let ciphertext = B64
        .decode(&value.ciphertext)
        .map_err(|error| protocol_error(format!("account-data ciphertext base64url: {error}")))?;
    let aad_bytes = canonical_aad(&value.aad)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|error| Error::Crypto(format!("account-data cipher init failed: {error}")))?;
    let nonce_value = XNonce::from(nonce);
    let plaintext = cipher
        .decrypt(
            &nonce_value,
            Payload {
                msg: &ciphertext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| Error::Crypto("account-data authentication failed".to_owned()))?;
    serde_json::from_slice(&plaintext)
        .map_err(|error| protocol_error(format!("account-data plaintext JSON: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTOR: &str = "did:webvh:z6mkfixture:alice.example";
    const DATA_TYPE: &str = "ak.dnd_schedule";

    #[test]
    fn account_data_value_round_trips_and_is_not_plaintext() {
        let secret = [7u8; 32];
        let plaintext = serde_json::json!({"dnd":{"enabled":true}});
        let envelope =
            seal_account_data_value_with_nonce(&secret, ACTOR, DATA_TYPE, &plaintext, [9u8; 24])
                .unwrap();
        assert!(!envelope.ciphertext.contains("enabled"));
        assert_eq!(
            open_account_data_value(&secret, ACTOR, DATA_TYPE, &envelope).unwrap(),
            plaintext
        );
    }

    #[test]
    fn account_data_value_rejects_tamper_and_cross_domain_open() {
        let secret = [11u8; 32];
        let plaintext = serde_json::json!({"dnd":{"enabled":true}});
        let envelope =
            seal_account_data_value_with_nonce(&secret, ACTOR, DATA_TYPE, &plaintext, [13u8; 24])
                .unwrap();
        assert!(open_account_data_value(&secret, ACTOR, "ak.push_rules", &envelope).is_err());
        assert!(open_account_data_value(&[12u8; 32], ACTOR, DATA_TYPE, &envelope,).is_err());
        let mut tampered = envelope;
        tampered.ciphertext.push('A');
        assert!(open_account_data_value(&secret, ACTOR, DATA_TYPE, &tampered).is_err());
    }
}
