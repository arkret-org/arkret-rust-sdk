#![cfg(feature = "backup")]
//! Executable consumers for the key-backup cryptographic transcripts in
//! `fixtures/key-backup-hardening-fixture.json`.
//!
//! The vector pins the full passphrase_kdf byte chain from
//! key-management.md §7.2: Argon2id (fixed params + salt) → HKDF-SHA256
//! subkeys (aead / nonce / commitment) → deterministic XChaCha20-Poly1305
//! nonce over the canonical nonce transcript → ciphertext, ciphertext digest
//! and key commitment. Every intermediate value is asserted so a drift in any
//! derivation stage is attributable, replacing the SDK's previous
//! self-certifying determinism tests with spec-anchored bytes.

use arkret_crypto::backup::{
    VAULT_AEAD_PROFILE, VaultBinding, commitment_digest, decrypt_vault, derive_subkey,
    derive_vault_kek_with_salt, encrypt_vault_with_nonce_salt,
};
use arkret_models_crypto::{BackupKind, KeyBackupDomainSeparationAad};
use arkret_schema::embedded_json_artifact;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FIXTURE_PATH: &str = "fixtures/key-backup-hardening-fixture.json";
const PASSPHRASE_VECTOR_ID: &str = "ak.vector.key_backup.passphrase_kdf_kat.v1";
const UNLOCK_VECTOR_ID: &str = "ak.vector.key_backup.unlock_proof.v1";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(input: &str) -> Vec<u8> {
    assert!(input.len().is_multiple_of(2), "hex string length");
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture field {key} must be a string"))
}

#[test]
fn passphrase_kdf_kat_reproduces_fixture_bytes() {
    let fixture =
        embedded_json_artifact(FIXTURE_PATH).expect("embedded key-backup hardening fixture");
    let case = fixture["cases"]
        .as_array()
        .expect("fixture cases")
        .iter()
        .find(|case| case["name"].as_str() == Some("passphrase_kdf_kat"))
        .expect("passphrase_kdf_kat case present");
    assert_eq!(case["vector_id"].as_str(), Some(PASSPHRASE_VECTOR_ID));

    let kat_cases = case["kat_cases"].as_array().expect("kat_cases array");
    assert_eq!(kat_cases.len(), 2, "KAT inventory pinned");
    for kat in kat_cases {
        run_kat(kat);
    }
}

#[test]
fn unlock_proof_kat_opens_to_the_declared_canonical_plaintext() {
    let fixture =
        embedded_json_artifact(FIXTURE_PATH).expect("embedded key-backup hardening fixture");
    let case = fixture["cases"]
        .as_array()
        .expect("fixture cases")
        .iter()
        .find(|case| case["name"].as_str() == Some("unlock_proof"))
        .expect("unlock_proof case present");
    assert_eq!(case["vector_id"].as_str(), Some(UNLOCK_VECTOR_ID));

    let envelope = &case["envelope"];
    let transcript = &case["crypto_transcript"];
    let created_at = DateTime::parse_from_rfc3339(str_field(envelope, "created_at"))
        .expect("envelope created_at parses")
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let aad_value = json!({
        "actor_id": envelope["actor_id"],
        "backup_id": envelope["backup_id"],
        "backup_kind": envelope["backup_kind"],
        "created_at": created_at,
        "recipient_method": envelope["encryption"]["recipient_method"],
        "schema": "ak.schema.key_backup.v1",
        "series_id": envelope["series_id"],
        "series_seq": envelope["series_seq"],
    });
    let aad = arkret_canonical::canonical_json_bytes(&aad_value).expect("AAD canonicalizes");
    assert_eq!(
        aad,
        str_field(transcript, "aad_canonical_json").as_bytes(),
        "unlock AAD must be the canonical envelope binding"
    );

    let plaintext = arkret_canonical::canonical_json_bytes(&case["plaintext"])
        .expect("plaintext canonicalizes");
    assert_eq!(
        plaintext,
        str_field(transcript, "plaintext_canonical_json").as_bytes(),
        "declared plaintext transcript must be canonical"
    );

    let key =
        arkret_canonical::base64url_decode(str_field(transcript, "key_b64u")).expect("key decodes");
    let nonce: [u8; 12] = arkret_canonical::base64url_decode(str_field(transcript, "nonce_b64u"))
        .expect("nonce decodes")
        .try_into()
        .expect("ChaCha20 nonce length");
    let ciphertext = arkret_canonical::base64url_decode(str_field(transcript, "ciphertext_b64u"))
        .expect("ciphertext decodes");
    let tag =
        arkret_canonical::base64url_decode(str_field(transcript, "tag_b64u")).expect("tag decodes");
    assert_eq!(
        ciphertext.len(),
        plaintext.len(),
        "ChaCha20 ciphertext and plaintext lengths must match"
    );
    assert_eq!(tag.len(), 16, "Poly1305 tag length");

    let mut ciphertext_and_tag = ciphertext.clone();
    ciphertext_and_tag.extend_from_slice(&tag);
    assert_eq!(
        arkret_canonical::base64url_encode(&ciphertext_and_tag),
        str_field(transcript, "ciphertext_and_tag_b64u")
    );
    assert_eq!(
        format!("sha256:{}", hex(&Sha256::digest(&ciphertext_and_tag))),
        str_field(transcript, "ciphertext_digest")
    );
    assert_eq!(
        envelope["ciphertext_digest"].as_str(),
        transcript["ciphertext_digest"].as_str()
    );

    let nonce = nonce.into();
    let opened = ChaCha20Poly1305::new_from_slice(&key)
        .expect("ChaCha20 key length")
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext_and_tag,
                aad: &aad,
            },
        )
        .expect("unlock transcript authenticates and opens");
    assert_eq!(opened, plaintext);
}

fn run_kat(kat: &Value) {
    let label = str_field(kat, "label");
    let input = &kat["input"];
    let mid = &kat["intermediate"];
    let expected = &kat["expected"];

    let passphrase = str_field(input, "passphrase_utf8");
    let salt: [u8; 16] = unhex(str_field(&input["argon2id"], "salt_hex"))
        .try_into()
        .expect("argon2id salt is 16 bytes");
    let nonce_salt: [u8; 16] = unhex(str_field(input, "nonce_salt_hex"))
        .try_into()
        .expect("nonce_salt is 16 bytes");
    let plaintext = str_field(input, "plaintext_utf8");

    let binding_json = &input["binding"];
    let backup_kind: BackupKind = serde_json::from_value(binding_json["backup_kind"].clone())
        .expect("fixture backup_kind parses");
    let binding = VaultBinding {
        backup_id: str_field(binding_json, "backup_id")
            .parse()
            .expect("backup_id parses"),
        subdomain: "aead".to_owned(),
        aead_aad: KeyBackupDomainSeparationAad {
            schema: "ak.schema.key_backup.v1".to_owned(),
            actor_id: str_field(binding_json, "actor_id")
                .parse()
                .expect("actor_id parses"),
            device_id: binding_json["device_id"].as_str().map(ToOwned::to_owned),
            backup_kind,
            backup_version: str_field(binding_json, "backup_version").to_owned(),
            created_at: str_field(binding_json, "created_at")
                .parse::<DateTime<Utc>>()
                .expect("created_at parses"),
            item_kinds: binding_json["item_kinds"]
                .as_array()
                .expect("item_kinds array")
                .iter()
                .map(|item| item.as_str().expect("item_kind string").to_owned())
                .collect(),
            managed_principal_bindings: vec![],
            recipient_method: None,
            recipient_key_ref: None,
            extra: Default::default(),
        },
    };

    // Stage 1: Argon2id root key.
    let kek = derive_vault_kek_with_salt(passphrase.as_bytes(), &salt).expect("kek derives");
    assert_eq!(
        hex(&kek.key),
        str_field(mid, "root_key_hex"),
        "{label}: Argon2id root key drift"
    );

    // Stage 2: HKDF-SHA256 subkeys (domain-separated per backup_kind).
    let subkeys = &mid["hkdf_sha256_subkeys"];
    assert_eq!(
        hex(&binding.subkey(&kek.key, "aead")),
        str_field(&subkeys["aead"], "subkey_hex"),
        "{label}: aead subkey drift"
    );
    assert_eq!(
        hex(&derive_subkey(&kek.key, b"arkret-key-backup-aead-nonce-v1")),
        str_field(&subkeys["nonce"], "subkey_hex"),
        "{label}: nonce subkey drift"
    );
    assert_eq!(
        hex(&binding.subkey(&kek.key, "commitment")),
        str_field(&subkeys["commitment"], "subkey_hex"),
        "{label}: commitment subkey drift"
    );
    assert_eq!(
        backup_kind.hkdf_info("aead"),
        str_field(&subkeys["aead"], "info"),
        "{label}: aead HKDF info drift"
    );
    assert_eq!(
        backup_kind.hkdf_info("commitment"),
        str_field(&subkeys["commitment"], "info"),
        "{label}: commitment HKDF info drift"
    );

    // Stage 3: deterministic AEAD encryption from the fixed nonce_salt.
    let ct = encrypt_vault_with_nonce_salt(&kek, &binding, plaintext.as_bytes(), &nonce_salt)
        .expect("encrypt succeeds");
    assert_eq!(
        ct.nonce_salt_b64,
        str_field(input, "nonce_salt_b64u"),
        "{label}: nonce_salt encoding drift"
    );
    assert_eq!(
        String::from_utf8(
            binding
                .nonce_transcript_canonical_bytes(&ct.nonce_salt_b64)
                .expect("nonce transcript")
        )
        .expect("transcript is UTF-8"),
        str_field(mid, "nonce_transcript_canonical_json"),
        "{label}: nonce transcript drift"
    );
    assert_eq!(
        String::from_utf8(binding.aad().expect("aad")).expect("aad is UTF-8"),
        str_field(mid, "aead_aad_canonical_json"),
        "{label}: AEAD AAD drift"
    );
    assert_eq!(
        hex(&ct.nonce),
        str_field(expected, "nonce_hex"),
        "{label}: deterministic nonce drift"
    );
    assert_eq!(
        ct.nonce_b64,
        str_field(expected, "nonce_b64u"),
        "{label}: nonce encoding drift"
    );
    assert_eq!(
        ct.ciphertext_b64,
        str_field(expected, "ciphertext_b64u"),
        "{label}: ciphertext drift"
    );
    assert_eq!(
        format!("sha256:{}", hex(&Sha256::digest(&ct.ciphertext))),
        str_field(expected, "ciphertext_digest"),
        "{label}: ciphertext digest drift"
    );

    // Stage 4: key commitment.
    assert_eq!(
        format!("sha256:{}", hex(&commitment_digest(&kek.key, backup_kind))),
        str_field(expected, "key_commitment"),
        "{label}: key commitment drift"
    );
    assert_eq!(
        str_field(expected, "aead_profile"),
        VAULT_AEAD_PROFILE,
        "{label}: AEAD profile drift"
    );

    // Round trip: the recorded envelope views decrypt back to the plaintext.
    let recovered = decrypt_vault(
        passphrase.as_bytes(),
        &binding,
        &ct.salt_b64,
        &ct.nonce_b64,
        &ct.nonce_salt_b64,
        &ct.ciphertext_b64,
    )
    .expect("round trip decrypts");
    assert_eq!(
        &*recovered,
        plaintext.as_bytes(),
        "{label}: round-trip plaintext drift"
    );
}
