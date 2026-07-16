use std::fs;

use arkret_core::BackupClass;
use arkret_crypto::backup::{
    KeyBackupDomainSeparationAad, VaultBinding, commitment_digest, derive_subkey,
    derive_vault_kek_with_salt, encrypt_vault_with_nonce_salt,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).unwrap())
        .collect()
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

fn main() {
    let path = std::env::args().nth(1).expect("fixture path");
    let fixture: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "passphrase_kdf_kat")
        .unwrap();
    let mut output = Vec::new();

    for kat in case["kat_cases"].as_array().unwrap() {
        let input = &kat["input"];
        let binding_json = &input["binding"];
        let backup_class: BackupClass =
            serde_json::from_value(binding_json["backup_class"].clone()).unwrap();
        let binding = VaultBinding {
            backup_id: string(binding_json, "backup_id").parse().unwrap(),
            aead_aad: KeyBackupDomainSeparationAad {
                actor_id: string(binding_json, "actor_id").parse().unwrap(),
                device_id: binding_json["device_id"]
                    .as_str()
                    .map(|value| value.parse().unwrap()),
                backup_class,
                backup_version: string(binding_json, "backup_version").to_owned(),
                created_at: string(binding_json, "created_at")
                    .parse::<DateTime<Utc>>()
                    .unwrap(),
                item_types: binding_json["item_types"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect(),
                recipient_actor_id: None,
                extra: Default::default(),
            },
        };
        let salt: [u8; 16] = unhex(string(&input["argon2id"], "salt_hex"))
            .try_into()
            .unwrap();
        let nonce_salt: [u8; 16] = unhex(string(input, "nonce_salt_hex")).try_into().unwrap();
        let kek =
            derive_vault_kek_with_salt(string(input, "passphrase_utf8").as_bytes(), &salt).unwrap();
        let ciphertext = encrypt_vault_with_nonce_salt(
            &kek,
            &binding,
            string(input, "plaintext_utf8").as_bytes(),
            &nonce_salt,
        )
        .unwrap();
        output.push(json!({
            "label": string(kat, "label"),
            "intermediate": {
                "root_key_hex": hex(&kek.key),
                "hkdf_sha256_subkeys": {
                    "aead": {
                        "info": backup_class.hkdf_info("aead"),
                        "subkey_hex": hex(&binding.subkey(&kek.key, "aead")),
                    },
                    "nonce": {
                        "info": "arkret-key-backup-aead-nonce-v1",
                        "subkey_hex": hex(&derive_subkey(
                            &kek.key,
                            b"arkret-key-backup-aead-nonce-v1",
                        )),
                    },
                    "commitment": {
                        "info": backup_class.hkdf_info("commitment"),
                        "subkey_hex": hex(&binding.subkey(&kek.key, "commitment")),
                    },
                },
                "nonce_transcript_canonical_json": String::from_utf8(
                    binding
                        .nonce_transcript_canonical_bytes(&ciphertext.nonce_salt_b64)
                        .unwrap(),
                )
                .unwrap(),
                "aead_aad_canonical_json": String::from_utf8(binding.aad().unwrap()).unwrap(),
            },
            "expected": {
                "aead": "xchacha20_poly1305",
                "aead_profile": "ak.aead.xchacha20_poly1305.v1",
                "nonce_hex": hex(&ciphertext.nonce),
                "nonce_b64u": ciphertext.nonce_b64,
                "ciphertext_b64u": ciphertext.ciphertext_b64,
                "ciphertext_digest": format!(
                    "sha256:{}",
                    hex(&Sha256::digest(&ciphertext.ciphertext)),
                ),
                "key_commitment": format!(
                    "sha256:{}",
                    hex(&commitment_digest(&kek.key, backup_class)),
                ),
            },
        }));
    }

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
