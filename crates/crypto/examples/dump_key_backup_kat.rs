//! Recompute the current key-backup unlock transcript without modifying the fixture.
use std::fs;

use arkret_canonical::{base64url_decode, base64url_encode, canonical_json_bytes};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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
        .find(|case| case["name"] == "unlock_proof")
        .expect("current unlock proof case");
    let envelope = &case["envelope"];
    let transcript = &case["crypto_transcript"];
    let actor: arkret_wire::ActorId =
        serde_json::from_value(envelope["actor_id"].clone()).expect("full ActorId");
    let created_at = arkret_canonical::format_timestamp_canonical(
        string(envelope, "created_at")
            .parse::<DateTime<Utc>>()
            .unwrap(),
    );
    let aad = canonical_json_bytes(&json!({
        "actor_id": actor,
        "backup_id": envelope["backup_id"],
        "backup_kind": envelope["backup_kind"],
        "created_at": created_at,
        "recipient_method": envelope["encryption"]["recipient_method"],
        "schema": "ak.schema.key_backup.v1",
        "series_id": envelope["series_id"],
        "series_seq": envelope["series_seq"],
    }))
    .unwrap();
    let plaintext = canonical_json_bytes(&case["plaintext"]).unwrap();
    let key = base64url_decode(string(transcript, "key_b64u")).unwrap();
    let nonce: [u8; 12] = base64url_decode(string(transcript, "nonce_b64u"))
        .unwrap()
        .try_into()
        .unwrap();
    let sealed = ChaCha20Poly1305::new_from_slice(&key)
        .unwrap()
        .encrypt(
            &nonce.into(),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .unwrap();
    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    let digest: String = Sha256::digest(&sealed)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "aad_canonical_json": String::from_utf8(aad).unwrap(),
            "plaintext_canonical_json": String::from_utf8(plaintext).unwrap(),
            "ciphertext_b64u": base64url_encode(ciphertext),
            "tag_b64u": base64url_encode(tag),
            "ciphertext_and_tag_b64u": base64url_encode(&sealed),
            "ciphertext_digest": format!("sha256:{digest}"),
        }))
        .unwrap()
    );
}
