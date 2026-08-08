#![cfg(feature = "backup")]
//! Executable consumers for the key-backup cryptographic transcripts in
//! `fixtures/key-backup-hardening-fixture.json`.
use arkret_schema::embedded_json_artifact;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FIXTURE_PATH: &str = "fixtures/key-backup-hardening-fixture.json";
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture field {key} must be a string"))
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
    assert_eq!(
        case["vector_id"].as_str(),
        Some(arkret_models_crypto::key_backup::VECTOR_ID_KEY_BACKUP_UNLOCK_PROOF)
    );

    let envelope = &case["envelope"];
    let transcript = &case["crypto_transcript"];
    let created_at = arkret_canonical::format_timestamp_canonical(
        DateTime::parse_from_rfc3339(str_field(envelope, "created_at"))
            .expect("envelope created_at parses")
            .with_timezone(&Utc),
    );
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

    let mut ciphertext_and_tag = ciphertext;
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
