#![cfg(feature = "backup")]
//! Executable consumers for the key-backup cryptographic transcripts in
//! `fixtures/key-backup-hardening-fixture.json`.
use arkret_schema_conformance::spec_json_artifact;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE_PATH: &str = "fixtures/key-backup-hardening-fixture.json";
const UNLOCK_PROOF_VECTOR_ID: &str = "ak.vector.key_backup.unlock_proof.v1";
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
    let fixture = spec_json_artifact(FIXTURE_PATH).expect("embedded key-backup hardening fixture");
    let case = fixture["cases"]
        .as_array()
        .expect("fixture cases")
        .iter()
        .find(|case| case["name"].as_str() == Some("unlock_proof"))
        .expect("unlock_proof case present");
    assert_eq!(case["vector_id"].as_str(), Some(UNLOCK_PROOF_VECTOR_ID));

    let envelope = &case["envelope"];
    let transcript = &case["crypto_transcript"];
    let typed_envelope =
        serde_json::from_value(envelope.clone()).expect("fixture envelope is a typed KeyBackup");
    let aad = arkret_crypto::backup::key_backup_aead_aad(&typed_envelope)
        .expect("production envelope AAD canonicalizes");
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
