//! Shared authenticated encryption helpers.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub const AEAD_ALGORITHM: &str = "xchacha20poly1305-sha256-key-v1";
pub const ENCRYPTED_ENVELOPE_AAD_CONTEXT: &str = "contrix-encrypted-envelope-aad-v1";
const NONCE_LEN: usize = 24;

/// Canonical AAD shape for encrypted timeline and operation envelopes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelopeAad {
    pub space_id: String,
    pub event_type: String,
    pub event_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causal_refs: Vec<String>,
}

/// Digest report used by callers that store AAD digest separately from ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelopeDigestReport {
    pub ciphertext_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad_sha256: Option<String>,
}

/// Security review status for internal pre-audit checklists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityReviewStatus {
    Planned,
    Modeled,
    Tested,
    ExternalAuditRequired,
}

/// Structured security review item mapped to SDK source and tests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityReviewItem {
    pub area: String,
    pub source_files: Vec<String>,
    pub test_targets: Vec<String>,
    pub status: SecurityReviewStatus,
    pub notes: String,
}

/// Key lifecycle phase modeled by SDK crypto helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyLifecyclePhase {
    Created,
    Published,
    Used,
    Rotated,
    BackedUp,
    Recovered,
    Revoked,
    Destroyed,
}

/// Hook record for applications that mirror key lifecycle events into audit logs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyLifecycleHook {
    pub key_ref: String,
    pub phase: KeyLifecyclePhase,
    pub actor: String,
    pub reason: String,
}

/// Encrypt plaintext with XChaCha20-Poly1305 using the given key material and AAD.
///
/// The key material is hashed with SHA-256 before use. The output contains the
/// 24-byte nonce followed by the AEAD ciphertext+tag.
#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, fields(plaintext_len = plaintext.len())))]
pub fn seal(plaintext: &[u8], key_material: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = Sha256::digest(key_material);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|error| Error::Crypto(error.to_string()))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto("AEAD encryption failed".to_owned()))?;
    let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Decrypt an AEAD envelope produced by `seal`.
#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, fields(envelope_len = envelope.len())))]
pub fn open(envelope: &[u8], key_material: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() < NONCE_LEN {
        return Err(Error::Crypto("AEAD envelope is shorter than nonce".to_owned()));
    }
    let (nonce, ciphertext) = envelope.split_at(NONCE_LEN);
    let key = Sha256::digest(key_material);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Crypto("AEAD decryption failed".to_owned()))
}

/// Canonicalize encrypted-envelope AAD and bind it to a domain-separated context.
pub fn canonical_envelope_aad(aad: &EncryptedEnvelopeAad) -> Result<Vec<u8>> {
    let mut bytes = ENCRYPTED_ENVELOPE_AAD_CONTEXT.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&crate::canonical::canonical_json_bytes(aad)?);
    Ok(bytes)
}

/// Compute a SHA-256 digest over canonical encrypted-envelope AAD.
pub fn envelope_aad_digest(aad: &EncryptedEnvelopeAad) -> Result<String> {
    Ok(sha256_prefixed(&canonical_envelope_aad(aad)?))
}

/// Compute a SHA-256 digest over arbitrary JSON AAD using canonical JSON.
pub fn json_aad_digest(aad: &Value) -> Result<String> {
    let mut bytes = ENCRYPTED_ENVELOPE_AAD_CONTEXT.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&crate::canonical::canonical_json_bytes(aad)?);
    Ok(sha256_prefixed(&bytes))
}

/// Fail closed if the supplied AAD digest does not match the canonical AAD.
pub fn verify_envelope_aad_digest(aad: &EncryptedEnvelopeAad, expected: &str) -> Result<()> {
    let actual = envelope_aad_digest(aad)?;
    if constant_time_eq(&actual, expected) {
        Ok(())
    } else {
        Err(Error::Protocol("encrypted envelope AAD digest mismatch".to_owned()))
    }
}

/// Produce ciphertext and optional AAD digests for encrypted-envelope compliance checks.
pub fn encrypted_envelope_digest_report(
    ciphertext: &[u8],
    aad: Option<&EncryptedEnvelopeAad>,
) -> Result<EncryptedEnvelopeDigestReport> {
    Ok(EncryptedEnvelopeDigestReport {
        ciphertext_sha256: sha256_prefixed(ciphertext),
        aad_sha256: aad.map(envelope_aad_digest).transpose()?,
    })
}

/// Baseline internal checklist. This is not an external audit attestation.
pub fn security_review_checklist() -> Vec<SecurityReviewItem> {
    vec![
        SecurityReviewItem {
            area: "encrypted envelope compliance".to_owned(),
            source_files: vec!["crypto.rs".to_owned(), "mls.rs".to_owned(), "e2ee.rs".to_owned()],
            test_targets: vec![
                "crypto::tests::encrypted_envelope_aad_digest_is_canonical".to_owned(),
                "mls::tests::message_crypto_encrypts_with_aad_and_verifies_digest".to_owned(),
            ],
            status: SecurityReviewStatus::Tested,
            notes: "payload and AAD digests are modeled and verified before decrypt".to_owned(),
        },
        SecurityReviewItem {
            area: "key lifecycle".to_owned(),
            source_files: vec!["e2ee.rs".to_owned(), "devices.rs".to_owned(), "mls.rs".to_owned()],
            test_targets: vec![
                "e2ee::tests::e2ee_restores_key_records_and_rejects_wrong_sender".to_owned(),
                "devices::tests::devices_rotate_and_validate_authenticated_key_backups".to_owned(),
            ],
            status: SecurityReviewStatus::Modeled,
            notes: "creation, publication, rotation, backup, recovery and revocation hooks exist"
                .to_owned(),
        },
        SecurityReviewItem {
            area: "external audit".to_owned(),
            source_files: Vec::new(),
            test_targets: Vec::new(),
            status: SecurityReviewStatus::ExternalAuditRequired,
            notes: "external review remains intentionally unclaimed by SDK tests".to_owned(),
        },
    ]
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();

    for idx in 0..max_len {
        let left_byte = left.get(idx).copied().unwrap_or(0);
        let right_byte = right.get(idx).copied().unwrap_or(0);
        diff |= (left_byte ^ right_byte) as usize;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_seal_open_roundtrips_and_authenticates_aad() {
        let sealed = seal(b"secret", b"passphrase", b"context").unwrap();
        assert_ne!(sealed, b"secret");
        assert_eq!(open(&sealed, b"passphrase", b"context").unwrap(), b"secret");
        assert!(open(&sealed, b"passphrase", b"wrong-context").is_err());
    }

    #[test]
    fn encrypted_envelope_aad_digest_is_canonical() {
        let aad = EncryptedEnvelopeAad {
            space_id: "cx:space:01JS0SP000000000000000000".to_owned(),
            event_type: "cx.message.create".to_owned(),
            event_id: "cx:event:01JS0EV000000000000000000".to_owned(),
            causal_refs: vec!["cx:event:01JS0PARENT0000000000000".to_owned()],
        };
        let digest = envelope_aad_digest(&aad).unwrap();
        verify_envelope_aad_digest(&aad, &digest).unwrap();
        assert!(verify_envelope_aad_digest(&aad, "sha256:bad").is_err());

        let report = encrypted_envelope_digest_report(b"ciphertext", Some(&aad)).unwrap();
        assert_eq!(report.aad_sha256, Some(digest));
        assert!(report.ciphertext_sha256.starts_with("sha256:"));
    }

    #[test]
    fn security_review_checklist_does_not_claim_external_audit() {
        let checklist = security_review_checklist();
        assert!(checklist.iter().any(|item| {
            item.area == "external audit"
                && item.status == SecurityReviewStatus::ExternalAuditRequired
        }));
    }

    // Property-style tests: exercise many inputs to verify invariants.

    #[test]
    fn seal_open_roundtrips_for_various_plaintext_sizes() {
        let key = b"test-key-material-for-property-tests";
        let aad = b"test-aad";
        // Test a range of plaintext sizes including edge cases.
        let sizes: Vec<usize> = vec![0, 1, 15, 16, 17, 23, 31, 32, 63, 64, 127, 128, 255, 256, 512, 1024];
        for size in sizes {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let sealed = seal(&plaintext, key, aad).unwrap();
            assert!(sealed.len() > plaintext.len(), "sealed must be larger than plaintext for size {size}");
            let opened = open(&sealed, key, aad).unwrap();
            assert_eq!(opened, plaintext, "roundtrip failed for plaintext size {size}");
        }
    }

    #[test]
    fn seal_open_roundtrips_for_various_key_materials() {
        let aad = b"aad";
        let plaintext = b"fixed plaintext for key variation test";
        // Test various key material lengths.
        let keys: Vec<Vec<u8>> = vec![
            vec![0u8; 1],
            vec![0u8; 16],
            vec![0u8; 32],
            vec![0xffu8; 32],
            vec![0u8; 64],
            (0..128u8).collect(),
        ];
        for key in &keys {
            let sealed = seal(plaintext, key, aad).unwrap();
            let opened = open(&sealed, key, aad).unwrap();
            assert_eq!(opened, plaintext, "roundtrip failed for key length {}", key.len());
        }
    }

    #[test]
    fn seal_open_roundtrips_for_various_aad_values() {
        let key = b"test-key";
        let plaintext = b"plaintext with varying AAD";
        let aads: Vec<Vec<u8>> = vec![
            vec![],
            vec![0],
            b"context".to_vec(),
            b"longer-context-with-special-chars!@#$".to_vec(),
            vec![0xffu8; 256],
        ];
        for aad in &aads {
            let sealed = seal(plaintext, key, aad).unwrap();
            let opened = open(&sealed, key, aad).unwrap();
            assert_eq!(opened, plaintext, "roundtrip failed for AAD length {}", aad.len());
        }
    }

    #[test]
    fn seal_produces_unique_ciphertext_for_same_input() {
        let key = b"test-key";
        let aad = b"aad";
        let plaintext = b"same plaintext";
        let sealed1 = seal(plaintext, key, aad).unwrap();
        let sealed2 = seal(plaintext, key, aad).unwrap();
        // Different nonces should produce different ciphertexts.
        assert_ne!(sealed1, sealed2, "two seals of the same plaintext must differ (unique nonce)");
        // Both should decrypt to the same plaintext.
        assert_eq!(open(&sealed1, key, aad).unwrap(), plaintext);
        assert_eq!(open(&sealed2, key, aad).unwrap(), plaintext);
    }

    #[test]
    fn open_fails_on_tampered_ciphertext() {
        let key = b"test-key";
        let aad = b"aad";
        let plaintext = b"integrity test";
        let mut sealed = seal(plaintext, key, aad).unwrap();
        // Tamper with a byte in the ciphertext portion (after the 24-byte nonce).
        if sealed.len() > 25 {
            sealed[25] ^= 0xff;
        }
        assert!(open(&sealed, key, aad).is_err(), "tampered ciphertext must fail to open");
    }

    #[test]
    fn open_fails_on_truncated_envelope() {
        let key = b"test-key";
        let aad = b"aad";
        let sealed = seal(b"test", key, aad).unwrap();
        // Truncate to less than nonce length.
        for len in 0..NONCE_LEN {
            assert!(open(&sealed[..len], key, aad).is_err(), "truncated envelope of length {len} must fail");
        }
    }

    #[test]
    fn canonical_digest_is_deterministic_for_same_input() {
        let aad = EncryptedEnvelopeAad {
            space_id: "cx:space:test".to_owned(),
            event_type: "cx.message.create".to_owned(),
            event_id: "cx:event:test".to_owned(),
            causal_refs: vec![],
        };
        let digest1 = envelope_aad_digest(&aad).unwrap();
        let digest2 = envelope_aad_digest(&aad).unwrap();
        assert_eq!(digest1, digest2, "canonical digest must be deterministic");
        assert!(digest1.starts_with("sha256:"));
    }

    #[test]
    fn canonical_digest_differs_for_different_inputs() {
        let aad1 = EncryptedEnvelopeAad {
            space_id: "cx:space:A".to_owned(),
            event_type: "cx.message.create".to_owned(),
            event_id: "cx:event:1".to_owned(),
            causal_refs: vec![],
        };
        let aad2 = EncryptedEnvelopeAad {
            space_id: "cx:space:B".to_owned(),
            event_type: "cx.message.create".to_owned(),
            event_id: "cx:event:1".to_owned(),
            causal_refs: vec![],
        };
        let digest1 = envelope_aad_digest(&aad1).unwrap();
        let digest2 = envelope_aad_digest(&aad2).unwrap();
        assert_ne!(digest1, digest2, "different AADs must produce different digests");
    }

    #[test]
    fn constant_time_eq_matches_standard_equality() {
        let pairs: Vec<(&str, &str)> = vec![
            ("", ""),
            ("a", "a"),
            ("abc", "abc"),
            ("abc", "abd"),
            ("abc", "ab"),
            ("", "a"),
        ];
        for (left, right) in pairs {
            let ct_result = constant_time_eq(left, right);
            let eq_result = left == right;
            assert_eq!(ct_result, eq_result, "constant_time_eq({left:?}, {right:?}) != standard ==");
        }
    }
}
