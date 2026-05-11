//! Shared authenticated encryption helpers.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub const AEAD_ALGORITHM: &str = "xchacha20poly1305-sha256-key-v1";
pub const ENCRYPTED_ENVELOPE_AAD_CONTEXT: &str = "contrix-encrypted-envelope-aad-v1";
pub const REDACTED_SECRET: &str = "<redacted>";
const NONCE_LEN: usize = 24;

/// Canonical AAD shape for encrypted timeline and operation envelopes.
///
/// Wire form per `crypto-media/encrypted-envelope-schema.md` §2: the
/// canonical field name is `event_kind`. `event_type` is accepted on input
/// for backward compatibility (deprecated) but is **never** emitted on
/// serialization, and an envelope that carries both `event_kind` and a
/// non-matching `event_type` is rejected on deserialization with
/// `aad_ambiguous_kind`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EncryptedEnvelopeAad {
    pub space_id: String,
    /// Canonical event kind (`cx.<category>.<verb>`). Wire field name
    /// `event_kind`; legacy decoders that wrote `event_type` are accepted
    /// on input.
    #[serde(rename = "event_kind")]
    pub event_kind: String,
    pub event_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causal_refs: Vec<String>,
}

impl<'de> Deserialize<'de> for EncryptedEnvelopeAad {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            space_id: String,
            #[serde(default)]
            event_kind: Option<String>,
            #[serde(default)]
            event_type: Option<String>,
            event_id: String,
            #[serde(default)]
            causal_refs: Vec<String>,
        }
        let r = Repr::deserialize(deserializer)?;
        let event_kind = match (r.event_kind, r.event_type) {
            (Some(k), None) => k,
            (None, Some(t)) => t,
            (Some(k), Some(t)) if k == t => k,
            (Some(_), Some(_)) => {
                return Err(serde::de::Error::custom(
                    "aad_ambiguous_kind: event_kind and event_type both set with different values",
                ));
            }
            (None, None) => {
                return Err(serde::de::Error::missing_field("event_kind"));
            }
        };
        Ok(EncryptedEnvelopeAad {
            space_id: r.space_id,
            event_kind,
            event_id: r.event_id,
            causal_refs: r.causal_refs,
        })
    }
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

/// Feature combinations rejected by the SDK security review.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsafeFeatureCombination {
    MlsWithoutFullSurface,
    ServerWithoutFullSurface,
    SalvoWithoutServer,
    RuntimeWithoutFullSurface,
}

/// Security review result for a Cargo feature set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureSafetyReport {
    pub enabled_features: Vec<String>,
    pub violations: Vec<UnsafeFeatureCombination>,
}

impl FeatureSafetyReport {
    pub fn validate(&self) -> Result<()> {
        if self.violations.is_empty() {
            Ok(())
        } else {
            Err(Error::Protocol(format!("unsafe Cargo feature combination: {:?}", self.violations)))
        }
    }
}

/// Evaluate a Cargo feature set for combinations that should never be published.
pub fn feature_safety_report<I, S>(features: I) -> FeatureSafetyReport
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut enabled_features =
        features.into_iter().map(|feature| feature.as_ref().to_owned()).collect::<Vec<_>>();
    enabled_features.sort();
    enabled_features.dedup();

    let has = |feature: &str| enabled_features.iter().any(|enabled| enabled == feature);
    let mut violations = Vec::new();
    if has("mls") && !has("full-surface") {
        violations.push(UnsafeFeatureCombination::MlsWithoutFullSurface);
    }
    if has("server") && !has("full-surface") {
        violations.push(UnsafeFeatureCombination::ServerWithoutFullSurface);
    }
    if has("salvo") && !has("server") {
        violations.push(UnsafeFeatureCombination::SalvoWithoutServer);
    }
    if ["applet-runtime", "device-runtime", "sync-runtime", "timeline-runtime"]
        .iter()
        .any(|feature| has(feature))
        && !has("full-surface")
    {
        violations.push(UnsafeFeatureCombination::RuntimeWithoutFullSurface);
    }

    FeatureSafetyReport { enabled_features, violations }
}

/// Evaluate the feature set compiled into this crate.
pub fn current_feature_safety_report() -> FeatureSafetyReport {
    let mut features = Vec::new();
    if cfg!(feature = "client") {
        features.push("client");
    }
    if cfg!(feature = "server") {
        features.push("server");
    }
    if cfg!(feature = "mls") {
        features.push("mls");
    }
    if cfg!(feature = "full-surface") {
        features.push("full-surface");
    }
    if cfg!(feature = "tracing") {
        features.push("tracing");
    }
    if cfg!(feature = "salvo") {
        features.push("salvo");
    }
    if cfg!(feature = "applet-runtime") {
        features.push("applet-runtime");
    }
    if cfg!(feature = "device-runtime") {
        features.push("device-runtime");
    }
    if cfg!(feature = "sync-runtime") {
        features.push("sync-runtime");
    }
    if cfg!(feature = "timeline-runtime") {
        features.push("timeline-runtime");
    }
    feature_safety_report(features)
}

/// Whether a field name can contain credential, token, proof or signature data.
pub fn is_sensitive_log_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "access_token"
            | "authorization"
            | "bearer"
            | "code"
            | "device_proof"
            | "grant_jwt"
            | "id_token"
            | "jws"
            | "password"
            | "password_hash"
            | "private_key"
            | "proof"
            | "refresh_token"
            | "reset_token"
            | "secret"
            | "service_signature"
            | "session_token"
            | "signature"
            | "token"
    ) || key.ends_with("_token")
        || key.ends_with("_secret")
        || key.ends_with("_signature")
        || key.ends_with("_proof")
}

/// Redact sensitive fields from a structured value before logging.
pub fn redact_log_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| {
                    if is_sensitive_log_key(key) {
                        (key.clone(), Value::String(REDACTED_SECRET.to_owned()))
                    } else {
                        (key.clone(), redact_log_value(value))
                    }
                })
                .collect::<Map<_, _>>(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact_log_value).collect()),
        _ => value.clone(),
    }
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
            area: "canonical signing/proof binding".to_owned(),
            source_files: vec!["canonical.rs".to_owned(), "model.rs".to_owned()],
            test_targets: vec![
                "model::tests::signature_binding_payload_matches_canonical_vector".to_owned(),
                "model::tests::proof_validate_binding_rejects_mismatched_payload_hash".to_owned(),
                "model::tests::proof_validate_production_rejects_dev_kinds".to_owned(),
            ],
            status: SecurityReviewStatus::Tested,
            notes: "signed payloads use canonical JSON and reject alg:none/dev proof kinds"
                .to_owned(),
        },
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
            area: "MLS transcript and persistence".to_owned(),
            source_files: vec![
                "mls.rs".to_owned(),
                "crypto_store.rs".to_owned(),
                "devices.rs".to_owned(),
            ],
            test_targets: vec![
                "mls::tests::openmls_state_persists_through_crypto_store_record".to_owned(),
                "mls::tests::multi_device_workflow_applies_missed_commits_and_models_recovery"
                    .to_owned(),
            ],
            status: SecurityReviewStatus::Tested,
            notes: "KeyPackages, Welcomes, commits and epoch recovery records have durable shapes"
                .to_owned(),
        },
        SecurityReviewItem {
            area: "encrypted storage contracts".to_owned(),
            source_files: vec![
                "store.rs".to_owned(),
                "crypto_store.rs".to_owned(),
                "platform.rs".to_owned(),
            ],
            test_targets: vec![
                "store::tests::encrypted_store_keeps_ciphertext_and_plain_api".to_owned(),
                "crypto_store::tests::encrypted_crypto_store_seals_group_state_and_epoch_secrets_at_rest"
                    .to_owned(),
                "platform::tests::wasm_runtime_contract_covers_browser_http_indexeddb_webcrypto_and_sync_cache"
                    .to_owned(),
            ],
            status: SecurityReviewStatus::Tested,
            notes: "native and browser storage contracts model encrypted-at-rest boundaries"
                .to_owned(),
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
            area: "token/log redaction".to_owned(),
            source_files: vec![
                "auth.rs".to_owned(),
                "client.rs".to_owned(),
                "server.rs".to_owned(),
                "crypto.rs".to_owned(),
            ],
            test_targets: vec![
                "auth::tests::auth_redacts_secrets_in_debug_output".to_owned(),
                "client::tests::rejects_query_auth_on_base_path_and_built_request".to_owned(),
                "server::tests::query_auth_and_wire_negative_vectors_are_available".to_owned(),
                "crypto::tests::redact_log_value_removes_nested_secret_material".to_owned(),
            ],
            status: SecurityReviewStatus::Tested,
            notes: "debug output, structured logs and query auth vectors remove credential material"
                .to_owned(),
        },
        SecurityReviewItem {
            area: "unsafe feature combinations".to_owned(),
            source_files: vec!["Cargo.toml".to_owned(), "crypto.rs".to_owned()],
            test_targets: vec![
                "crypto::tests::feature_safety_report_rejects_unsafe_combinations".to_owned(),
                "crypto::tests::current_feature_safety_report_accepts_compiled_features".to_owned(),
            ],
            status: SecurityReviewStatus::Tested,
            notes: "Cargo feature dependencies are mirrored by a machine-readable safety report"
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
            space_id: "cx:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
            event_kind: "cx.message.create".to_owned(),
            event_id: "cx:event:01904100-0000-7000-8000-51495aba0a08".to_owned(),
            causal_refs: vec!["cx:event:01904100-0000-7000-8000-2b39e7197b88".to_owned()],
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
        for area in [
            "canonical signing/proof binding",
            "MLS transcript and persistence",
            "encrypted storage contracts",
            "token/log redaction",
            "unsafe feature combinations",
        ] {
            assert!(
                checklist
                    .iter()
                    .any(|item| item.area == area && item.status == SecurityReviewStatus::Tested),
                "missing tested security review area: {area}"
            );
        }
    }

    #[test]
    fn redact_log_value_removes_nested_secret_material() {
        let value = serde_json::json!({
            "access_token": "access-secret",
            "nested": {
                "refresh_token": "refresh-secret",
                "safe": "visible"
            },
            "events": [
                {"device_proof": "proof-secret", "count": 1},
                {"message": "ok"}
            ]
        });
        let redacted = redact_log_value(&value);
        let serialized = serde_json::to_string(&redacted).unwrap();

        assert!(!serialized.contains("access-secret"));
        assert!(!serialized.contains("refresh-secret"));
        assert!(!serialized.contains("proof-secret"));
        assert!(serialized.contains("visible"));
        assert_eq!(redacted["access_token"], REDACTED_SECRET);
        assert_eq!(redacted["nested"]["refresh_token"], REDACTED_SECRET);
        assert_eq!(redacted["events"][0]["device_proof"], REDACTED_SECRET);
    }

    #[test]
    fn feature_safety_report_rejects_unsafe_combinations() {
        let report = feature_safety_report(["mls", "salvo", "sync-runtime"]);
        assert!(report.validate().is_err());
        assert!(report.violations.contains(&UnsafeFeatureCombination::MlsWithoutFullSurface));
        assert!(report.violations.contains(&UnsafeFeatureCombination::SalvoWithoutServer));
        assert!(report.violations.contains(&UnsafeFeatureCombination::RuntimeWithoutFullSurface));

        let safe = feature_safety_report(["full-surface", "server", "salvo", "mls"]);
        safe.validate().unwrap();
    }

    #[test]
    fn current_feature_safety_report_accepts_compiled_features() {
        current_feature_safety_report().validate().unwrap();
    }

    // Property-style tests: exercise many inputs to verify invariants.

    #[test]
    fn seal_open_roundtrips_for_various_plaintext_sizes() {
        let key = b"test-key-material-for-property-tests";
        let aad = b"test-aad";
        // Test a range of plaintext sizes including edge cases.
        let sizes: Vec<usize> =
            vec![0, 1, 15, 16, 17, 23, 31, 32, 63, 64, 127, 128, 255, 256, 512, 1024];
        for size in sizes {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let sealed = seal(&plaintext, key, aad).unwrap();
            assert!(
                sealed.len() > plaintext.len(),
                "sealed must be larger than plaintext for size {size}"
            );
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
            assert!(
                open(&sealed[..len], key, aad).is_err(),
                "truncated envelope of length {len} must fail"
            );
        }
    }

    #[test]
    fn canonical_digest_is_deterministic_for_same_input() {
        let aad = EncryptedEnvelopeAad {
            space_id: "cx:space:01904100-0000-7000-8000-cfc039892036".to_owned(),
            event_kind: "cx.message.create".to_owned(),
            event_id: "cx:event:01904100-0000-7000-8000-b70714ca75c5".to_owned(),
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
            space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            event_kind: "cx.message.create".to_owned(),
            event_id: "cx:event:01904100-0000-7000-8000-0b94566027c1".to_owned(),
            causal_refs: vec![],
        };
        let aad2 = EncryptedEnvelopeAad {
            space_id: "cx:space:01904100-0000-7000-8000-2a9d538f2fcf".to_owned(),
            event_kind: "cx.message.create".to_owned(),
            event_id: "cx:event:01904100-0000-7000-8000-0b94566027c1".to_owned(),
            causal_refs: vec![],
        };
        let digest1 = envelope_aad_digest(&aad1).unwrap();
        let digest2 = envelope_aad_digest(&aad2).unwrap();
        assert_ne!(digest1, digest2, "different AADs must produce different digests");
    }

    #[test]
    fn constant_time_eq_matches_standard_equality() {
        let pairs: Vec<(&str, &str)> =
            vec![("", ""), ("a", "a"), ("abc", "abc"), ("abc", "abd"), ("abc", "ab"), ("", "a")];
        for (left, right) in pairs {
            let ct_result = constant_time_eq(left, right);
            let eq_result = left == right;
            assert_eq!(
                ct_result, eq_result,
                "constant_time_eq({left:?}, {right:?}) != standard =="
            );
        }
    }
}
