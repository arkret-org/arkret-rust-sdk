//! Shared authenticated encryption helpers.

use std::collections::BTreeSet;

pub use arkret_core::EncryptedEnvelopeAad;
use arkret_core::error::{
    REASON_AEAD_NONCE_COUNTER_REPLAY, REASON_AEAD_NONCE_DERIVATION_INVALID,
    REASON_AEAD_NONCE_SENDER_DOMAIN_COLLISION,
};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{Error, Result};

pub const AEAD_ALGORITHM: &str = "xchacha20poly1305-hkdf-sha256-v1";
/// HKDF salt that domain-separates the `seal`/`open` AEAD key derivation
/// from any other use of the same key material.
const AEAD_HKDF_SALT: &[u8] = b"arkret-aead-seal-hkdf-v1";
pub const ENCRYPTED_ENVELOPE_AAD_CONTEXT: &str = "arkret-encrypted-envelope-aad-v1";
pub const REDACTED_SECRET: &str = "<redacted>";
const NONCE_LEN: usize = 24;
pub const AEAD_NONCE_EXPORTER_LABEL: &str = "arkret-aead-sender-nonce-prefix-v1";
pub const AEAD_NONCE_COUNTER_LEN: usize = 8;
pub const AEAD_NONCE_XCHACHA20_POLY1305_LEN: usize = 24;
pub const AEAD_NONCE_AES_GCM_LEN: usize = 12;
pub const AEAD_PROFILE_XCHACHA20_POLY1305: &str = "mls_exporter_aead_xchacha20poly1305";
pub const AEAD_PROFILE_AES_256_GCM: &str = "mls_exporter_aead_aes_256_gcm";

/// Canonical context for v1 AEAD sender nonce prefix derivation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadNonceContext {
    pub key_ref: Value,
    pub epoch: u64,
    pub device_id: String,
    pub purpose: String,
    pub aead_profile: String,
}

/// Receiver-side replay cache for per-sender AEAD counters.
#[derive(Clone, Debug, Default)]
pub struct AeadNonceReplayTracker {
    seen: BTreeSet<(Vec<u8>, u64)>,
}

impl AeadNonceReplayTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept_counter(&mut self, context: &AeadNonceContext, counter: u64) -> Result<()> {
        let scope = aead_sender_nonce_context_bytes(context)?;
        if !self.seen.insert((scope, counter)) {
            return Err(protocol_error(
                REASON_AEAD_NONCE_COUNTER_REPLAY,
                "AEAD nonce counter was already seen for this sender scope",
            ));
        }
        Ok(())
    }
}

/// Digest report used by callers that store AAD digest separately from ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelopeDigestReport {
    pub ciphertext_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad_sha256: Option<String>,
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
            Err(Error::Protocol(format!(
                "unsafe Cargo feature combination: {:?}",
                self.violations
            )))
        }
    }
}

/// Evaluate a Cargo feature set for combinations that should never be published.
pub fn feature_safety_report<I, S>(features: I) -> FeatureSafetyReport
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut enabled_features = features
        .into_iter()
        .map(|feature| feature.as_ref().to_owned())
        .collect::<Vec<_>>();
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
    if [
        "applet-runtime",
        "device-runtime",
        "sync-runtime",
        "timeline-runtime",
    ]
    .iter()
    .any(|feature| has(feature))
        && !has("full-surface")
    {
        violations.push(UnsafeFeatureCombination::RuntimeWithoutFullSurface);
    }

    FeatureSafetyReport {
        enabled_features,
        violations,
    }
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

/// The crypto-relevant Cargo feature set compiled into this SDK build, in the
/// spelling [`arkret_core::verify_declared_profiles_against_features`] expects.
///
/// The SDK crate can observe `mls` (OpenMLS group crypto) directly. Client-side
/// key-backup crypto (`backup`) is a feature of the separate `arkret-crypto`
/// crate, not re-exported as an SDK feature, so it is not visible to `cfg!`
/// here; a caller that links `arkret-crypto` with `backup` should append
/// [`arkret_core::profile_feature_guard::FEATURE_BACKUP`] to this list before
/// calling [`arkret_core::verify_declared_profiles_against_features`].
pub fn current_profile_crypto_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    if cfg!(feature = "mls") {
        features.push(arkret_core::profile_feature_guard::FEATURE_MLS);
    }
    features
}

/// Cross-check the conformance profiles this build intends to declare against
/// the crypto features actually compiled in, so a feature-trimmed binary never
/// advertises `e2ee_client` (or any MLS/backup-bearing profile) it cannot
/// serve. See [`arkret_core::verify_declared_profiles_against_features`].
pub fn verify_declared_profiles_against_current_features(
    declared: &[&str],
) -> std::result::Result<
    std::result::Result<(), Vec<arkret_core::ProfileFeatureGap>>,
    arkret_core::generated::profile_requirements::ProfileRequirementsError,
> {
    arkret_core::verify_declared_profiles_against_features(
        declared,
        &current_profile_crypto_features(),
    )
}

/// Whether a field name can contain credential, token, proof or signature data.
pub fn is_sensitive_log_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "session_credential"
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
            | "renewal_credential"
            | "reset_token"
            | "secret"
            | "service_signature"
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

/// Derive the 32-byte AEAD key from caller key material with HKDF-SHA256.
///
/// HKDF (RFC 5869) replaces the previous bare `SHA-256(key_material)`: a
/// fixed salt domain-separates this `seal`/`open` use from any other key
/// derivation, and the AAD is mixed into the `info` parameter so the same
/// key material under a different context produces an independent key. The
/// key material is still expected to be high-entropy; low-entropy
/// passphrases MUST be stretched with `arkret_crypto::backup::derive_vault_kek`
/// (Argon2id) before being passed here.
fn derive_aead_key(key_material: &[u8], aad: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(AEAD_HKDF_SALT), key_material);
    let mut key = [0u8; 32];
    hkdf.expand(aad, &mut key)
        .map_err(|_| Error::Crypto("AEAD key derivation failed".to_owned()))?;
    Ok(key)
}

fn protocol_error(reason: &str, detail: &str) -> Error {
    Error::Protocol(format!("{reason}: {detail}"))
}

fn aead_nonce_prefix_len(nonce_len: usize) -> Result<usize> {
    if nonce_len <= AEAD_NONCE_COUNTER_LEN {
        return Err(protocol_error(
            REASON_AEAD_NONCE_DERIVATION_INVALID,
            "AEAD nonce length must reserve an 8-byte counter suffix",
        ));
    }
    Ok(nonce_len - AEAD_NONCE_COUNTER_LEN)
}

fn validate_aead_nonce_context(context: &AeadNonceContext) -> Result<()> {
    if context.key_ref.is_null() {
        return Err(protocol_error(
            REASON_AEAD_NONCE_DERIVATION_INVALID,
            "key_ref must be present in the AEAD nonce exporter context",
        ));
    }
    if context.device_id.is_empty() || context.purpose.is_empty() || context.aead_profile.is_empty()
    {
        return Err(protocol_error(
            REASON_AEAD_NONCE_DERIVATION_INVALID,
            "device_id, purpose and aead_profile must be non-empty",
        ));
    }
    Ok(())
}

/// Canonical JSON bytes used as MLS-Exporter Context for v1 AEAD nonce prefixes.
pub fn aead_sender_nonce_context_bytes(context: &AeadNonceContext) -> Result<Vec<u8>> {
    validate_aead_nonce_context(context)?;
    Ok(crate::canonical::canonical_json_bytes(context)?)
}

/// Derive the sender nonce prefix from a fixed exporter secret for tests and adapters.
///
/// Live MLS integrations should call the MLS exporter with
/// `AEAD_NONCE_EXPORTER_LABEL`, [`aead_sender_nonce_context_bytes`] and
/// `nonce_len - 8`. This helper mirrors that exporter input with HKDF-SHA256
/// so conformance tests can pin deterministic bytes without a live MLS group.
pub fn derive_aead_sender_nonce_prefix(
    exporter_secret: &[u8],
    context: &AeadNonceContext,
    nonce_len: usize,
) -> Result<Vec<u8>> {
    let prefix_len = aead_nonce_prefix_len(nonce_len)?;
    let context_bytes = aead_sender_nonce_context_bytes(context)?;
    let mut info = Vec::with_capacity(AEAD_NONCE_EXPORTER_LABEL.len() + 1 + context_bytes.len());
    info.extend_from_slice(AEAD_NONCE_EXPORTER_LABEL.as_bytes());
    info.push(0x00);
    info.extend_from_slice(&context_bytes);

    let hkdf = Hkdf::<Sha256>::new(None, exporter_secret);
    let mut prefix = vec![0u8; prefix_len];
    hkdf.expand(&info, &mut prefix)
        .map_err(|_| Error::Crypto("AEAD nonce prefix derivation failed".to_owned()))?;
    Ok(prefix)
}

/// Compose `nonce = sender_nonce_prefix || device_nonce_counter_be64`.
pub fn compose_aead_nonce(sender_nonce_prefix: &[u8], counter: u64) -> Vec<u8> {
    let mut nonce = Vec::with_capacity(sender_nonce_prefix.len() + AEAD_NONCE_COUNTER_LEN);
    nonce.extend_from_slice(sender_nonce_prefix);
    nonce.extend_from_slice(&counter.to_be_bytes());
    nonce
}

/// Reject if a supplied nonce does not equal the deterministic canonical nonce.
pub fn verify_aead_nonce_derivation(expected_nonce: &[u8], supplied_nonce: &[u8]) -> Result<()> {
    if expected_nonce == supplied_nonce {
        Ok(())
    } else {
        Err(protocol_error(
            REASON_AEAD_NONCE_DERIVATION_INVALID,
            "AEAD nonce does not match the canonical deterministic derivation",
        ))
    }
}

/// Verify the sender prefix, parse the counter and optionally enforce replay.
pub fn verify_aead_sender_nonce(
    exporter_secret: &[u8],
    context: &AeadNonceContext,
    supplied_nonce: &[u8],
    nonce_len: usize,
    replay_tracker: Option<&mut AeadNonceReplayTracker>,
) -> Result<u64> {
    if supplied_nonce.len() != nonce_len {
        return Err(protocol_error(
            REASON_AEAD_NONCE_DERIVATION_INVALID,
            "AEAD nonce length does not match the declared AEAD profile",
        ));
    }
    let expected_prefix = derive_aead_sender_nonce_prefix(exporter_secret, context, nonce_len)?;
    let prefix_len = expected_prefix.len();
    if supplied_nonce[..prefix_len] != expected_prefix {
        return Err(protocol_error(
            REASON_AEAD_NONCE_SENDER_DOMAIN_COLLISION,
            "sender_nonce_prefix does not match the declared sender device",
        ));
    }
    let mut counter_bytes = [0u8; AEAD_NONCE_COUNTER_LEN];
    counter_bytes.copy_from_slice(&supplied_nonce[prefix_len..]);
    let counter = u64::from_be_bytes(counter_bytes);
    if let Some(tracker) = replay_tracker {
        tracker.accept_counter(context, counter)?;
    }
    Ok(counter)
}

/// Encrypt plaintext with XChaCha20-Poly1305 using the given key material and AAD.
///
/// The key material is stretched with HKDF-SHA256 (domain-separated by a
/// fixed salt and bound to `aad`) before use. The output contains the
/// 24-byte nonce followed by the AEAD ciphertext+tag.
#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, fields(plaintext_len = plaintext.len())))]
pub fn seal(plaintext: &[u8], key_material: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = derive_aead_key(key_material, aad)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::Crypto("AEAD key derivation failed".to_owned()))?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|error| Error::Crypto(error.to_string()))?;
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
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
        return Err(Error::Crypto(
            "AEAD envelope is shorter than nonce".to_owned(),
        ));
    }
    let (nonce, ciphertext) = envelope.split_at(NONCE_LEN);
    let key = derive_aead_key(key_material, aad)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::Crypto("AEAD key derivation failed".to_owned()))?;
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| Error::Crypto("AEAD envelope nonce has invalid length".to_owned()))?;
    cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
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
        Err(Error::Protocol(
            "encrypted envelope AAD digest mismatch".to_owned(),
        ))
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

fn sha256_prefixed(bytes: &[u8]) -> String {
    // Reuse the authoritative `sha256:<lowercase-hex>` formatter in
    // `arkret-core` (single source of truth for the digest prefix/encoding).
    arkret_canonical::canonical::sha256_digest(bytes)
}

/// Constant-time string comparison backed by the audited `subtle` crate.
///
/// Both inputs are reduced to a fixed-length SHA-256 digest first so the
/// comparison loop bound never depends on the secret's length, then
/// compared with `subtle::ConstantTimeEq`. Shared crate-wide (see
/// `key_verification::commitment`, `identity::records`, `auth::helpers`).
pub(crate) fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = arkret_canonical::canonical::sha256_bytes(left.as_bytes());
    let right = arkret_canonical::canonical::sha256_bytes(right.as_bytes());
    left.ct_eq(&right).into()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn fixture_nonce_context(device_id: &str) -> AeadNonceContext {
        AeadNonceContext {
            key_ref: json!({
                "algorithm": "MLS",
                "group_state_ref": "ak:event:01964148-0000-7000-8000-000000000000"
            }),
            epoch: 42,
            device_id: device_id.to_owned(),
            purpose: "ak.message.encrypted_payload".to_owned(),
            aead_profile: AEAD_PROFILE_XCHACHA20_POLY1305.to_owned(),
        }
    }

    #[test]
    fn aead_seal_open_roundtrips_and_authenticates_aad() {
        let sealed = seal(b"secret", b"passphrase", b"context").unwrap();
        assert_ne!(sealed, b"secret");
        assert_eq!(open(&sealed, b"passphrase", b"context").unwrap(), b"secret");
        assert!(open(&sealed, b"passphrase", b"wrong-context").is_err());
    }

    #[test]
    fn aead_sender_nonce_prefix_context_and_replay_are_enforced() {
        const EXPORTER_SECRET: [u8; 32] = [0x24u8; 32];
        const DEVICE_ONE: &str = "ak:device:01964137-0000-7000-8000-000000000001";
        const DEVICE_TWO: &str = "ak:device:01964137-0000-7000-8000-000000000002";
        const EXPECTED_PREFIX_HEX: &str = "5d62cff5f7a7befee1e39e3dc287cb67";

        let context = fixture_nonce_context(DEVICE_ONE);
        let prefix = derive_aead_sender_nonce_prefix(
            &EXPORTER_SECRET,
            &context,
            AEAD_NONCE_XCHACHA20_POLY1305_LEN,
        )
        .unwrap();
        assert_eq!(hex::encode(&prefix), EXPECTED_PREFIX_HEX);

        let nonce = compose_aead_nonce(&prefix, 7);
        assert_eq!(nonce.len(), AEAD_NONCE_XCHACHA20_POLY1305_LEN);
        assert_eq!(&nonce[16..], &7u64.to_be_bytes());

        let mut tracker = AeadNonceReplayTracker::new();
        let counter = verify_aead_sender_nonce(
            &EXPORTER_SECRET,
            &context,
            &nonce,
            AEAD_NONCE_XCHACHA20_POLY1305_LEN,
            Some(&mut tracker),
        )
        .unwrap();
        assert_eq!(counter, 7);
        let replay = verify_aead_sender_nonce(
            &EXPORTER_SECRET,
            &context,
            &nonce,
            AEAD_NONCE_XCHACHA20_POLY1305_LEN,
            Some(&mut tracker),
        )
        .unwrap_err();
        assert!(matches!(
            replay,
            Error::Protocol(message) if message.starts_with(REASON_AEAD_NONCE_COUNTER_REPLAY)
        ));

        let other_context = fixture_nonce_context(DEVICE_TWO);
        let mismatch = verify_aead_sender_nonce(
            &EXPORTER_SECRET,
            &other_context,
            &nonce,
            AEAD_NONCE_XCHACHA20_POLY1305_LEN,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            mismatch,
            Error::Protocol(message) if message.starts_with(REASON_AEAD_NONCE_SENDER_DOMAIN_COLLISION)
        ));

        let aes_context = AeadNonceContext {
            aead_profile: AEAD_PROFILE_AES_256_GCM.to_owned(),
            ..fixture_nonce_context(DEVICE_ONE)
        };
        let expected_aes_prefix =
            derive_aead_sender_nonce_prefix(&EXPORTER_SECRET, &aes_context, AEAD_NONCE_AES_GCM_LEN)
                .unwrap();
        let expected_aes_nonce = compose_aead_nonce(&expected_aes_prefix, 0);
        let random_nonce = [0xa5u8; AEAD_NONCE_AES_GCM_LEN];
        let random_reject =
            verify_aead_nonce_derivation(&expected_aes_nonce, &random_nonce).unwrap_err();
        assert!(matches!(
            random_reject,
            Error::Protocol(message) if message.starts_with(REASON_AEAD_NONCE_DERIVATION_INVALID)
        ));
    }

    #[test]
    fn encrypted_envelope_aad_digest_is_canonical() {
        let aad = EncryptedEnvelopeAad {
            realm_id: crate::RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            event_kind: "ak.message.create".to_owned(),
            event_id: Some(
                crate::EventId::new("ak:event:01904100-0000-7000-8000-51495aba0a08").unwrap(),
            ),
            event_ref_digest: None,
            causal_refs: Some(vec![
                crate::EventId::new("ak:event:01904100-0000-7000-8000-2b39e7197b88").unwrap(),
            ]),
            causal_ref_digests: None,
        };
        let digest = envelope_aad_digest(&aad).unwrap();
        verify_envelope_aad_digest(&aad, &digest).unwrap();
        assert!(verify_envelope_aad_digest(&aad, "sha256:bad").is_err());

        let report = encrypted_envelope_digest_report(b"ciphertext", Some(&aad)).unwrap();
        assert_eq!(report.aad_sha256, Some(digest));
        assert!(report.ciphertext_sha256.starts_with("sha256:"));
    }

    #[test]
    fn redact_log_value_removes_nested_secret_material() {
        let value = serde_json::json!({
            "session_credential": "access-secret",
            "nested": {
                "renewal_credential": "refresh-secret",
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
        assert_eq!(redacted["session_credential"], REDACTED_SECRET);
        assert_eq!(redacted["nested"]["renewal_credential"], REDACTED_SECRET);
        assert_eq!(redacted["events"][0]["device_proof"], REDACTED_SECRET);
    }

    #[test]
    fn feature_safety_report_rejects_unsafe_combinations() {
        let report = feature_safety_report(["mls", "salvo", "sync-runtime"]);
        assert!(report.validate().is_err());
        assert!(
            report
                .violations
                .contains(&UnsafeFeatureCombination::MlsWithoutFullSurface)
        );
        assert!(
            report
                .violations
                .contains(&UnsafeFeatureCombination::SalvoWithoutServer)
        );
        assert!(
            report
                .violations
                .contains(&UnsafeFeatureCombination::RuntimeWithoutFullSurface)
        );

        let safe = feature_safety_report(["full-surface", "server", "salvo", "mls"]);
        safe.validate().unwrap();
    }

    #[test]
    fn current_feature_safety_report_accepts_compiled_features() {
        current_feature_safety_report().validate().unwrap();
    }

    #[test]
    fn declared_profiles_are_cross_checked_against_compiled_crypto_features() {
        // A plaintext core profile never depends on crypto features, so it
        // passes regardless of how this build was compiled.
        verify_declared_profiles_against_current_features(&["ak.profile.minimal_client.v1"])
            .expect("known profile")
            .expect("plaintext profile needs no crypto features");

        // The SDK crate can observe `mls` but not the `arkret-crypto` `backup`
        // feature, so a default (mls-on) build declaring `e2ee_client` reports a
        // `backup` gap — the intended SPEC-FEAT-01 signal.
        let outcome =
            verify_declared_profiles_against_current_features(&["ak.profile.e2ee_client.v1"])
                .expect("known profile");
        if cfg!(feature = "mls") {
            let gaps = outcome
                .expect_err("e2ee_client still needs the backup crypto feature the SDK cannot see");
            assert!(
                gaps.iter().all(|gap| gap.required_feature
                    == arkret_core::profile_feature_guard::FEATURE_BACKUP),
                "only the backup crypto feature should gap on an mls build: {gaps:?}"
            );
        }
    }

    // Property-style tests: exercise many inputs to verify invariants.

    #[test]
    fn seal_open_roundtrips_for_various_plaintext_sizes() {
        let key = b"test-key-material-for-property-tests";
        let aad = b"test-aad";
        // Test a range of plaintext sizes including edge cases.
        let sizes: Vec<usize> = vec![
            0, 1, 15, 16, 17, 23, 31, 32, 63, 64, 127, 128, 255, 256, 512, 1024,
        ];
        for size in sizes {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let sealed = seal(&plaintext, key, aad).unwrap();
            assert!(
                sealed.len() > plaintext.len(),
                "sealed must be larger than plaintext for size {size}"
            );
            let opened = open(&sealed, key, aad).unwrap();
            assert_eq!(
                opened, plaintext,
                "roundtrip failed for plaintext size {size}"
            );
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
            assert_eq!(
                opened,
                plaintext,
                "roundtrip failed for key length {}",
                key.len()
            );
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
            assert_eq!(
                opened,
                plaintext,
                "roundtrip failed for AAD length {}",
                aad.len()
            );
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
        assert_ne!(
            sealed1, sealed2,
            "two seals of the same plaintext must differ (unique nonce)"
        );
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
        assert!(
            open(&sealed, key, aad).is_err(),
            "tampered ciphertext must fail to open"
        );
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
            realm_id: crate::RealmId::new("ak:realm:01904100-0000-7000-8000-cfc039892036").unwrap(),
            event_kind: "ak.message.create".to_owned(),
            event_id: Some(
                crate::EventId::new("ak:event:01904100-0000-7000-8000-b70714ca75c5").unwrap(),
            ),
            event_ref_digest: None,
            causal_refs: None,
            causal_ref_digests: None,
        };
        let digest1 = envelope_aad_digest(&aad).unwrap();
        let digest2 = envelope_aad_digest(&aad).unwrap();
        assert_eq!(digest1, digest2, "canonical digest must be deterministic");
        assert!(digest1.starts_with("sha256:"));
    }

    #[test]
    fn canonical_digest_differs_for_different_inputs() {
        let aad1 = EncryptedEnvelopeAad {
            realm_id: crate::RealmId::new("ak:realm:01904100-0000-7000-8000-1a412919cd4b").unwrap(),
            event_kind: "ak.message.create".to_owned(),
            event_id: Some(
                crate::EventId::new("ak:event:01904100-0000-7000-8000-0b94566027c1").unwrap(),
            ),
            event_ref_digest: None,
            causal_refs: None,
            causal_ref_digests: None,
        };
        let aad2 = EncryptedEnvelopeAad {
            realm_id: crate::RealmId::new("ak:realm:01904100-0000-7000-8000-2a9d538f2fcf").unwrap(),
            event_kind: "ak.message.create".to_owned(),
            event_id: Some(
                crate::EventId::new("ak:event:01904100-0000-7000-8000-0b94566027c1").unwrap(),
            ),
            event_ref_digest: None,
            causal_refs: None,
            causal_ref_digests: None,
        };
        let digest1 = envelope_aad_digest(&aad1).unwrap();
        let digest2 = envelope_aad_digest(&aad2).unwrap();
        assert_ne!(
            digest1, digest2,
            "different AADs must produce different digests"
        );
    }

    #[test]
    fn constant_time_eq_matches_standard_equality() {
        let pairs: Vec<(&str, &str)> = vec![
            ("", ""),
            ("a", "a"),
            ("abc", "abc"),
            ("abc", "abe"),
            ("abc", "ab"),
            ("", "a"),
        ];
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
