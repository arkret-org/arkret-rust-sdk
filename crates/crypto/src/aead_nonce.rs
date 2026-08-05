//! MLS-Exporter AEAD nonce derivation + encrypted-envelope AAD digest helpers.
//!
//! v1 deterministic AEAD sender-nonce construction
//! (`nonce = sender_nonce_prefix || counter_be64`, per
//! `crypto-media/encryption-and-audit.md`) plus the canonical
//! encrypted-envelope AAD digest. These moved here from the SDK so the MLS
//! behavior layer can reach them without a dependency cycle back through the
//! umbrella crate; the SDK keeps the `arkret::crypto::*` surface via re-export
//! and the byte-level outputs are unchanged.

use std::collections::{BTreeMap, VecDeque};

use arkret_canonical::canonical::{canonical_json_bytes, sha256_bytes, sha256_digest};
use arkret_models_crypto::EncryptedEnvelopeAad;
use arkret_wire::{ExporterLabelId, ReasonCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{Error, Result};

/// MLS exporter label domain-separating the v1 AEAD sender nonce prefix.
pub const AEAD_NONCE_EXPORTER_LABEL: &str = ExporterLabelId::AEAD_SENDER_NONCE_PREFIX_V1;
/// Length of the big-endian device nonce counter suffix.
pub const AEAD_NONCE_COUNTER_LEN: usize = 8;
/// `N_AEAD` for XChaCha20-Poly1305 (`encoding.md` §10.1).
pub const AEAD_NONCE_XCHACHA20_POLY1305_LEN: usize = 24;
/// `N_AEAD` for AES-GCM (`encoding.md` §10.1).
pub const AEAD_NONCE_AES_GCM_LEN: usize = 12;
/// `alg` value of the XChaCha20-Poly1305 **blob** AEAD scheme
/// (`blob.schema.json#/properties/encryption/properties/alg`,
/// `crypto-media/media-and-blob.md` §3.1).
///
/// This is a blob/attachment algorithm id, NOT an `aead_profile`. §10.1 routes
/// `aead_profile` by how the key was obtained, and the MLS-exporter-derived
/// domains (`mls_exporter_aead_v1` content, ephemeral signal AEAD) take the
/// `canonical_id` of the group's negotiated `mls-ciphersuite-registry.json`
/// row — a value that MUST NOT be an HPKE suite name or a local alias such as
/// this one.
pub const AEAD_PROFILE_XCHACHA20_POLY1305: &str = "mls_exporter_aead_xchacha20poly1305";
/// `alg` value of the AES-256-GCM **blob** AEAD scheme. Same domain caveat as
/// [`AEAD_PROFILE_XCHACHA20_POLY1305`].
pub const AEAD_PROFILE_AES_256_GCM: &str = "mls_exporter_aead_aes_256_gcm";
/// Domain-separation context prefix bound into canonical encrypted-envelope AAD.
pub const ENCRYPTED_ENVELOPE_AAD_CONTEXT: &str = "arkret-encrypted-envelope-aad-v1";

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
#[derive(Clone, Debug)]
pub struct AeadNonceReplayTracker {
    scopes: BTreeMap<[u8; 32], ReplayWindow>,
    lru: VecDeque<[u8; 32]>,
    max_scopes: usize,
}

#[derive(Clone, Copy, Debug)]
struct ReplayWindow {
    highest_counter: u64,
    bitmap: u128,
}

impl Default for AeadNonceReplayTracker {
    fn default() -> Self {
        Self::with_max_scopes(1_024)
    }
}

impl AeadNonceReplayTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_scopes(max_scopes: usize) -> Self {
        Self {
            scopes: BTreeMap::new(),
            lru: VecDeque::new(),
            max_scopes: max_scopes.max(1),
        }
    }

    pub fn accept_counter(&mut self, context: &AeadNonceContext, counter: u64) -> Result<()> {
        let scope: [u8; 32] = Sha256::digest(aead_sender_nonce_context_bytes(context)?).into();
        if !self.scopes.contains_key(&scope) {
            if self.scopes.len() >= self.max_scopes
                && let Some(evicted) = self.lru.pop_front()
            {
                self.scopes.remove(&evicted);
            }
            self.scopes.insert(
                scope,
                ReplayWindow {
                    highest_counter: counter,
                    bitmap: 1,
                },
            );
            self.lru.push_back(scope);
            return Ok(());
        }

        self.lru.retain(|entry| entry != &scope);
        self.lru.push_back(scope);
        let window = self
            .scopes
            .get_mut(&scope)
            .expect("scope was checked above");
        if counter > window.highest_counter {
            let shift = counter - window.highest_counter;
            window.bitmap = if shift >= u128::BITS as u64 {
                1
            } else {
                (window.bitmap << shift) | 1
            };
            window.highest_counter = counter;
            return Ok(());
        }
        let distance = window.highest_counter - counter;
        if distance >= u128::BITS as u64 || window.bitmap & (1_u128 << distance) != 0 {
            return Err(protocol_error(
                ReasonCode::AEAD_NONCE_COUNTER_REPLAY,
                "AEAD nonce counter was replayed or fell outside the receive window",
            ));
        }
        window.bitmap |= 1_u128 << distance;
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

fn protocol_error(reason: &str, detail: &str) -> Error {
    Error::Protocol(format!("{reason}: {detail}"))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    // Authoritative `sha256:<lowercase-hex>` formatter (single source of truth
    // for the digest prefix/encoding).
    sha256_digest(bytes)
}

pub fn aead_nonce_prefix_len(nonce_len: usize) -> Result<usize> {
    if nonce_len <= AEAD_NONCE_COUNTER_LEN {
        return Err(protocol_error(
            ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
            "AEAD nonce length must reserve an 8-byte counter suffix",
        ));
    }
    Ok(nonce_len - AEAD_NONCE_COUNTER_LEN)
}

fn validate_aead_nonce_context(context: &AeadNonceContext) -> Result<()> {
    if context.key_ref.is_null() {
        return Err(protocol_error(
            ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
            "key_ref must be present in the AEAD nonce exporter context",
        ));
    }
    if context.device_id.is_empty() || context.purpose.is_empty() || context.aead_profile.is_empty()
    {
        return Err(protocol_error(
            ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
            "device_id, purpose and aead_profile must be non-empty",
        ));
    }
    Ok(())
}

/// Canonical JSON bytes used as MLS-Exporter Context for v1 AEAD nonce prefixes.
pub fn aead_sender_nonce_context_bytes(context: &AeadNonceContext) -> Result<Vec<u8>> {
    validate_aead_nonce_context(context)?;
    Ok(canonical_json_bytes(context)?)
}

/// Derive the §10.1 sender nonce prefix from an epoch exporter secret.
///
/// This is `MLS-Exporter(label = "arkret-aead-sender-nonce-prefix-v1",
/// context = <canonical context bytes>, length = N_AEAD - 8)`. The label and
/// the Context are two separate exporter parameters, so the Context is the
/// canonical context bytes alone. A live integration reaches the same bytes
/// through its group's exporter (`ArkretMlsGroup::content_aead_nonce` /
/// `signal_nonce_prefix` in `arkret-mls`); this entry point takes the epoch
/// exporter secret directly for receivers, adapters and known-answer tests.
pub fn derive_aead_sender_nonce_prefix(
    exporter_secret: &[u8],
    context: &AeadNonceContext,
    nonce_len: usize,
) -> Result<Vec<u8>> {
    let prefix_len = aead_nonce_prefix_len(nonce_len)?;
    let context_bytes = aead_sender_nonce_context_bytes(context)?;
    crate::mls_exporter::mls_exporter_from_secret(
        exporter_secret,
        AEAD_NONCE_EXPORTER_LABEL,
        &context_bytes,
        prefix_len,
    )
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
            ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
            "AEAD nonce does not match the canonical deterministic derivation",
        ))
    }
}

/// Verify the sender prefix, parse the counter and optionally enforce replay.
///
/// Recomputes the prefix with [`derive_aead_sender_nonce_prefix`], so it is
/// scoped to the same test/adapter setting: a live receiver recomputes the
/// declared sender's prefix through its MLS group exporter instead.
pub fn verify_aead_sender_nonce(
    exporter_secret: &[u8],
    context: &AeadNonceContext,
    supplied_nonce: &[u8],
    nonce_len: usize,
    replay_tracker: Option<&mut AeadNonceReplayTracker>,
) -> Result<u64> {
    if supplied_nonce.len() != nonce_len {
        return Err(protocol_error(
            ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
            "AEAD nonce length does not match the declared AEAD profile",
        ));
    }
    let expected_prefix = derive_aead_sender_nonce_prefix(exporter_secret, context, nonce_len)?;
    let prefix_len = expected_prefix.len();
    if supplied_nonce[..prefix_len] != expected_prefix {
        return Err(protocol_error(
            ReasonCode::AEAD_NONCE_SENDER_DOMAIN_COLLISION,
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

/// Canonicalize encrypted-envelope AAD and bind it to a domain-separated context.
pub fn canonical_envelope_aad(aad: &EncryptedEnvelopeAad) -> Result<Vec<u8>> {
    let mut bytes = ENCRYPTED_ENVELOPE_AAD_CONTEXT.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&canonical_json_bytes(aad)?);
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
    bytes.extend_from_slice(&canonical_json_bytes(aad)?);
    Ok(sha256_prefixed(&bytes))
}

/// Fail closed if the supplied AAD digest does not match the canonical AAD.
pub fn verify_envelope_aad_digest(aad: &EncryptedEnvelopeAad, expected: &str) -> Result<()> {
    let actual = envelope_aad_digest(aad)?;
    let actual_digest = sha256_bytes(actual.as_bytes());
    let expected_digest = sha256_bytes(expected.as_bytes());
    if bool::from(actual_digest.ct_eq(&expected_digest)) {
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

/// Compare two strings in constant time after reducing both to fixed-size digests.
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = sha256_bytes(left.as_bytes());
    let right = sha256_bytes(right.as_bytes());
    bool::from(left.ct_eq(&right))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{EventId, RealmId};
    use serde_json::json;

    use super::*;

    fn fixture_nonce_context(device_id: &str) -> AeadNonceContext {
        AeadNonceContext {
            key_ref: json!({
                "algorithm": "MLS",
                "group_state_ref": "ak:event:01964148-0000-8000-8000-000000000000"
            }),
            epoch: 42,
            device_id: device_id.to_owned(),
            purpose: "ak.message.encrypted_payload".to_owned(),
            aead_profile: AEAD_PROFILE_XCHACHA20_POLY1305.to_owned(),
        }
    }

    fn registered_sender_nonce_prefix_case() -> Value {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/arkret-private-kdf-fixture.json")
                .expect("kdf fixture must be embedded");
        fixture["cases"]
            .as_array()
            .expect("kdf fixture must carry cases")
            .iter()
            .find(|case| case["name"].as_str() == Some("aead_sender_nonce_prefix_aes128gcm"))
            .expect("kdf fixture must register the sender nonce prefix vector")
            .clone()
    }

    #[test]
    fn sender_nonce_prefix_matches_the_registered_vector() {
        let case = registered_sender_nonce_prefix_case();
        let secret = hex::decode(case["input"]["exporter_secret_hex"].as_str().unwrap()).unwrap();
        let context: AeadNonceContext = serde_json::from_value(case["input"]["context"].clone())
            .expect("the registered context must decode into the canonical context type");
        let nonce_len =
            usize::try_from(case["input"]["nonce_length_bytes"].as_u64().unwrap()).unwrap();
        assert_eq!(nonce_len, AEAD_NONCE_AES_GCM_LEN);
        assert_eq!(
            AEAD_NONCE_EXPORTER_LABEL,
            case["input"]["exporter_label"].as_str().unwrap()
        );

        // The exporter Context is the canonical context bytes alone. Pin them
        // before the derivation so a canonicalization drift cannot hide behind
        // a prefix that happens to match over different bytes.
        assert_eq!(
            String::from_utf8(aead_sender_nonce_context_bytes(&context).unwrap()).unwrap(),
            case["expected"]["context_canonical_json"].as_str().unwrap()
        );

        let prefix = derive_aead_sender_nonce_prefix(&secret, &context, nonce_len).unwrap();
        assert_eq!(
            hex::encode(&prefix),
            case["expected"]["sender_nonce_prefix_hex"]
                .as_str()
                .unwrap()
        );

        let counter =
            u64::from_str_radix(case["input"]["counter_be64_hex"].as_str().unwrap(), 16).unwrap();
        assert_eq!(
            hex::encode(compose_aead_nonce(&prefix, counter)),
            case["expected"]["nonce_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn sender_nonce_context_and_replay_are_enforced() {
        const EXPORTER_SECRET: [u8; 32] = [0x24u8; 32];
        let context = fixture_nonce_context("ak:device:01964137-0000-7000-8000-000000000001");
        let prefix = derive_aead_sender_nonce_prefix(
            &EXPORTER_SECRET,
            &context,
            AEAD_NONCE_XCHACHA20_POLY1305_LEN,
        )
        .unwrap();

        let nonce = compose_aead_nonce(&prefix, 7);
        let mut tracker = AeadNonceReplayTracker::new();
        assert_eq!(
            verify_aead_sender_nonce(
                &EXPORTER_SECRET,
                &context,
                &nonce,
                AEAD_NONCE_XCHACHA20_POLY1305_LEN,
                Some(&mut tracker),
            )
            .unwrap(),
            7
        );
        assert!(
            verify_aead_sender_nonce(
                &EXPORTER_SECRET,
                &context,
                &nonce,
                AEAD_NONCE_XCHACHA20_POLY1305_LEN,
                Some(&mut tracker),
            )
            .is_err()
        );
    }

    #[test]
    fn replay_tracker_bounds_scopes_and_rejects_old_counters() {
        let mut tracker = AeadNonceReplayTracker::with_max_scopes(2);
        let first = fixture_nonce_context("ak:device:01964137-0000-7000-8000-000000000001");
        let second = fixture_nonce_context("ak:device:01964137-0000-7000-8000-000000000002");
        let third = fixture_nonce_context("ak:device:01964137-0000-7000-8000-000000000003");

        tracker.accept_counter(&first, 200).unwrap();
        assert!(tracker.accept_counter(&first, 72).is_err());
        tracker.accept_counter(&second, 0).unwrap();
        tracker.accept_counter(&third, 0).unwrap();
        assert_eq!(tracker.scopes.len(), 2);
        assert_eq!(tracker.lru.len(), 2);
    }

    #[test]
    fn encrypted_envelope_aad_digest_is_canonical() {
        let aad = EncryptedEnvelopeAad {
            realm_id: RealmId::new("ak:realm:01904100-0000-8000-8000-9b64700c6ee8").unwrap(),
            event_kind: "ak.message.create".to_owned(),
            event_id: Some(EventId::new("ak:event:01904100-0000-8000-8000-51495aba0a08").unwrap()),
            event_ref_digest: None,
            causal_refs: Some(vec![
                EventId::new("ak:event:01904100-0000-8000-8000-2b39e7197b88").unwrap(),
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
}
