//! MLS-Exporter AEAD nonce derivation + encrypted-envelope AAD digest helpers.
//!
//! v1 deterministic AEAD sender-nonce construction
//! (`nonce = I2OSP(durable_sender_counter, AEAD.Nn)`, per
//! `crypto-media/encryption-and-audit.md`) plus the canonical
//! encrypted-envelope AAD digest. These moved here from the SDK so the MLS
//! behavior layer can reach them without a dependency cycle back through the
//! umbrella crate; the SDK keeps the `arkret::crypto::*` surface via re-export.

use std::collections::{BTreeMap, VecDeque};

use arkret_canonical::canonical::{canonical_json_bytes, sha256_bytes, sha256_digest};
use arkret_models_crypto::EncryptedEnvelopeAad;
use arkret_wire::{EventId, RealmId, ReasonCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{Error, Result};

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
/// Domain separator for the privacy-preserving AAD Event reference digest.
pub const AAD_EVENT_REF_DIGEST_CONTEXT: &str = "ak.aad-event-ref-v1";

/// Canonical replay scope for a v1 full-width AEAD sender counter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadNonceContext {
    pub mls_group_id: String,
    pub epoch: u64,
    pub sender_domain: String,
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
        validate_aead_nonce_context(context)?;
        let scope: [u8; 32] = Sha256::digest(canonical_json_bytes(context)?).into();
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

fn validate_aead_nonce_len(nonce_len: usize) -> Result<()> {
    if nonce_len < AEAD_NONCE_COUNTER_LEN {
        return Err(protocol_error(
            ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
            "AEAD nonce length cannot encode a u64 counter",
        ));
    }
    Ok(())
}

fn validate_aead_nonce_context(context: &AeadNonceContext) -> Result<()> {
    if context.mls_group_id.is_empty() || context.sender_domain.is_empty() {
        return Err(protocol_error(
            ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
            "mls_group_id and sender_domain must be non-empty",
        ));
    }
    Ok(())
}

/// Encode the durable sender counter as full-width `I2OSP(counter, AEAD.Nn)`.
pub fn compose_aead_nonce(counter: u64, nonce_len: usize) -> Result<Vec<u8>> {
    validate_aead_nonce_len(nonce_len)?;
    let mut nonce = vec![0; nonce_len - AEAD_NONCE_COUNTER_LEN];
    nonce.extend_from_slice(&counter.to_be_bytes());
    Ok(nonce)
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

/// Parse the canonical full-width counter nonce and optionally enforce replay.
pub fn verify_aead_sender_nonce(
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
    validate_aead_nonce_context(context)?;
    validate_aead_nonce_len(nonce_len)?;
    let counter_offset = nonce_len - AEAD_NONCE_COUNTER_LEN;
    if supplied_nonce[..counter_offset]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(protocol_error(
            ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
            "AEAD nonce is not canonical full-width I2OSP of a u64 counter",
        ));
    }
    let mut counter_bytes = [0u8; AEAD_NONCE_COUNTER_LEN];
    counter_bytes.copy_from_slice(&supplied_nonce[counter_offset..]);
    let counter = u64::from_be_bytes(counter_bytes);
    if let Some(tracker) = replay_tracker {
        tracker.accept_counter(context, counter)?;
    }
    Ok(counter)
}

/// Canonicalize encrypted-envelope AAD exactly as specified by the v1 KAT.
pub fn canonical_envelope_aad(aad: &EncryptedEnvelopeAad) -> Result<Vec<u8>> {
    canonical_json_bytes(aad).map_err(Into::into)
}

/// Compute a SHA-256 digest over canonical encrypted-envelope AAD.
pub fn envelope_aad_digest(aad: &EncryptedEnvelopeAad) -> Result<String> {
    Ok(sha256_prefixed(&canonical_envelope_aad(aad)?))
}

/// Compute a SHA-256 digest over arbitrary JSON AAD using canonical JSON.
pub fn json_aad_digest(aad: &Value) -> Result<String> {
    Ok(sha256_prefixed(&canonical_json_bytes(aad)?))
}

/// Compute the privacy-preserving AAD reference for one canonical Event id.
///
/// The preimage is exactly
/// `utf8("ak.aad-event-ref-v1") || 0x00 || utf8(event_id) || 0x00 || utf8(realm_id)`.
pub fn event_ref_digest(event_id: &EventId, realm_id: &RealmId) -> String {
    let mut preimage = Vec::with_capacity(
        AAD_EVENT_REF_DIGEST_CONTEXT.len() + 2 + event_id.as_str().len() + realm_id.as_str().len(),
    );
    preimage.extend_from_slice(AAD_EVENT_REF_DIGEST_CONTEXT.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(event_id.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(realm_id.as_str().as_bytes());
    sha256_prefixed(&preimage)
}

/// Fail closed unless an AAD Event reference digest matches its typed inputs.
pub fn verify_event_ref_digest(
    event_id: &EventId,
    realm_id: &RealmId,
    expected: &str,
) -> Result<()> {
    if constant_time_eq(&event_ref_digest(event_id, realm_id), expected) {
        Ok(())
    } else {
        Err(Error::Protocol(
            "encrypted envelope event_ref_digest mismatch".to_owned(),
        ))
    }
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
    use arkret_wire::{EventId, RealmId, ScopeRef};

    use super::*;

    fn fixture_nonce_context(sender_domain: &str) -> AeadNonceContext {
        AeadNonceContext {
            mls_group_id: "YWs6cmVhbG06QWFkbm9uY2VmaXh0dXJl".to_owned(),
            epoch: 42,
            sender_domain: sender_domain.to_owned(),
        }
    }

    #[test]
    fn full_width_counter_nonce_is_canonical() {
        assert_eq!(
            hex::encode(compose_aead_nonce(7, AEAD_NONCE_AES_GCM_LEN).unwrap()),
            "000000000000000000000007"
        );
    }

    #[test]
    fn sender_nonce_context_and_replay_are_enforced() {
        let context = fixture_nonce_context("ak:device:01964137-0000-7000-8000-000000000001");
        let nonce = compose_aead_nonce(7, AEAD_NONCE_XCHACHA20_POLY1305_LEN).unwrap();
        let mut tracker = AeadNonceReplayTracker::new();
        assert_eq!(
            verify_aead_sender_nonce(
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
        let realm_id =
            RealmId::new("ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs").unwrap();
        let aad = EncryptedEnvelopeAad {
            scope_digest: arkret_models_crypto::encrypted_envelope_scope_digest(
                &ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                &realm_id,
            )
            .unwrap(),
            realm_id,
            event_kind: "ak.message.create".to_owned(),
            event_id: Some(
                EventId::new("ak:event:ARVUUS5MsgtJTHxDUnT_24cP4k86XFFUI-95GFfyLv6j").unwrap(),
            ),
            event_ref_digest: None,
            causal_refs: Some(vec![
                EventId::new("ak:event:AYoviZ1XjwFy7zH14Su8a_9FmsyO_vGq1qCW6mLmLP10").unwrap(),
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
    fn aad_and_event_ref_helpers_match_the_registered_encoding_vectors() {
        let fixture = arkret_schema::embedded_json_artifact("fixtures/encoding-fixture.json")
            .expect("encoding fixture must be embedded");
        let case = fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| {
                case["vector_id"].as_str()
                    == Some("ak.vector.encoding.encrypted_envelope_digest.v1")
            })
            .expect("fixture must contain the encrypted payload vector");
        let kat = &case["event_ref_digest_kat"];
        let event_id = EventId::new(kat["event_id"].as_str().unwrap()).unwrap();
        let realm_id = RealmId::new(kat["realm_id"].as_str().unwrap()).unwrap();
        let expected = kat["expected_digest"].as_str().unwrap();

        assert_eq!(AAD_EVENT_REF_DIGEST_CONTEXT, kat["domain_separator_utf8"]);
        assert_eq!(event_ref_digest(&event_id, &realm_id), expected);
        verify_event_ref_digest(&event_id, &realm_id, expected).unwrap();
        assert!(verify_event_ref_digest(&event_id, &realm_id, "sha256:bad").is_err());

        let aad: EncryptedEnvelopeAad =
            serde_json::from_value(case["payload_metadata"]["aad"].clone()).unwrap();
        assert_eq!(
            envelope_aad_digest(&aad).unwrap(),
            case["aad_digest"].as_str().unwrap()
        );
        assert_eq!(
            json_aad_digest(&case["payload_metadata"]["aad"]).unwrap(),
            case["aad_digest"].as_str().unwrap()
        );
    }
}
