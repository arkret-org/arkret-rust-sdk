//! MLS-Exporter AEAD nonce derivation helpers.
//!
//! v1 deterministic AEAD sender-nonce construction
//! (`nonce = I2OSP(durable_sender_counter, AEAD.Nn)`, per
//! `crypto-media/encryption-and-audit.md`) plus the canonical
//! These moved here from the SDK so the MLS behavior layer can reach them
//! without a dependency cycle back through the umbrella crate.

use std::collections::{BTreeMap, VecDeque};

use arkret_canonical::canonical::{canonical_json_bytes, sha256_bytes, sha256_digest};
use arkret_wire::ReasonCode;
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

/// Compute a SHA-256 digest over arbitrary JSON AAD using canonical JSON.
pub fn json_aad_digest(aad: &Value) -> Result<String> {
    Ok(sha256_prefixed(&canonical_json_bytes(aad)?))
}

/// Compare two strings in constant time after reducing both to fixed-size digests.
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = sha256_bytes(left.as_bytes());
    let right = sha256_bytes(right.as_bytes());
    bool::from(left.ct_eq(&right))
}

#[cfg(test)]
mod tests {
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
}
