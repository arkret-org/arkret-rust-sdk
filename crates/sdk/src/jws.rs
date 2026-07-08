//! RFC 7515 detached JWS verifier — Ed25519 only.
//!
//! Used by event-envelope `proof.jws` verification and the federation
//! transcript signature path. The SDK ships a single canonical implementation
//! so every consumer (inkson, floria, cotest, teabay, soland) reaches the
//! same `Ok(()) / Err(reason)` decision for the same `(canonical_bytes, jws,
//! verification_method, issuer, resolver)` tuple.
//!
//! # Detached JWS shape
//!
//! ```text
//! BASE64URL(JOSE_HEADER) || '.' || /* empty payload */ || '.' || BASE64URL(SIGNATURE)
//! ```
//!
//! The signer's input was
//! `BASE64URL(JOSE_HEADER) || '.' || BASE64URL(canonical_bytes)`. To
//! verify, reconstruct that string and run `verify(signing_input, sig)`
//! against the resolved public key.
//!
//! # API surface
//!
//! - `sign_jws_ed25519` — produce a detached JWS over `canonical_bytes` with an
//!   `ed25519_dalek::SigningKey`. Symmetric counterpart of `verify_jws_ed25519`: a `verify` after a
//!   `sign` over the same bytes round-trips, given the matching public key resolves through the
//!   supplied `DidResolver`.
//! - `verify_jws_ed25519` — full detached-JWS verify pipeline (shape + alg + DID resolve + Ed25519
//!   verify). Takes a `&dyn DidResolver` so callers control which DID methods are reachable.
//! - `resolve_ed25519_pubkey` — resolve a `did[#frag]` URL to a `VerifyingKey` via the supplied
//!   resolver.
//! - `verify_replay_window` / `verify_replay_window_at` — bound the freshness of an [`Hlc`] against
//!   wall-clock now (or an injected time for tests).
//! - `verify_replay_window_for_move` / `verify_replay_window_for_move_at` — same, but with
//!   per-cell-family overrides so authority-cell Moves (e.g. `ck.component.notary.v1`) can have
//!   tighter freshness windows than ordinary message Moves.
//! - `effective_window_for_move` — exposed for inspection / tests.
//! - `physical_millis_from_hlc` — extract the physical-ms prefix of an HLC string for low-level
//!   freshness telemetry.
//!
//! Verify-path errors are typed ([`JwsVerifyError`] / [`ReplayWindowError`])
//! so callers can map DID-resolution failures, malformed shapes and signature
//! mismatches to distinct wire `schema_violation` / `invalid_signature` 4xx
//! responses without string sniffing.

use chrono::{DateTime, Duration, Utc};
use cokret_core::{Hash, canonical};
use cokret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial, sign_eddsa_detached_jws};
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::identity::DidResolver;
use crate::{Did, Hlc};

/// Typed failure reasons for the detached-JWS verify pipeline
/// ([`verify_jws_ed25519`] / [`resolve_ed25519_pubkey`]).
///
/// Distinguishes input-shape violations, DID-resolution failures, key-material
/// problems and the signature check itself, so callers can map each family to
/// the right wire error code instead of sniffing message strings.
#[derive(Debug, thiserror::Error)]
pub enum JwsVerifyError {
    #[error("empty verification_method")]
    EmptyVerificationMethod,
    #[error("empty issuer")]
    EmptyIssuer,
    #[error("empty canonical bytes")]
    EmptyCanonicalBytes,
    /// The `verification_method` DID failed SDK validation.
    #[error("invalid DID `{did}`: {reason}")]
    InvalidDid { did: String, reason: String },
    /// The resolver chain could not resolve the DID.
    #[error("DID resolve failed for `{did}`: {source}")]
    DidResolveFailed {
        did: String,
        #[source]
        source: Box<crate::Error>,
    },
    /// The DID document has no matching verification method entry.
    #[error(
        "verification_method `{verification_method}` not found in DID document for `{did}` (have {available:?})"
    )]
    VerificationMethodNotFound {
        verification_method: String,
        did: String,
        available: Vec<String>,
    },
    /// The verification-method value is not a valid multibase Ed25519 key.
    #[error("ed25519 multibase decode failed: {source}")]
    MultibaseDecode {
        #[source]
        source: cokret_core::Error,
    },
    /// The decoded key bytes do not form a valid Ed25519 public key.
    #[error("Ed25519 public key parse failed: {reason}")]
    PublicKeyParse { reason: String },
    /// The canonical-bytes digest could not be constructed.
    #[error("event digest construction failed: {reason}")]
    Digest { reason: String },
    /// JWS shape / header / signature rejected by the detached-JWS verifier.
    #[error("detached JWS rejected: {source}")]
    Proof {
        #[source]
        source: cokret_signatures::VerifierError,
    },
}

/// Typed failure reasons for the HLC replay-window freshness checks
/// ([`verify_replay_window`] and variants).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReplayWindowError {
    /// The HLC string had no parsable physical-ms prefix.
    #[error("HLC physical-ms hex `{physical_hex}` parse failed")]
    PhysicalMsParse { physical_hex: String },
    /// The parsed physical-ms is outside chrono's representable range.
    #[error("HLC physical-ms {physical_ms} is out of representable range")]
    PhysicalMsOutOfRange { physical_ms: i64 },
    /// The HLC is older than the window allows.
    #[error(
        "HLC signed at {signed_at} is too old (now-signed = {age_seconds}s; window = {window_seconds}s)"
    )]
    TooOld {
        signed_at: DateTime<Utc>,
        age_seconds: i64,
        window_seconds: u64,
    },
    /// The HLC is further in the future than the window allows.
    #[error(
        "HLC signed at {signed_at} is too far in the future (signed-now = {ahead_seconds}s; window = {window_seconds}s)"
    )]
    TooFarInFuture {
        signed_at: DateTime<Utc>,
        ahead_seconds: i64,
        window_seconds: u64,
    },
}

/// Produce a detached Ed25519 JWS over `canonical_bytes`.
///
/// Wire shape (RFC 7515 §3.2 detached form):
///
/// ```text
/// BASE64URL(PROTECTED_HEADER) || ".." || BASE64URL(SIGNATURE)
/// ```
///
/// where the signed bytes are
/// `BASE64URL(PROTECTED_HEADER) || "." || BASE64URL(canonical_bytes)`.
///
/// The protected header is the SDK-canonical `{"alg":"EdDSA"}` — the
/// same byte string [`verify_jws_ed25519`] accepts. This function is
/// the symmetric counterpart of `verify_jws_ed25519`: a verify after a
/// sign over the same `canonical_bytes` and a resolver that returns
/// the matching public key always round-trips.
///
/// Rejects empty `canonical_bytes` with `Err` — the verify path does
/// too, so an "empty payload" caller fails fast at sign time instead
/// of producing a JWS that won't verify.
///
/// Callers are responsible for choosing the `verification_method`
/// they advertise alongside this JWS (e.g. `<service_did>#notary-key`);
/// the SDK doesn't bake the kid into the protected header to keep the
/// signing input byte-stable per RFC 7515 §4.1.4 (kid is not required
/// to be in the protected header for detached use cases).
pub fn sign_jws_ed25519(
    canonical_bytes: &[u8],
    signing_key: &SigningKey,
) -> Result<String, String> {
    sign_eddsa_detached_jws(signing_key, canonical_bytes).map_err(|error| error.to_string())
}

/// Verify a detached Ed25519 JWS against `canonical_bytes`.
///
/// Returns `Ok(())` on successful verification (shape valid + DID resolves
/// + signature checks against `canonical_bytes`); a typed [`JwsVerifyError`]
/// otherwise.
///
/// All error paths are uniform — any deviation from spec rejects with a
/// typed reason (callers map to `schema_violation` 4xx, never 5xx).
pub fn verify_jws_ed25519(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    resolver: &dyn DidResolver,
) -> Result<(), JwsVerifyError> {
    if verification_method.is_empty() {
        return Err(JwsVerifyError::EmptyVerificationMethod);
    }
    if issuer.is_empty() {
        return Err(JwsVerifyError::EmptyIssuer);
    }
    if canonical_bytes.is_empty() {
        return Err(JwsVerifyError::EmptyCanonicalBytes);
    }

    // Resolve verification_method via the supplied resolver chain. All JWS
    // shape/header/signature checks are delegated to cokret-signatures.
    let public_key = resolve_ed25519_pubkey(resolver, verification_method)?;
    let proof = cokret_core::Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: verification_method.to_owned(),
        event_digest: Hash::new(canonical::sha256_digest(canonical_bytes)).map_err(|error| {
            JwsVerifyError::Digest {
                reason: error.to_string(),
            }
        })?,
        created_at: Utc::now(),
        domain: None,
        audience: None,
        jws: jws.to_owned(),
    };
    let material = PublicKeyMaterial::Ed25519Raw {
        bytes: public_key.to_bytes().to_vec(),
    };
    Ed25519DetachedJwsVerifier::new()
        .verify_proof(&proof, canonical_bytes, &material)
        .map_err(|source| JwsVerifyError::Proof { source })
}

/// Resolve a DID URL (`<did>#<key_id>` or just a fragment-less DID) to
/// its Ed25519 [`VerifyingKey`] via the supplied [`DidResolver`].
///
/// Accepts:
///   - Full DID URL: `did:webvh:z6mkfixture:alice.example#k1` — resolves the DID, then looks up
///     `verification_methods["did:webvh:z6mkfixture:alice.example#k1"]`.
///   - Fragment fallback: if the full URL isn't a key, also tries the fragment-only key id (`#k1` →
///     `k1`).
///   - did:key: the multibase-encoded key is in the DID itself; resolve returns a doc whose
///     verification_methods entry points at the same multibase string.
pub fn resolve_ed25519_pubkey(
    resolver: &dyn DidResolver,
    verification_method: &str,
) -> Result<VerifyingKey, JwsVerifyError> {
    let (did_str, fragment) = verification_method
        .split_once('#')
        .map(|(d, f)| (d.to_owned(), Some(f.to_owned())))
        .unwrap_or_else(|| (verification_method.to_owned(), None));
    let did = Did::new(did_str.clone()).map_err(|e| JwsVerifyError::InvalidDid {
        did: did_str.clone(),
        reason: e.to_string(),
    })?;

    let document = resolver
        .resolve_did(&did)
        .map_err(|e| JwsVerifyError::DidResolveFailed {
            did: did_str.clone(),
            source: Box::new(e),
        })?;

    // Try full URL first, then fragment-only id, then any single-key
    // shortcut (`did:key:` documents typically have one key whose id
    // matches the full URL).
    let multibase = document
        .verification_methods
        .get(verification_method)
        .or_else(|| {
            fragment
                .as_ref()
                .and_then(|f| document.verification_methods.get(f))
        })
        .or_else(|| {
            // Single-key fallback: if there's exactly one verification
            // method, use it (common for did:key documents).
            if document.verification_methods.len() == 1 {
                document.verification_methods.values().next()
            } else {
                None
            }
        })
        .ok_or_else(|| JwsVerifyError::VerificationMethodNotFound {
            verification_method: verification_method.to_owned(),
            did: did_str.clone(),
            available: document.verification_methods.keys().cloned().collect(),
        })?;

    decode_ed25519_multibase(multibase)
}

/// Decode a base58btc-encoded multibase Ed25519 public key.
///
/// Format per W3C did:key + did-core verificationMethod: `z` prefix
/// (base58btc multibase indicator) + base58btc(0xed 0x01 || pubkey32).
/// Strips the multicodec varint (0xed01 = ed25519-pub) and extracts the
/// 32-byte raw key.
fn decode_ed25519_multibase(multibase: &str) -> Result<VerifyingKey, JwsVerifyError> {
    // Underlying base58btc + multicodec strip is the single `core::multibase`
    // helper (backed by the `bs58` crate); this only adds the VerifyingKey
    // parse + typed-error mapping the JWS verify path expects.
    let key_array = cokret_core::decode_ed25519_multibase(multibase)
        .map_err(|source| JwsVerifyError::MultibaseDecode { source })?;
    VerifyingKey::from_bytes(&key_array).map_err(|e| JwsVerifyError::PublicKeyParse {
        reason: e.to_string(),
    })
}

/// JWS replay protection: verify the SIGNED `Hlc` is within `±window`
/// of wall-clock now. Replay attackers who capture a valid `(canonical_bytes,
/// jws)` pair cannot reuse it past this window because the HLC is bound
/// into the signed canonical bytes (content-addressed id derives from
/// the same bytes), and the window check bounds the gap between sign
/// time and verify time.
///
/// `window_seconds = 0` disables the check (returns Ok without inspecting
/// the HLC). Production deploys MUST keep `window_seconds > 0`.
pub fn verify_replay_window(hlc: &Hlc, window_seconds: u64) -> Result<(), ReplayWindowError> {
    verify_replay_window_at(hlc, window_seconds, Utc::now())
}

/// Differentiated replay window for a Move based on the cell families
/// its `effects[]` touch. Looks up each effect's `cell_family` segment
/// in `per_family_overrides`; takes the **minimum** (tightest) override
/// across all touched cells; falls back to `default_window` if no
/// overrides apply. Returns the same shape as [`verify_replay_window`].
///
/// Rationale: some authority cells (notary, mls.epoch) have much
/// tighter freshness requirements than ordinary message events. Picking
/// the min ensures a Move with effects on BOTH notary (60s) and an
/// ordinary cell (300s) honors the tighter 60s window.
pub fn verify_replay_window_for_move(
    move_obj: &crate::Move,
    default_window_seconds: u64,
    per_family_overrides: &std::collections::BTreeMap<&'static str, u64>,
) -> Result<(), ReplayWindowError> {
    verify_replay_window_for_move_at(
        move_obj,
        default_window_seconds,
        per_family_overrides,
        Utc::now(),
    )
}

/// Test-friendly variant of [`verify_replay_window_for_move`] with an
/// injectable wall-clock reference.
pub fn verify_replay_window_for_move_at(
    move_obj: &crate::Move,
    default_window_seconds: u64,
    per_family_overrides: &std::collections::BTreeMap<&'static str, u64>,
    now: DateTime<Utc>,
) -> Result<(), ReplayWindowError> {
    let effective =
        effective_window_for_move(move_obj, default_window_seconds, per_family_overrides);
    verify_replay_window_at(&move_obj.hlc, effective, now)
}

/// Compute the effective (most-restrictive) replay window for a Move's
/// effects. `default` applies if no effect cell has an override.
pub fn effective_window_for_move(
    move_obj: &crate::Move,
    default_window_seconds: u64,
    per_family_overrides: &std::collections::BTreeMap<&'static str, u64>,
) -> u64 {
    let mut effective = default_window_seconds;
    for effect in &move_obj.effects {
        // CellRef shape: `ck:cell:<family>:<subject>` — extract family.
        let Ok(cell_id) = crate::CellId::parse(effect.cell.as_str()) else {
            continue;
        };
        let family = cell_id.component();
        if let Some(&override_secs) = per_family_overrides.get(family) {
            // 0 means "disabled" same as default; only a non-zero override
            // can be tighter than default. Special case: if default is 0
            // (disabled) and override is non-zero, the override wins (it
            // tightens an otherwise-disabled check).
            effective = if effective == 0 {
                override_secs
            } else {
                effective.min(override_secs)
            };
        }
    }
    effective
}

/// Extract the physical-millis prefix of an HLC string. Format is
/// `<12-hex-physical-ms>-<8-hex-logical>-<8-hex-node>`. Returns `None`
/// when the prefix can't be parsed; callers MUST treat that as "freshness
/// check is unavailable" rather than as a pass.
pub fn physical_millis_from_hlc(hlc_str: &str) -> Option<i64> {
    let physical_hex = hlc_str.split('-').next()?;
    i64::from_str_radix(physical_hex, 16).ok()
}

/// Same as [`verify_replay_window`] but with an injectable wall-clock
/// reference for unit tests.
pub fn verify_replay_window_at(
    hlc: &Hlc,
    window_seconds: u64,
    now: DateTime<Utc>,
) -> Result<(), ReplayWindowError> {
    if window_seconds == 0 {
        return Ok(());
    }
    let hlc_str = hlc.as_str();
    // HLC format: `<12-hex-physical-ms>-<8-hex-logical>-<8-hex-node>`. The
    // SDK's `Hlc::new` already validated the shape; we just parse the
    // first segment back to milliseconds. `split().next()` on a non-empty
    // string always yields a segment, so only the hex parse can fail here.
    let physical_hex = hlc_str.split('-').next().unwrap_or_default();
    let physical_ms =
        i64::from_str_radix(physical_hex, 16).map_err(|_| ReplayWindowError::PhysicalMsParse {
            physical_hex: physical_hex.to_owned(),
        })?;
    let signed_at = DateTime::<Utc>::from_timestamp_millis(physical_ms)
        .ok_or(ReplayWindowError::PhysicalMsOutOfRange { physical_ms })?;
    let window = Duration::seconds(window_seconds as i64);
    let delta = now - signed_at;
    if delta > window {
        return Err(ReplayWindowError::TooOld {
            signed_at,
            age_seconds: delta.num_seconds(),
            window_seconds,
        });
    }
    if -delta > window {
        return Err(ReplayWindowError::TooFarInFuture {
            signed_at,
            ahead_seconds: (-delta).num_seconds(),
            window_seconds,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use cokret_core::{base64url_decode, base64url_encode};
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::Error as SdkError;
    use crate::identity::DidDocument;

    /// Minimal in-memory resolver used by the sign-then-verify round-trip
    /// tests. Holds a single `(did, multibase_pubkey)` pair and surfaces
    /// it as a one-key DID Document so the verify path's
    /// "single-key fallback" lookup succeeds for arbitrary
    /// `verification_method` strings.
    struct StubResolver {
        did: Did,
        multibase: String,
    }

    impl DidResolver for StubResolver {
        fn supports(&self, did: &Did) -> bool {
            did.as_str() == self.did.as_str()
        }

        fn resolve_did(&self, did: &Did) -> crate::Result<DidDocument> {
            if did.as_str() != self.did.as_str() {
                return Err(SdkError::Protocol(format!(
                    "stub resolver does not handle {did}"
                )));
            }
            let mut verification_methods = BTreeMap::new();
            verification_methods.insert(format!("{}#k1", self.did), self.multibase.clone());
            Ok(DidDocument {
                id: self.did.clone(),
                verification_methods,
                also_known_as: Vec::new(),
                updated_at: Utc::now(),
            })
        }
    }

    /// Encode an Ed25519 public key as the multibase form used by did:key
    /// and DID Document verificationMethod entries. Pure test helper that
    /// reuses the single `core::multibase` encoder.
    fn encode_ed25519_multibase(verifying_key: &VerifyingKey) -> String {
        cokret_core::ed25519_pubkey_to_did_key_multibase(verifying_key.as_bytes())
    }

    #[test]
    fn round_trip_multibase_decode_recovers_public_key() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let verifying = signing.verifying_key();
        let multibase = encode_ed25519_multibase(&verifying);
        let decoded = decode_ed25519_multibase(&multibase).expect("decode");
        assert_eq!(decoded.as_bytes(), verifying.as_bytes());
    }

    #[test]
    fn decode_rejects_wrong_multicodec_prefix() {
        // 0xe7 is secp256k1-pub, not ed25519.
        let mut bytes = vec![0xe7u8, 0x01];
        bytes.extend_from_slice(&[0u8; 32]);
        let mb = cokret_core::encode_multibase_base58btc(bytes);
        let err = decode_ed25519_multibase(&mb).unwrap_err();
        assert!(matches!(err, JwsVerifyError::MultibaseDecode { .. }));
        assert!(err.to_string().contains("ed25519-pub multicodec"));
    }

    #[test]
    fn decode_rejects_missing_z_prefix() {
        let err = decode_ed25519_multibase("not-multibase").unwrap_err();
        assert!(matches!(err, JwsVerifyError::MultibaseDecode { .. }));
        assert!(err.to_string().contains("missing 'z' prefix"));
    }

    // -- Replay-window tests --

    fn hlc_at_ms(physical_ms: u64) -> Hlc {
        Hlc::new(format!("{physical_ms:012x}-0000-aabbccdd")).unwrap()
    }

    #[test]
    fn replay_window_zero_seconds_disables_check_for_any_hlc() {
        // Even an HLC from 1970 passes when window=0.
        let hlc = hlc_at_ms(0);
        verify_replay_window(&hlc, 0).unwrap();
    }

    #[test]
    fn replay_window_accepts_hlc_within_bounds() {
        let now = Utc::now();
        let hlc = hlc_at_ms(now.timestamp_millis() as u64);
        verify_replay_window_at(&hlc, 300, now).unwrap();
    }

    #[test]
    fn replay_window_rejects_stale_hlc() {
        let now = Utc::now();
        // 1 hour old, window 5 min.
        let stale_ms = (now - Duration::hours(1)).timestamp_millis() as u64;
        let hlc = hlc_at_ms(stale_ms);
        let err = verify_replay_window_at(&hlc, 300, now).unwrap_err();
        assert!(
            matches!(err, ReplayWindowError::TooOld { .. }),
            "stale HLC must reject as TooOld (got `{err}`)"
        );
    }

    #[test]
    fn replay_window_rejects_future_hlc() {
        let now = Utc::now();
        let future_ms = (now + Duration::hours(1)).timestamp_millis() as u64;
        let hlc = hlc_at_ms(future_ms);
        let err = verify_replay_window_at(&hlc, 300, now).unwrap_err();
        assert!(
            matches!(err, ReplayWindowError::TooFarInFuture { .. }),
            "future HLC must reject as TooFarInFuture (got `{err}`)"
        );
    }

    // -- Per-family override tests --

    fn build_test_move_touching(cell_id: &str, hlc_ms: u64) -> crate::Move {
        use crate::{CellRef, Hash, MoveId, MoveSignature, SealBasis};
        crate::Move {
            id: MoveId::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            issuer: Did::new("did:webvh:z6mkfixture:test").unwrap(),
            realm_id: crate::RealmId::new(
                "ck:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            )
            .unwrap(),
            preconditions: vec![],
            effects: vec![crate::Effect {
                cell: CellRef::new(cell_id.to_owned()).unwrap(),
                op: crate::LatticeOp {
                    op_type: crate::LatticeOpType::Set,
                    tag: None,
                    value: Some(
                        serde_json::json!({"shape": "single_did", "did": "did:webvh:z6mkfixture:foo"}),
                    ),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            }],
            seal_basis: SealBasis {
                leaves: vec![
                    crate::SealId::new(format!("ck:seal:sha256:{}", "00".repeat(32))).unwrap(),
                ],
                control_event_set_root: Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
                state_root: Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap(),
            },
            refs: vec![],
            hlc: Hlc::new(format!("{hlc_ms:012x}-0000-aabbccdd")).unwrap(),
            sig: MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: "did:webvh:z6mkfixture:test#k1".to_owned(),
                payload_digest: Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap(),
                created_at: Utc::now(),
                jws: "eyJhbGciOiJFZERTQSJ9..ZmFrZS1zaWctZm9yLXRlc3Rz".to_owned(),
            },
        }
    }

    #[test]
    fn effective_window_picks_default_when_no_overrides_apply() {
        let m = build_test_move_touching("ck:cell:ck.component.message.create.v1:ck.event.foo", 0);
        let overrides = BTreeMap::new();
        assert_eq!(effective_window_for_move(&m, 300, &overrides), 300);
    }

    #[test]
    fn effective_window_uses_notary_override_when_notary_cell_touched() {
        let m = build_test_move_touching("ck:cell:ck.component.notary.v1:ck.realm.x", 0);
        let mut overrides = BTreeMap::new();
        overrides.insert("ck.component.notary.v1", 60u64);
        // Default 300, notary override 60 -> effective 60.
        assert_eq!(effective_window_for_move(&m, 300, &overrides), 60);
    }

    #[test]
    fn effective_window_takes_minimum_when_default_tighter_than_override() {
        let m = build_test_move_touching("ck:cell:ck.component.notary.v1:ck.realm.x", 0);
        let mut overrides = BTreeMap::new();
        overrides.insert("ck.component.notary.v1", 600u64); // looser than default
        // Default 300, notary override 600 -> min = 300 (default wins because tighter).
        assert_eq!(effective_window_for_move(&m, 300, &overrides), 300);
    }

    #[test]
    fn effective_window_zero_default_with_override_uses_override() {
        // Test config has window=0 but spec-critical cells should still
        // be window-checked. The override "wins" in this case.
        let m = build_test_move_touching("ck:cell:ck.component.notary.v1:ck.realm.x", 0);
        let mut overrides = BTreeMap::new();
        overrides.insert("ck.component.notary.v1", 60u64);
        assert_eq!(effective_window_for_move(&m, 0, &overrides), 60);
    }

    #[test]
    fn notary_cell_with_60s_override_rejects_2min_old_hlc() {
        let now = Utc::now();
        let two_min_ago_ms = (now - Duration::minutes(2)).timestamp_millis() as u64;
        let m =
            build_test_move_touching("ck:cell:ck.component.notary.v1:ck.realm.x", two_min_ago_ms);
        let mut overrides = BTreeMap::new();
        overrides.insert("ck.component.notary.v1", 60u64);
        let err = verify_replay_window_for_move_at(&m, 300, &overrides, now).unwrap_err();
        assert!(
            matches!(err, ReplayWindowError::TooOld { .. }),
            "notary cell with 60s override should reject 2min-old hlc (got `{err}`)"
        );
    }

    #[test]
    fn message_cell_under_default_300s_accepts_2min_old_hlc() {
        let now = Utc::now();
        let two_min_ago_ms = (now - Duration::minutes(2)).timestamp_millis() as u64;
        let m = build_test_move_touching(
            "ck:cell:ck.component.message.create.v1:ck.event.foo",
            two_min_ago_ms,
        );
        // Default 300s, no override for message family -> 2min = 120s < 300s -> accept.
        let mut overrides = BTreeMap::new();
        overrides.insert("ck.component.notary.v1", 60u64);
        verify_replay_window_for_move_at(&m, 300, &overrides, now).unwrap();
    }

    // -- Sign / sign+verify round-trip tests --

    #[test]
    fn sign_jws_ed25519_produces_canonical_detached_shape() {
        let signing = SigningKey::from_bytes(&[1u8; 32]);
        let jws = sign_jws_ed25519(b"hello-world", &signing).expect("sign");
        // Detached form: header..signature (empty payload segment).
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "JWS must have 3 segments");
        assert!(parts[1].is_empty(), "payload segment must be empty");
        // Header decodes to the SDK-canonical EdDSA marker.
        let header = base64url_decode(parts[0]).expect("header decode");
        assert_eq!(header.as_slice(), br#"{"alg":"EdDSA"}"#);
        // Signature decodes to exactly 64 bytes.
        let sig = base64url_decode(parts[2]).expect("sig decode");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn sign_jws_ed25519_rejects_empty_payload() {
        let signing = SigningKey::from_bytes(&[2u8; 32]);
        let err = sign_jws_ed25519(b"", &signing).unwrap_err();
        assert!(
            err.contains("canonical bytes must not be empty"),
            "got `{err}`"
        );
    }

    #[test]
    fn verify_jws_ed25519_rejects_duplicate_protected_header_key() {
        let signing = SigningKey::from_bytes(&[2u8; 32]);
        let did = Did::new("did:webvh:z6mkfixture:duplicate-header.example".to_owned()).unwrap();
        let resolver = StubResolver {
            did: did.clone(),
            multibase: encode_ed25519_multibase(&signing.verifying_key()),
        };
        let header = base64url_encode(br#"{"alg":"EdDSA","alg":"EdDSA"}"#);
        let signature = base64url_encode([1u8; 64]);
        let jws = format!("{header}..{signature}");

        let err = verify_jws_ed25519(b"{}", &jws, &format!("{did}#k1"), did.as_str(), &resolver)
            .unwrap_err();
        assert!(matches!(err, JwsVerifyError::Proof { .. }), "got `{err}`");
        let rendered = err.to_string();
        assert!(
            rendered.contains("duplicate key") || rendered.contains("canonical JSON"),
            "got `{rendered}`"
        );
    }

    #[test]
    fn sign_jws_ed25519_is_deterministic_for_same_input_and_key() {
        // ed25519 (per RFC 8032) is deterministic — two signs of the same
        // bytes under the same key MUST produce byte-identical JWS strings.
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let a = sign_jws_ed25519(b"some-canonical-bytes", &signing).unwrap();
        let b = sign_jws_ed25519(b"some-canonical-bytes", &signing).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn sign_then_verify_jws_ed25519_round_trips() {
        let signing = SigningKey::from_bytes(&[4u8; 32]);
        let verifying = signing.verifying_key();
        let multibase = encode_ed25519_multibase(&verifying);
        let did = Did::new("did:webvh:z6mkfixture:roundtrip.example".to_owned()).unwrap();
        let resolver = StubResolver {
            did: did.clone(),
            multibase,
        };

        let canonical = br#"{"hello":"world","n":42}"#;
        let jws = sign_jws_ed25519(canonical, &signing).expect("sign");
        verify_jws_ed25519(
            canonical,
            &jws,
            &format!("{did}#k1"),
            did.as_str(),
            &resolver,
        )
        .expect("verify");
    }

    #[test]
    fn verify_rejects_tampered_payload_after_sign() {
        let signing = SigningKey::from_bytes(&[5u8; 32]);
        let verifying = signing.verifying_key();
        let multibase = encode_ed25519_multibase(&verifying);
        let did = Did::new("did:webvh:z6mkfixture:tamper.example".to_owned()).unwrap();
        let resolver = StubResolver {
            did: did.clone(),
            multibase,
        };

        let canonical = b"original-bytes";
        let jws = sign_jws_ed25519(canonical, &signing).expect("sign");
        // Flip a byte in the canonical input the verifier reconstructs the
        // signing string from — signature MUST fail.
        let tampered = b"tampered-bytes";
        let err = verify_jws_ed25519(
            tampered,
            &jws,
            &format!("{did}#k1"),
            did.as_str(),
            &resolver,
        )
        .unwrap_err();
        assert!(matches!(err, JwsVerifyError::Proof { .. }), "got `{err}`");
        assert!(
            err.to_string().contains("signature verification failed"),
            "got `{err}`"
        );
    }

    #[test]
    fn replay_window_accepts_hlc_at_exact_boundary() {
        // Build `now` at exact ms granularity so `now - signed_at` matches
        // `window` to the millisecond (HLC physical-ms truncates sub-ms,
        // so the verifier's parsed `signed_at` is also ms-aligned).
        let raw = Utc::now();
        let now_ms = raw.timestamp_millis();
        let now = DateTime::<Utc>::from_timestamp_millis(now_ms).unwrap();
        // Exactly 300s old -- boundary case (delta == window, so still pass).
        let boundary_ms = (now - Duration::seconds(300)).timestamp_millis() as u64;
        let hlc = hlc_at_ms(boundary_ms);
        verify_replay_window_at(&hlc, 300, now).unwrap();
    }
}
