//! RFC 7515 detached JWS verifier — Ed25519 only (DID-resolver-driven).
//!
//! The verify / DID-resolve / replay-window half of the SDK detached-JWS
//! surface. It is coupled to the [`DidResolver`] trait and
//! this crate's [`IdentityError`](crate::IdentityError), so it lives here rather
//! than in `arkret-signatures` (which owns only the resolver-free
//! `arkret_signatures::jws::sign_jws_ed25519` signer). The umbrella exposes
//! this verifier module directly; signing remains in the signatures owner.
//!
//! # Detached JWS shape
//!
//! ```text
//! BASE64URL(JOSE_HEADER) || '.' || /* empty payload */ || '.' || BASE64URL(SIGNATURE)
//! ```
//!
//! Verify-path errors are typed ([`JwsVerifyError`] / [`ReplayWindowError`]) so
//! callers can map DID-resolution failures, malformed shapes and signature
//! mismatches to distinct wire `schema_violation` / `signature_invalid` 4xx
//! responses without string sniffing.

use arkret_signatures::PublicKeyMaterial;
use arkret_wire::{CellId, DidFullId, Hlc, ProjectedCellWrite};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;

use crate::{DidDocument, DidResolver};

/// Typed failure reasons for the DID-resolution half of the detached-JWS
/// verify pipeline ([`resolve_ed25519_pubkey`]).
///
/// Distinguishes input-shape violations, DID-resolution failures, key-material
/// problems and the signature check itself, so callers can map each family to
/// the right wire error code instead of sniffing message strings.
#[derive(Debug, thiserror::Error)]
pub enum JwsVerifyError {
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
        source: arkret_canonical::CanonicalError,
    },
    /// The verification-method value is neither multibase nor valid JWK JSON.
    #[error("public key material is neither Ed25519 multibase nor JWK JSON: {reason}")]
    PublicKeyMaterialParse { reason: String },
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
        source: arkret_signatures::VerifierError,
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
///   - DID verification methods carrying an Ed25519 `publicKeyJwk` serialized as JSON.
pub fn resolve_ed25519_pubkey(
    resolver: &dyn DidResolver,
    verification_method: &str,
) -> Result<VerifyingKey, JwsVerifyError> {
    let did_str = verification_method
        .split_once('#')
        .map(|(did, _)| did.to_owned())
        .unwrap_or_else(|| verification_method.to_owned());
    let did = DidFullId::new(did_str.clone()).map_err(|e| JwsVerifyError::InvalidDid {
        did: did_str.clone(),
        reason: e.to_string(),
    })?;

    let document =
        resolver
            .resolve_did_document(&did)
            .map_err(|e| JwsVerifyError::DidResolveFailed {
                did: did_str.clone(),
                source: Box::new(e),
            })?;

    resolve_ed25519_pubkey_from_document(&document, verification_method)
}

/// Resolve an Ed25519 verification method from an already-pinned DID document.
///
/// This is the document-only counterpart of [`resolve_ed25519_pubkey`]. It
/// exists so downstream services do not need to wrap a pinned document in a
/// private one-shot [`DidResolver`] merely to reuse canonical key lookup.
pub fn resolve_ed25519_pubkey_from_document(
    document: &DidDocument,
    verification_method: &str,
) -> Result<VerifyingKey, JwsVerifyError> {
    let fragment = verification_method
        .split_once('#')
        .map(|(_, fragment)| fragment);
    let did_str = document.id.as_str();

    // Try full URL first, then fragment-only id, then any single-key
    // shortcut (`did:key:` documents typically have one key whose id
    // matches the full URL).
    let material = document
        .verification_methods
        .get(verification_method)
        .or_else(|| fragment.and_then(|fragment| document.verification_methods.get(fragment)))
        .or_else(|| {
            fragment.and_then(|fragment| document.verification_methods.get(&format!("#{fragment}")))
        })
        .or_else(|| {
            // Single-key fallback: only for `did:key` documents, where the
            // key is embedded in the DID itself and the single verification
            // method's id canonically matches the full URL. Restricting the
            // fallback to `did:key` keeps the `verification_method` key-id
            // binding strict for `did:webvh` (and any multi-key-capable
            // method) so a JWS referencing a wrong/absent fragment is not
            // silently verified against an unrelated key.
            if document.id.method() == "key" && document.verification_methods.len() == 1 {
                document.verification_methods.values().next()
            } else {
                None
            }
        })
        .ok_or_else(|| JwsVerifyError::VerificationMethodNotFound {
            verification_method: verification_method.to_owned(),
            did: did_str.to_owned(),
            available: document.verification_methods.keys().cloned().collect(),
        })?;

    decode_ed25519_public_key_material(material)
}

/// Decode the Ed25519 verification material stored by [`crate::DidDocument`].
///
/// DID resolvers normalize `publicKeyMultibase` to the multibase string and
/// `publicKeyJwk` to a JSON string. This helper accepts both forms so all SDK
/// consumers share the same key-shape checks.
pub fn decode_ed25519_public_key_material(material: &str) -> Result<VerifyingKey, JwsVerifyError> {
    let material = material.trim();
    if material.starts_with('z') {
        return decode_ed25519_multibase(material);
    }

    let value: serde_json::Value =
        serde_json::from_str(material).map_err(|error| JwsVerifyError::PublicKeyMaterialParse {
            reason: error.to_string(),
        })?;
    if let serde_json::Value::String(inner) = value {
        return decode_ed25519_public_key_material(&inner);
    }

    if !value.is_object() {
        return Err(JwsVerifyError::PublicKeyMaterialParse {
            reason: format!("unsupported public key material shape: {value}"),
        });
    }
    let raw = PublicKeyMaterial::Jwk { value }
        .ed25519_bytes()
        .map_err(|error| JwsVerifyError::PublicKeyParse {
            reason: error.to_string(),
        })?;
    VerifyingKey::from_bytes(&raw).map_err(|error| JwsVerifyError::PublicKeyParse {
        reason: error.to_string(),
    })
}

/// Decode a base58btc-encoded multibase Ed25519 public key.
///
/// Format per W3C did:key + did-core verificationMethod: `z` prefix
/// (base58btc multibase indicator) + base58btc(0xed 0x01 || pubkey32).
/// Strips the multicodec varint (0xed01 = ed25519-pub) and extracts the
/// 32-byte raw key.
fn decode_ed25519_multibase(multibase: &str) -> Result<VerifyingKey, JwsVerifyError> {
    // Underlying base58btc + multicodec strip is the single `canonical::multibase`
    // helper (backed by the `bs58` crate); this only adds the VerifyingKey
    // parse + typed-error mapping the JWS verify path expects.
    let key_array = arkret_canonical::decode_ed25519_multibase(multibase)
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

/// Differentiated replay window for a reducer input, based on the cell
/// families its **projected** writes touch. Looks up each write's
/// `cell_family` segment in `per_family_overrides`; takes the **minimum**
/// (tightest) override across all touched cells; falls back to
/// `default_window` if no overrides apply. Returns the same shape as
/// [`verify_replay_window`].
///
/// Rationale: some authority cells (notary, mls.epoch) have much
/// tighter freshness requirements than ordinary message events. Picking
/// the min ensures an Event touching BOTH notary (60s) and an ordinary
/// cell (300s) honors the tighter 60s window.
///
/// The writes are passed in rather than read off the Event because v1 has no
/// producer-written effect array: they are derived from `kind + payload`
/// through the contract registry, which this crate does not hold by layering.
/// Passing an empty slice therefore means "this Event projects no write", not
/// "the projection is unknown" — resolve the projection before calling.
pub fn verify_replay_window_for_projection(
    hlc: &Hlc,
    writes: &[ProjectedCellWrite],
    default_window_seconds: u64,
    per_family_overrides: &std::collections::BTreeMap<&'static str, u64>,
) -> Result<(), ReplayWindowError> {
    verify_replay_window_for_projection_at(
        hlc,
        writes,
        default_window_seconds,
        per_family_overrides,
        Utc::now(),
    )
}

/// Test-friendly variant of [`verify_replay_window_for_projection`] with an
/// injectable wall-clock reference.
pub fn verify_replay_window_for_projection_at(
    hlc: &Hlc,
    writes: &[ProjectedCellWrite],
    default_window_seconds: u64,
    per_family_overrides: &std::collections::BTreeMap<&'static str, u64>,
    now: DateTime<Utc>,
) -> Result<(), ReplayWindowError> {
    let effective =
        effective_window_for_projection(writes, default_window_seconds, per_family_overrides);
    verify_replay_window_at(hlc, effective, now)
}

/// Compute the effective (most-restrictive) replay window for a set of
/// projected writes. `default` applies if no touched cell has an override.
pub fn effective_window_for_projection(
    writes: &[ProjectedCellWrite],
    default_window_seconds: u64,
    per_family_overrides: &std::collections::BTreeMap<&'static str, u64>,
) -> u64 {
    let mut effective = default_window_seconds;
    for write in writes {
        // CellRef shape: `ak:cell:<family>:<subject>` — extract family.
        let Ok(cell_id) = CellId::parse(write.cell.as_str()) else {
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

    use arkret_canonical::base64url_encode;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{DidDocument, Error as SdkError};

    /// Minimal in-memory resolver used by the key-resolution tests. Holds a
    /// single `(did, public_key_material)` pair and surfaces it as a one-key
    /// DID Document under the id `{did}#k1`.
    struct StubResolver {
        did: DidFullId,
        material: String,
    }

    impl DidResolver for StubResolver {
        fn supports(&self, did: &DidFullId) -> bool {
            did.as_str() == self.did.as_str()
        }

        fn resolve_did(&self, did: &DidFullId) -> crate::Result<crate::ResolvedDid> {
            if did.as_str() != self.did.as_str() {
                return Err(SdkError::Protocol(format!(
                    "stub resolver does not handle {did}"
                )));
            }
            let mut verification_methods = BTreeMap::new();
            verification_methods.insert(format!("{}#k1", self.did), self.material.clone());
            Ok(crate::ResolvedDid::proofless(DidDocument {
                id: self.did.clone(),
                verification_methods,
                also_known_as: Vec::new(),
                updated_at: Some(Utc::now()),
                raw_properties: BTreeMap::new(),
            }))
        }
    }

    /// Encode an Ed25519 public key as the multibase form used by did:key
    /// and DID Document verificationMethod entries.
    fn encode_ed25519_multibase(verifying_key: &VerifyingKey) -> String {
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(verifying_key.as_bytes())
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
    fn resolve_ed25519_pubkey_accepts_public_key_jwk() {
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let did = DidFullId::new("did:web:policy.example".to_owned()).unwrap();
        let resolver = StubResolver {
            did: did.clone(),
            material: serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": base64url_encode(signing.verifying_key().as_bytes()),
            })
            .to_string(),
        };

        let resolved = resolve_ed25519_pubkey(&resolver, &format!("{did}#k1")).unwrap();
        assert_eq!(resolved.as_bytes(), signing.verifying_key().as_bytes());
    }

    #[test]
    fn decode_rejects_non_ed25519_public_key_jwk() {
        let material = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": base64url_encode([7u8; 32]),
        })
        .to_string();

        let err = decode_ed25519_public_key_material(&material).unwrap_err();
        assert!(matches!(err, JwsVerifyError::PublicKeyParse { .. }));
        assert!(err.to_string().contains("unsupported JWK for Ed25519"));
    }

    #[test]
    fn decode_rejects_wrong_multicodec_prefix() {
        // 0xe7 is secp256k1-pub, not ed25519.
        let mut bytes = vec![0xe7u8, 0x01];
        bytes.extend_from_slice(&[0u8; 32]);
        let mb = arkret_canonical::encode_multibase_base58btc(bytes);
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

    fn writes_touching(cell_id: &str) -> Vec<ProjectedCellWrite> {
        use arkret_wire::{CellRef, LatticeOp, LatticeOpType, ProjectedOp};
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Set;
        op.value = Some(serde_json::json!({"shape": "test_value", "value": "fixture"}));
        vec![ProjectedCellWrite {
            cell: CellRef::new(cell_id.to_owned()).unwrap(),
            op: ProjectedOp::Direct(op),
        }]
    }

    fn hlc_at(hlc_ms: u64) -> Hlc {
        Hlc::new(format!("{hlc_ms:012x}-0000-aabbccdd")).unwrap()
    }

    #[test]
    fn effective_window_picks_default_when_no_overrides_apply() {
        let w = writes_touching("ak:cell:ak.component.message.create.v1:ak.event.foo");
        let overrides = BTreeMap::new();
        assert_eq!(effective_window_for_projection(&w, 300, &overrides), 300);
    }

    #[test]
    fn effective_window_uses_notary_override_when_notary_cell_touched() {
        let w = writes_touching("ak:cell:ak.component.notary.v1:ak.realm.x");
        let mut overrides = BTreeMap::new();
        overrides.insert(arkret_wire::CellFamilyId::NOTARY_V1, 60u64);
        // Default 300, notary override 60 -> effective 60.
        assert_eq!(effective_window_for_projection(&w, 300, &overrides), 60);
    }

    #[test]
    fn effective_window_takes_minimum_when_default_tighter_than_override() {
        let w = writes_touching("ak:cell:ak.component.notary.v1:ak.realm.x");
        let mut overrides = BTreeMap::new();
        overrides.insert(arkret_wire::CellFamilyId::NOTARY_V1, 600u64); // looser than default
        // Default 300, notary override 600 -> min = 300 (default wins because tighter).
        assert_eq!(effective_window_for_projection(&w, 300, &overrides), 300);
    }

    #[test]
    fn effective_window_zero_default_with_override_uses_override() {
        // Test config has window=0 but spec-critical cells should still
        // be window-checked. The override "wins" in this case.
        let w = writes_touching("ak:cell:ak.component.notary.v1:ak.realm.x");
        let mut overrides = BTreeMap::new();
        overrides.insert(arkret_wire::CellFamilyId::NOTARY_V1, 60u64);
        assert_eq!(effective_window_for_projection(&w, 0, &overrides), 60);
    }

    #[test]
    fn notary_cell_with_60s_override_rejects_2min_old_hlc() {
        let now = Utc::now();
        let two_min_ago_ms = (now - Duration::minutes(2)).timestamp_millis() as u64;
        let w = writes_touching("ak:cell:ak.component.notary.v1:ak.realm.x");
        let hlc = hlc_at(two_min_ago_ms);
        let mut overrides = BTreeMap::new();
        overrides.insert(arkret_wire::CellFamilyId::NOTARY_V1, 60u64);
        let err =
            verify_replay_window_for_projection_at(&hlc, &w, 300, &overrides, now).unwrap_err();
        assert!(
            matches!(err, ReplayWindowError::TooOld { .. }),
            "notary cell with 60s override should reject 2min-old hlc (got `{err}`)"
        );
    }

    #[test]
    fn message_cell_under_default_300s_accepts_2min_old_hlc() {
        let now = Utc::now();
        let two_min_ago_ms = (now - Duration::minutes(2)).timestamp_millis() as u64;
        let w = writes_touching("ak:cell:ak.component.message.create.v1:ak.event.foo");
        let hlc = hlc_at(two_min_ago_ms);
        // Default 300s, no override for message family -> 2min = 120s < 300s -> accept.
        let mut overrides = BTreeMap::new();
        overrides.insert(arkret_wire::CellFamilyId::NOTARY_V1, 60u64);
        verify_replay_window_for_projection_at(&hlc, &w, 300, &overrides, now).unwrap();
    }

    #[test]
    fn single_key_fallback_rejected_for_did_webvh_wrong_fragment() {
        // SEC-02: for a `did:webvh` document with exactly one key, a JWS that
        // references a wrong/absent fragment MUST NOT silently fall back to the
        // sole key — the key-id binding stays strict for multi-key-capable
        // methods.
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let did = DidFullId::new("did:webvh:z6mkfixture:single.example".to_owned()).unwrap();
        let resolver = StubResolver {
            did: did.clone(),
            material: encode_ed25519_multibase(&signing.verifying_key()),
        };
        let err = resolve_ed25519_pubkey(&resolver, &format!("{did}#does-not-exist")).unwrap_err();
        assert!(
            matches!(err, JwsVerifyError::VerificationMethodNotFound { .. }),
            "wrong fragment on did:webvh must not fall back to the single key (got `{err}`)"
        );
    }

    #[test]
    fn single_key_fallback_allowed_for_did_key() {
        // SEC-02: `did:key` documents embed the key in the DID and carry exactly
        // one verification method, so the single-key fallback is still honoured.
        let signing = SigningKey::from_bytes(&[8u8; 32]);
        let multibase = encode_ed25519_multibase(&signing.verifying_key());
        let did = DidFullId::new(format!("did:key:{multibase}")).unwrap();
        let resolver = StubResolver {
            did: did.clone(),
            material: multibase,
        };
        // A reference with a mismatched fragment still resolves via the
        // single-key fallback for did:key.
        let resolved = resolve_ed25519_pubkey(&resolver, &format!("{did}#anything"))
            .expect("did:key fallback");
        assert_eq!(resolved.as_bytes(), signing.verifying_key().as_bytes());
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
