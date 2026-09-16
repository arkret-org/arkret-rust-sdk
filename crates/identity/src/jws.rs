//! RFC 7515 detached JWS verifier — Ed25519 only (DID-resolver-driven).
//!
//! The verify and DID-resolve half of the SDK detached-JWS
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
//! Verify-path errors are typed ([`JwsVerifyError`]) so
//! callers can map DID-resolution failures, malformed shapes and signature
//! mismatches to distinct wire `schema_violation` / `signature_invalid` 4xx
//! responses without string sniffing.

use arkret_signatures::PublicKeyMaterial;
use arkret_wire::Did;
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
        source: Box<crate::IdentityError>,
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

/// Resolve a DID URL (`<did>#<key_id>` or just a fragment-less DID) to
/// its Ed25519 [`VerifyingKey`] via the supplied [`DidResolver`].
///
/// Accepts:
///   - DID URL: `did:webvh:z6mkfixture:alice.example#k1` — resolves the DID, then looks up
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
    let did = Did::new(did_str.clone()).map_err(|e| JwsVerifyError::InvalidDid {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_canonical::base64url_encode;
    use chrono::Utc;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{DidDocument, IdentityError};

    /// Minimal in-memory resolver used by the key-resolution tests. Holds a
    /// single `(did, public_key_material)` pair and surfaces it as a one-key
    /// DID Document under the id `{did}#k1`.
    struct StubResolver {
        did: Did,
        material: String,
    }

    impl DidResolver for StubResolver {
        fn supports(&self, did: &Did) -> bool {
            did.as_str() == self.did.as_str()
        }

        fn resolve_did(&self, did: &Did) -> crate::Result<crate::ResolvedDid> {
            if did.as_str() != self.did.as_str() {
                return Err(IdentityError::Protocol(format!(
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
        let did = Did::new("did:web:policy.example".to_owned()).unwrap();
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

    #[test]
    fn single_key_fallback_rejected_for_did_webvh_wrong_fragment() {
        // SEC-02: for a `did:webvh` document with exactly one key, a JWS that
        // references a wrong/absent fragment MUST NOT silently fall back to the
        // sole key — the key-id binding stays strict for multi-key-capable
        // methods.
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let did = Did::new("did:webvh:z6mkfixture:single.example".to_owned()).unwrap();
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
        let did = Did::new(format!("did:key:{multibase}")).unwrap();
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

}
