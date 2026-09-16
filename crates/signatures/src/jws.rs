//! RFC 7515 detached Ed25519 JWS signer.
//!
//! This module owns only the resolver-free *sign* half of the SDK
//! detached-JWS surface. The verify / DID-resolve / replay-window half is
//! coupled to the `DidResolver` trait and the identity error type, so it
//! lives in `arkret-identity` (`arkret_identity::jws`). Applications use this
//! owner for signing and the identity owner for DID-resolver-driven
//! verification.
//!
//! # Detached JWS shape
//!
//! ```text
//! BASE64URL(PROTECTED_HEADER) || ".." || BASE64URL(SIGNATURE)
//! ```
//!
//! where the signed bytes are
//! `BASE64URL(PROTECTED_HEADER) || "." || BASE64URL(canonical_bytes)`.

use ed25519_dalek::SigningKey;

// Reach the function at its defining module rather than through the crate-root
// re-export: that re-export is gated on `collaboration`, while this module is
// not, so importing it from the root breaks any build without that feature.
use crate::proof::sign_ed25519_detached_jws;

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
/// The protected header is the SDK-canonical `{"alg":"Ed25519"}` — the same byte
/// string `arkret_identity::verify_jws_with_document` accepts. This function is
/// the symmetric counterpart of that verifier: a verify after a sign over the
/// same `canonical_bytes` and a resolver that returns the matching public key
/// always round-trips.
///
/// Rejects empty `canonical_bytes` with `Err` — the verify path does too, so an
/// "empty payload" caller fails fast at sign time instead of producing a JWS
/// that won't verify.
///
/// Callers are responsible for choosing the `verification_method` they
/// advertise alongside this JWS (e.g. `<service_id>#authority-key`); the SDK does
/// not bake the kid into the protected header to keep the signing input
/// byte-stable per RFC 7515 §4.1.4 (kid is not required to be in the protected
/// header for detached use cases).
pub fn sign_jws_ed25519(
    canonical_bytes: &[u8],
    signing_key: &SigningKey,
) -> Result<String, String> {
    sign_ed25519_detached_jws(signing_key, canonical_bytes).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url_decode;
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn sign_jws_ed25519_produces_canonical_detached_shape() {
        let signing = SigningKey::from_bytes(&[1u8; 32]);
        let jws = sign_jws_ed25519(b"hello-world", &signing).expect("sign");
        // Detached form: header..signature (empty payload segment).
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "JWS must have 3 segments");
        assert!(parts[1].is_empty(), "payload segment must be empty");
        // Header decodes to the SDK-canonical Ed25519 marker.
        let header = base64url_decode(parts[0]).expect("header decode");
        assert_eq!(header.as_slice(), br#"{"alg":"Ed25519"}"#);
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
    fn sign_jws_ed25519_is_deterministic_for_same_input_and_key() {
        // ed25519 (per RFC 8032) is deterministic — two signs of the same
        // bytes under the same key MUST produce byte-identical JWS strings.
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let a = sign_jws_ed25519(b"some-canonical-bytes", &signing).unwrap();
        let b = sign_jws_ed25519(b"some-canonical-bytes", &signing).unwrap();
        assert_eq!(a, b);
    }
}
