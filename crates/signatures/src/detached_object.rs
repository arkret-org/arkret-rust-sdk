//! Canonical producer and verifier for [`DetachedObjectSignature`].
//!
//! A detached object signature is the authority-side counterpart of an Event
//! producer proof: the signed body is *not* an Event, so it carries no
//! envelope, no producer proof and no `RealmCommit` of its own. `RealmCommit`,
//! `RealmAuthorityHandoff`, `RealmAuthorityCurrentAssertion`, the Realm
//! snapshot and the MLS Welcome delivery record are all sealed with it.
//!
//! The transcript has two layers and both are mandatory:
//!
//! 1. `signed_digest` is the SHA-256 of the RFC 8785/JCS bytes of the body **without** its
//!    signature member. It is the only thing tying a signature to a body, which is why a verifier
//!    recomputes it instead of trusting the carried value.
//! 2. `sig` is Ed25519 over the context wire string, a newline, then the JCS bytes of the signature
//!    object minus `sig`. That covers the context, the algorithm, the verification method,
//!    `signed_digest` and `created_at` at once, so a signature cannot be lifted into another
//!    context, re-pointed at another key, or re-dated.

use arkret_canonical::base64url::base64url_encode;
use arkret_canonical::canonical;
use arkret_wire::{
    Base64UrlString, DetachedObjectSignature, DetachedSignatureAlgorithm, DetachedSignatureContext,
    DidUrl, Hash,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;

use crate::{Error, PublicKeyMaterial, Result};

/// Exactly the members of [`DetachedObjectSignature`] that `sig` covers.
///
/// `sig` itself is the one excluded member; every other member is bound, so
/// the verifier's reconstruction is total and needs no field allowlist.
#[derive(Serialize)]
struct DetachedSignatureBinding<'a> {
    context: DetachedSignatureContext,
    signature_algorithm: DetachedSignatureAlgorithm,
    verification_method: &'a DidUrl,
    signed_digest: &'a Hash,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
}

/// SHA-256 over the JCS bytes of a body that carries no signature member.
///
/// Callers pass the *unsigned* projection of the object: the signature is what
/// this digest is about to authenticate, so it cannot be inside it.
pub fn detached_object_signed_digest<T: Serialize>(unsigned_body: &T) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(unsigned_body)?).map_err(Into::into)
}

/// The exact bytes `sig` is computed over.
pub fn detached_object_signing_bytes(
    context: DetachedSignatureContext,
    verification_method: &DidUrl,
    signed_digest: &Hash,
    created_at: DateTime<Utc>,
) -> Result<Vec<u8>> {
    let binding = DetachedSignatureBinding {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method,
        signed_digest,
        created_at,
    };
    let canonical_bytes = canonical::canonical_json_bytes(&binding)?;
    let domain = context.as_wire_str();
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical_bytes.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&canonical_bytes);
    Ok(bytes)
}

/// Seal an unsigned body under one context.
///
/// `created_at` is supplied by the caller, never read from the wall clock
/// here: the issuing service owns the observation time it is willing to sign,
/// and a helper that invented one would make the transcript untestable.
pub fn sign_detached_object<T: Serialize>(
    unsigned_body: &T,
    context: DetachedSignatureContext,
    verification_method: DidUrl,
    created_at: DateTime<Utc>,
    signing_key: &SigningKey,
) -> Result<DetachedObjectSignature> {
    let signed_digest = detached_object_signed_digest(unsigned_body)?;
    let bytes =
        detached_object_signing_bytes(context, &verification_method, &signed_digest, created_at)?;
    let signature = signing_key.sign(&bytes);
    Ok(DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method,
        signed_digest,
        created_at,
        sig: Base64UrlString::new(base64url_encode(signature.to_bytes()))
            .map_err(|error| Error::Protocol(format!("invalid detached signature: {error}")))?,
    })
}

/// Verify a detached signature against the body it claims to seal.
///
/// The caller states the context it expects. A signature whose context is
/// merely internally consistent is not enough: the enclosing object decides
/// which of the six contexts is admissible in its position.
pub fn verify_detached_object_signature<T: Serialize>(
    signature: &DetachedObjectSignature,
    unsigned_body: &T,
    expected_context: DetachedSignatureContext,
    public_key: &PublicKeyMaterial,
) -> Result<()> {
    if signature.context != expected_context {
        return Err(Error::Protocol(format!(
            "detached signature carries context {} where {} is required",
            signature.context.as_wire_str(),
            expected_context.as_wire_str()
        )));
    }
    if signature.signed_digest != detached_object_signed_digest(unsigned_body)? {
        return Err(Error::Protocol(
            "detached signature signed_digest does not address the signed body".to_owned(),
        ));
    }
    let bytes = detached_object_signing_bytes(
        signature.context,
        &signature.verification_method,
        &signature.signed_digest,
        signature.created_at,
    )?;
    crate::proof::verify_ed25519_raw_transcript_signature(
        &bytes,
        signature.sig.as_str(),
        public_key,
    )
    .map_err(|error| Error::Protocol(format!("detached object signature is invalid: {error}")))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public(signing_key: &SigningKey) -> PublicKeyMaterial {
        PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        }
    }

    fn method() -> DidUrl {
        DidUrl::new("did:web:authority.example#realm-commit").unwrap()
    }

    fn created_at() -> DateTime<Utc> {
        "2026-09-16T00:00:00.000Z".parse().unwrap()
    }

    #[test]
    fn a_sealed_body_verifies_under_its_own_context() {
        let signing_key = key(11);
        let body = json!({"commit_id": "ak:realm_commit:1", "stream_position": 4});
        let signature = sign_detached_object(
            &body,
            DetachedSignatureContext::RealmCommit,
            method(),
            created_at(),
            &signing_key,
        )
        .unwrap();

        verify_detached_object_signature(
            &signature,
            &body,
            DetachedSignatureContext::RealmCommit,
            &public(&signing_key),
        )
        .unwrap();
        assert_eq!(
            signature.signed_digest,
            detached_object_signed_digest(&body).unwrap()
        );
    }

    #[test]
    fn a_signature_does_not_survive_a_body_mutation() {
        let signing_key = key(13);
        let body = json!({"commit_id": "ak:realm_commit:1", "stream_position": 4});
        let signature = sign_detached_object(
            &body,
            DetachedSignatureContext::RealmSnapshot,
            method(),
            created_at(),
            &signing_key,
        )
        .unwrap();

        let mutated = json!({"commit_id": "ak:realm_commit:1", "stream_position": 5});
        let error = verify_detached_object_signature(
            &signature,
            &mutated,
            DetachedSignatureContext::RealmSnapshot,
            &public(&signing_key),
        )
        .expect_err("a changed body must fail closed");
        assert!(error.to_string().contains("signed_digest"), "{error}");
    }

    /// The context is inside the transcript, so lifting a valid signature into
    /// another position fails on the signature itself, not only on the
    /// caller's expectation check.
    #[test]
    fn a_signature_cannot_be_lifted_into_another_context() {
        let signing_key = key(17);
        let body = json!({"realm_id": "ak:realm:1"});
        let mut signature = sign_detached_object(
            &body,
            DetachedSignatureContext::RealmAuthorityHandoffOld,
            method(),
            created_at(),
            &signing_key,
        )
        .unwrap();

        signature.context = DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance;
        let error = verify_detached_object_signature(
            &signature,
            &body,
            DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            &public(&signing_key),
        )
        .expect_err("a re-tagged signature must fail closed");
        assert!(error.to_string().contains("invalid"), "{error}");
    }

    #[test]
    fn an_unexpected_context_is_refused_before_any_crypto() {
        let signing_key = key(19);
        let body = json!({"realm_id": "ak:realm:1"});
        let signature = sign_detached_object(
            &body,
            DetachedSignatureContext::MlsWelcomeDelivery,
            method(),
            created_at(),
            &signing_key,
        )
        .unwrap();

        let error = verify_detached_object_signature(
            &signature,
            &body,
            DetachedSignatureContext::RealmCommit,
            &public(&signing_key),
        )
        .expect_err("a foreign context must fail closed");
        assert!(error.to_string().contains("where"), "{error}");
    }

    #[test]
    fn a_re_dated_signature_is_refused() {
        let signing_key = key(23);
        let body = json!({"realm_id": "ak:realm:1"});
        let mut signature = sign_detached_object(
            &body,
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            method(),
            created_at(),
            &signing_key,
        )
        .unwrap();

        signature.created_at = "2026-09-16T00:00:01.000Z".parse().unwrap();
        assert!(
            verify_detached_object_signature(
                &signature,
                &body,
                DetachedSignatureContext::RealmAuthorityCurrentAssertion,
                &public(&signing_key),
            )
            .is_err()
        );
    }

    #[test]
    fn another_authority_key_does_not_verify() {
        let signing_key = key(29);
        let body = json!({"realm_id": "ak:realm:1"});
        let signature = sign_detached_object(
            &body,
            DetachedSignatureContext::RealmCommit,
            method(),
            created_at(),
            &signing_key,
        )
        .unwrap();

        assert!(
            verify_detached_object_signature(
                &signature,
                &body,
                DetachedSignatureContext::RealmCommit,
                &public(&key(31)),
            )
            .is_err()
        );
    }
}
