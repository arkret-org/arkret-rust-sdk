//! Ed25519 backend for the [`PayloadSigner`] trait.
//!
//! Production Move/Seal signer. Wraps an
//! `ed25519_dalek::SigningKey` and produces detached JWS strings whose
//! payload is the canonical bytes of the Move/Seal body. Available
//! behind the `signer` feature.
//!
//! ```
//! use arkret_signatures::Ed25519PayloadSigner;
//! use arkret_wire::{Did, DidUrl, PayloadSigner};
//!
//! let seed = [0u8; 32];
//! let did = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
//! let signer = Ed25519PayloadSigner::from_did_key_seed(
//!     seed,
//!     did,
//!     DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
//! );
//! assert_eq!(
//!     signer.signer_did().as_str(),
//!     "did:webvh:z6mkfixture:alice.example"
//! );
//! ```

use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use arkret_canonical::canonical;
use arkret_wire::{
    Did, DidUrl, Hash, PayloadSignature, PayloadSigner, Result as WireResult, WireError,
};
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::{Error, Result};

/// Ed25519 [`PayloadSigner`] backend.
///
/// `signing_key` holds the raw 32-byte ed25519 secret; `did` is the issuer
/// DID published as `Move.issuer` (or one of the notary set members);
/// `kid` is the verification method id (`<did>#<fragment>`) that goes into
/// `PayloadSignature.verification_method`.
pub struct Ed25519PayloadSigner {
    signing_key: SigningKey,
    did: Did,
    kid: DidUrl,
}

impl Ed25519PayloadSigner {
    /// Wrap an existing `ed25519_dalek::SigningKey`.
    pub fn new(signing_key: SigningKey, did: Did, verification_method_id: DidUrl) -> Self {
        Self {
            signing_key,
            did,
            kid: verification_method_id,
        }
    }

    /// Convenience constructor that derives an ed25519 keypair from a 32-byte
    /// seed (RFC 8032 secret-key seed).
    pub fn from_did_key_seed(seed: [u8; 32], did: Did, verification_method_id: DidUrl) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        Self::new(signing_key, did, verification_method_id)
    }

    /// Borrow the verifying public key (32-byte ed25519 verifying key).
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl PayloadSigner for Ed25519PayloadSigner {
    fn signer_did(&self) -> &Did {
        &self.did
    }

    fn verification_method_id(&self) -> &DidUrl {
        &self.kid
    }

    fn sign_payload(&self, canonical_bytes: &[u8]) -> WireResult<PayloadSignature> {
        // Detached JWS over canonical bytes: SDK-canonical header
        // `{"alg":"Ed25519"}` (no `typ`, matching spec §6 / soland / cotest /
        // teabay), then base64url-no-pad(header) + "." + "" (detached
        // payload) + "." + base64url-no-pad(signature). Per spec §3 the SDK
        // keeps the JWS detached so the receiver re-derives the payload from
        // the canonical body bytes rather than from the JWS itself.
        let header = r#"{"alg":"Ed25519"}"#;
        let header_b64 = base64url_encode(header.as_bytes());
        let signing_input = format!("{header_b64}.{}", base64url_encode(canonical_bytes));
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = base64url_encode(signature.to_bytes());
        let jws = format!("{header_b64}..{sig_b64}");

        let payload_digest = Hash::new(canonical::sha256_digest(canonical_bytes))
            .map_err(|err| WireError::Protocol(format!("invalid canonical hash: {err}")))?;

        Ok(PayloadSignature {
            verification_method: self.kid.clone(),
            payload_digest,
            created_at: Utc::now(),
            jws,
        })
    }

    fn sign_notary_payload_with_digest_suite(
        &self,
        canonical_bytes: &[u8],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> WireResult<PayloadSignature> {
        let header = canonical::canonical_json_bytes(&serde_json::json!({
            "alg": "Ed25519",
            "kid": self.kid,
        }))
        .map_err(|err| WireError::Protocol(format!("invalid notary protected header: {err}")))?;
        let header_b64 = base64url_encode(header);
        let signing_input = format!("{header_b64}.{}", base64url_encode(canonical_bytes));
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let jws = format!("{header_b64}..{}", base64url_encode(signature.to_bytes()));
        let payload_digest = Hash::new(canonical::digest(digest_suite, canonical_bytes))
            .map_err(|err| WireError::Protocol(format!("invalid canonical hash: {err}")))?;

        Ok(PayloadSignature {
            verification_method: self.kid.clone(),
            payload_digest,
            created_at: Utc::now(),
            jws,
        })
    }
}

/// Best-effort verification of a [`PayloadSignature`] produced by an
/// [`Ed25519PayloadSigner`]. Useful for tests and round-trip vectors.
///
/// Returns `Ok(())` on success, `Err(Error::Protocol(...))` if the canonical
/// bytes don't match the declared `payload_digest` or the signature fails to
/// verify against the supplied public key.
pub fn verify_ed25519_payload_signature(
    canonical_bytes: &[u8],
    sig: &PayloadSignature,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    let expected = canonical::sha256_digest(canonical_bytes);
    if sig.payload_digest.as_str() != expected {
        return Err(Error::Protocol(format!(
            "payload_digest {} does not match canonical bytes hash {}",
            sig.payload_digest, expected
        )));
    }
    let parts: Vec<&str> = sig.jws.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Protocol(
            "Ed25519 detached JWS must have three '.'-separated parts".to_owned(),
        ));
    }
    let header_b64 = parts[0];
    let sig_b64 = parts[2];
    if !parts[1].is_empty() {
        return Err(Error::Protocol(
            "Ed25519 detached JWS payload segment must be empty".to_owned(),
        ));
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProtectedHeader {
        alg: String,
        #[serde(default)]
        typ: Option<String>,
        #[serde(default)]
        crit: Option<serde_json::Value>,
    }
    let header_bytes = base64url_decode(header_b64)
        .map_err(|err| Error::Protocol(format!("invalid header base64: {err}")))?;
    let header: ProtectedHeader = canonical::from_canonical_json_slice(&header_bytes)
        .map_err(|err| Error::Protocol(format!("invalid protected header: {err}")))?;
    if header.alg != "Ed25519" {
        return Err(Error::Protocol(
            "payload signature and protected header alg must both be Ed25519".to_owned(),
        ));
    }
    if header.typ.is_some() || header.crit.is_some() {
        return Err(Error::Protocol(
            "detached JWS does not support typ or crit headers".to_owned(),
        ));
    }
    let sig_bytes = base64url_decode(sig_b64)
        .map_err(|err| Error::Protocol(format!("invalid sig base64: {err}")))?;
    if sig_bytes.len() != 64 {
        return Err(Error::Protocol(
            "Ed25519 signature must be 64 bytes".to_owned(),
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let signing_input = format!("{header_b64}.{}", base64url_encode(canonical_bytes));
    // `verify_strict` (ed25519-dalek's protocol-recommended path): rejects
    // malleable / small-order / non-canonical signatures so every verifier
    // in the SDK reaches the same accept/reject verdict.
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|err| Error::Protocol(format!("Ed25519 signature verification failed: {err}")))?;
    Ok(())
}
