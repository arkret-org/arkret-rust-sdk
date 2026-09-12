//! Canonical proof builders, Event proof verification, and signing primitives.
//!
//! Single canonical JSON + detached JWS pipeline for signing Event
//! Envelopes, shared by `coauth`, `soland`, and `inkson`:
//! canonical-bytes computation, the `EventSigner` /
//! `EventVerifier` traits, the `PublicKeyMaterial` carrier, and a
//! generic `Ed25519DetachedJwsSigner` / `Ed25519DetachedJwsVerifier` primitives.
//! Arkret Event proofs are signed through [`crate::sign_event`], which constructs
//! the mandatory domain-separated proof binding object.
//!
//! ```
//! use arkret_signatures::proof::{EventProofBuilder, EventSigner};
//! use serde_json::json;
//!
//! # #[cfg(feature = "signer")]
//! # {
//! use arkret_signatures::proof::Ed25519DetachedJwsSigner;
//!
//! let signer = Ed25519DetachedJwsSigner::from_seed(
//!     [9u8; 32],
//!     "did:webvh:z6mkfixture:alice.example#key-1",
//! );
//! let builder = EventProofBuilder::new();
//! let bytes = builder.canonical_bytes(&json!({"b": 2, "a": 1})).unwrap();
//! let sig = signer.sign(&bytes).unwrap();
//! assert_eq!(sig.len(), 64);
//! # }
//! ```

use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use arkret_canonical::canonical;
use arkret_wire::{DidUrl, Hash, PayloadProof, ProducerEventProof, SignalEnvelope, proof_kind};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Wire-form public key material used by [`EventVerifier`] adapters.
///
/// Each variant declares the on-the-wire encoding so a verifier can
/// reject keys it does not understand. Production deployments today
/// only need `Ed25519Raw`; the multibase / JWK variants support DID document
/// resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case")]
pub enum PublicKeyMaterial {
    /// Raw 32-byte Ed25519 verifying key (RFC 8032 §5.1.5).
    Ed25519Raw {
        #[serde(with = "key_bytes")]
        bytes: Vec<u8>,
    },
    /// `z<base58-btc>` multibase-encoded Ed25519 verifying key.
    Ed25519Multibase { value: String },
    /// JSON Web Key (`OKP` + `crv=Ed25519`). Accepted for resolver
    /// interop; consumed by parsing the embedded `x` parameter.
    Jwk { value: serde_json::Value },
}

impl PublicKeyMaterial {
    /// Decode the public key material into raw Ed25519 bytes.
    pub fn ed25519_bytes(&self) -> Result<[u8; 32]> {
        let raw = match self {
            Self::Ed25519Raw { bytes } => bytes.clone(),
            Self::Ed25519Multibase { value } => decode_multibase_btc58(value)?,
            Self::Jwk { value } => decode_jwk_ed25519(value)?,
        };
        if raw.len() != 32 {
            return Err(Error::Protocol(format!(
                "expected 32-byte Ed25519 verifying key, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(out)
    }

    /// Digest of the normalized raw Ed25519 key bytes.
    ///
    /// Signal Agent sequence domains use this value so equivalent raw,
    /// multibase and JWK encodings cannot create different domains, while a
    /// real runtime key replacement necessarily creates a fresh domain.
    pub fn raw_ed25519_digest(&self) -> Result<Hash> {
        Hash::new(canonical::sha256_digest(self.ed25519_bytes()?)).map_err(Into::into)
    }
}

/// Decode a `did:key` Ed25519 multibase string into raw key bytes.
///
/// Tolerates either the standard 2-byte multicodec prefix (`0xed 0x01`) or a
/// bare 32-byte payload. The base58btc primitive comes from
/// [`arkret_canonical::multibase`] — the single base58 home shared with `sdk`.
fn decode_multibase_btc58(value: &str) -> Result<Vec<u8>> {
    let decoded = canonical_decode_multibase(value)?;
    if decoded.len() == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
        Ok(decoded[2..].to_vec())
    } else {
        Ok(decoded)
    }
}

fn canonical_decode_multibase(value: &str) -> Result<Vec<u8>> {
    Ok(arkret_canonical::decode_multibase_base58btc(value)?)
}

mod key_bytes {
    use arkret_canonical::{base64url_decode, base64url_encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64url_encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64url_decode(&s).map_err(serde::de::Error::custom)
    }
}

fn decode_jwk_ed25519(value: &serde_json::Value) -> Result<Vec<u8>> {
    let kty = value.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let crv = value.get("crv").and_then(|v| v.as_str()).unwrap_or("");
    if kty != "OKP" || crv != "Ed25519" {
        return Err(Error::Protocol(format!(
            "unsupported JWK for Ed25519: kty={kty:?} crv={crv:?}"
        )));
    }
    let x = value
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Protocol("Ed25519 JWK missing 'x' parameter".to_owned()))?;
    Ok(base64url_decode(x)?)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetachedJwsProtectedHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    crit: Option<serde_json::Value>,
}

/// Verify an Ed25519 detached-JWS [`ProducerEventProof`] against canonical event bytes,
/// the signing `actor_id`, and a resolver-supplied public key.
///
/// Per `encoding.md` §6 the verifier sequence is fixed:
///   1. strip `proofs`/`unsigned` from the Event, canonicalize, compute `event_digest`, and
///      constant-time compare it to `proof.event_digest` (`canonical_bytes` here is exactly those
///      stripped canonical bytes);
///   2. construct the canonical **proof binding object** `{event_digest, actor_id,
///      verification_method, created_at, domain?, audience?}` and verify the detached JWS signs
///      *those* bytes — NOT the raw event bytes. `actor_id` is the Event envelope's `actor_id`
///      field.
///
/// This is intentionally not gated behind the `signer` feature: production
/// receivers need verification even when they never hold signing material.
pub fn verify_ed25519_detached_jws_proof(
    proof: &ProducerEventProof,
    canonical_bytes: &[u8],
    actor_id: &arkret_wire::ActorId,
    public_key: &PublicKeyMaterial,
) -> std::result::Result<(), VerifierError> {
    verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        canonical_bytes,
        actor_id,
        public_key,
        arkret_canonical::DigestSuite::Sha256,
    )
}

/// Verify a detached Event proof with the trusted Realm digest suite.
///
/// The suite is explicit because an Event payload is not trusted until its
/// proof has verified. Callers must resolve it from accepted Realm state (or
/// the verified genesis authoring context), never infer it from the Event.
pub fn verify_ed25519_detached_jws_proof_with_digest_suite(
    proof: &ProducerEventProof,
    canonical_bytes: &[u8],
    actor_id: &arkret_wire::ActorId,
    public_key: &PublicKeyMaterial,
    digest_suite: arkret_canonical::DigestSuite,
) -> std::result::Result<(), VerifierError> {
    verify_ed25519_detached_jws_proof_inner(
        proof,
        canonical_bytes,
        actor_id,
        public_key,
        digest_suite,
    )
}

/// Verify a non-Event detached payload proof over an object-family canonical
/// binding transcript. The owning model constructs `binding_bytes` with its
/// registered proof context and rejects a mismatched payload digest first.
pub fn verify_ed25519_detached_jws_payload_proof(
    proof: &PayloadProof,
    binding_bytes: &[u8],
    public_key: &PublicKeyMaterial,
) -> std::result::Result<(), VerifierError> {
    if binding_bytes.is_empty() {
        return Err(VerifierError::Encoding(
            "payload proof binding bytes must not be empty".to_owned(),
        ));
    }
    proof
        .validate_production()
        .map_err(|error| VerifierError::Binding(error.to_string()))?;
    verify_detached_jws_over(&proof.jws, binding_bytes, public_key)
}

/// Verify a raw base64url Ed25519 signature over an exact protocol transcript.
/// Object-family verifiers remain responsible for constructing and validating
/// that transcript before calling this primitive.
pub fn verify_ed25519_raw_transcript_signature(
    transcript: &[u8],
    signature_b64u: &str,
    public_key: &PublicKeyMaterial,
) -> std::result::Result<(), VerifierError> {
    if transcript.is_empty() {
        return Err(VerifierError::Encoding(
            "signature transcript must not be empty".to_owned(),
        ));
    }
    let key_bytes = public_key
        .ed25519_bytes()
        .map_err(|error| VerifierError::UnsupportedKey(error.to_string()))?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| VerifierError::UnsupportedKey(error.to_string()))?;
    let signature_bytes = base64url_decode(signature_b64u)
        .map_err(|error| VerifierError::Encoding(error.to_string()))?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map_err(|error| VerifierError::Encoding(error.to_string()))?;
    verifying
        .verify_strict(transcript, &signature)
        .map_err(|error| VerifierError::Backend(error.to_string()))
}

/// Verify a [`SignalEnvelope`] against the sending device's key.
///
/// A Signal proof is not an Event proof: its transcript names the sending
/// device and commits to `envelope_digest` (the envelope with `proof` removed),
/// so it cannot be verified by the Event path and a signature from one rail can
/// never be replayed on the other.
///
/// This checks the signature and the envelope's self-consistency only. The
/// caller still owes the admission checks that need accepted state: that
/// `verification_method` resolves, at `seal_ref`, to the active device signing
/// method authorized for `sender_device_id` under `sender_actor_id`; that the
/// device may send into this scope; and, for `moderation`, the corresponding
/// moderation action. `signal.md` §3 requires all four. In particular, no
/// fragment-to-device-id string equality may stand in for that lookup.
pub fn verify_ed25519_signal_proof(
    envelope: &SignalEnvelope,
    public_key: &PublicKeyMaterial,
) -> std::result::Result<(), VerifierError> {
    envelope
        .validate_structural()
        .map_err(|error| VerifierError::Binding(error.to_string()))?;
    let binding_bytes = envelope
        .proof_binding_bytes()
        .map_err(|err| VerifierError::Encoding(format!("signal proof binding object: {err}")))?;
    verify_detached_jws_over(&envelope.proof.jws, &binding_bytes, public_key)
}

fn verify_ed25519_detached_jws_proof_inner(
    proof: &ProducerEventProof,
    canonical_bytes: &[u8],
    actor_id: &arkret_wire::ActorId,
    public_key: &PublicKeyMaterial,
    digest_suite: arkret_canonical::DigestSuite,
) -> std::result::Result<(), VerifierError> {
    if canonical_bytes.is_empty() {
        return Err(VerifierError::Encoding(
            "canonical bytes must not be empty".to_owned(),
        ));
    }
    let expected = canonical::digest(digest_suite, canonical_bytes);
    use subtle::ConstantTimeEq;
    if !bool::from(
        proof
            .event_digest
            .as_str()
            .as_bytes()
            .ct_eq(expected.as_bytes()),
    ) {
        return Err(VerifierError::Binding(format!(
            "proof event_digest '{}' does not match canonical bytes '{}'",
            proof.event_digest, expected
        )));
    }
    let binding_bytes = proof
        .canonical_binding_bytes(actor_id)
        .map_err(|err| VerifierError::Encoding(format!("proof binding object: {err}")))?;

    verify_detached_jws_over(&proof.jws, &binding_bytes, public_key)
}

/// Shared detached-JWS tail: parse the protected header, reject every
/// extension this profile does not accept, and verify the signature over
/// `header.base64url(binding_bytes)`.
fn verify_detached_jws_over(
    jws: &str,
    binding_bytes: &[u8],
    public_key: &PublicKeyMaterial,
) -> std::result::Result<(), VerifierError> {
    let parts = validate_ed25519_detached_jws_shape(jws)?;
    let sig_bytes = base64url_decode(parts[2])
        .map_err(|err| VerifierError::Encoding(format!("invalid sig base64: {err}")))?;
    let signing_input = format!("{}.{}", parts[0], base64url_encode(binding_bytes));
    verify_ed25519_signing_input(&signing_input, &sig_bytes, public_key)
}

/// Validate the shared Arkret Ed25519 detached-JWS carrier profile without
/// verifying its signature. This is intended for structural admission checks;
/// cryptographic consumers must still call a verifier with the canonical
/// signing input and resolved public key.
pub fn validate_ed25519_detached_jws_shape(
    jws: &str,
) -> std::result::Result<Vec<&str>, VerifierError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 || !parts[1].is_empty() {
        return Err(VerifierError::Encoding(
            "detached JWS must be header..signature with empty payload segment".to_owned(),
        ));
    }
    let header_bytes = base64url_decode(parts[0])
        .map_err(|err| VerifierError::Encoding(format!("invalid header base64: {err}")))?;
    let header: DetachedJwsProtectedHeader = canonical::from_canonical_json_slice(&header_bytes)
        .map_err(|err| VerifierError::Encoding(format!("invalid protected header: {err}")))?;
    if header.alg != "Ed25519" {
        return Err(VerifierError::Backend(format!(
            "Ed25519 verifier received non-Ed25519 protected alg '{}'",
            header.alg
        )));
    }
    if header.kid.is_some() {
        return Err(VerifierError::Encoding(
            "event detached JWS must not duplicate the outer verification_method as `kid`"
                .to_owned(),
        ));
    }
    if header.crit.is_some() {
        return Err(VerifierError::Encoding(
            "detached JWS declares unsupported `crit` extensions".to_owned(),
        ));
    }
    if let Some(typ) = header.typ.as_deref() {
        return Err(VerifierError::Encoding(format!(
            "unsupported detached JWS typ '{typ}'"
        )));
    }
    let sig_bytes = base64url_decode(parts[2])
        .map_err(|err| VerifierError::Encoding(format!("invalid sig base64: {err}")))?;
    if sig_bytes.len() != 64 {
        return Err(VerifierError::Encoding(
            "Ed25519 signature must be 64 bytes".to_owned(),
        ));
    }
    Ok(parts)
}

/// Verify a raw detached Ed25519 signature over `message` with `public_key`.
///
/// Unlike [`verify_ed25519_detached_jws_proof`] (which reconstructs a JWS
/// signing input and a proof binding object), this is the bare primitive: the
/// signature is computed directly over `message` bytes. It is the verification
/// half used by device proof-of-possession verification, where the message is
/// the canonical, domain-separated device authorization input and the
/// signature is base64url(-no-pad).
///
/// Uses `ed25519-dalek` `verify_strict` (rejects malleable / non-canonical
/// signatures). Returns `false` on any decode or verification failure — it
/// never panics and never returns `true` for malformed material (fail-closed).
pub fn verify_detached_ed25519_signature(
    public_key: &PublicKeyMaterial,
    message: &[u8],
    signature_b64url: &str,
) -> bool {
    let Ok(key_bytes) = public_key.ed25519_bytes() else {
        return false;
    };
    let Ok(verifying) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(raw) = base64url_decode(signature_b64url) else {
        return false;
    };
    if raw.len() != 64 {
        return false;
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&raw);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    verifying.verify_strict(message, &sig).is_ok()
}

/// Produce the canonical Ed25519 detached-JWS wire form over payload bytes.
///
/// The signing input is `b64u({"alg":"Ed25519"}).b64u(canonical_bytes)` and
/// the serialized JWS carries an empty detached payload segment.
pub fn sign_ed25519_detached_jws(
    signing_key: &ed25519_dalek::SigningKey,
    canonical_bytes: &[u8],
) -> std::result::Result<String, SignerError> {
    if canonical_bytes.is_empty() {
        return Err(SignerError::Backend(
            "canonical bytes must not be empty".to_owned(),
        ));
    }
    Ok(ed25519_jws::detached_jws_over(signing_key, canonical_bytes))
}

fn verify_ed25519_signing_input(
    signing_input: &str,
    signature: &[u8],
    public_key: &PublicKeyMaterial,
) -> std::result::Result<(), VerifierError> {
    let key_bytes = public_key
        .ed25519_bytes()
        .map_err(|err| VerifierError::UnsupportedKey(err.to_string()))?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|err| VerifierError::UnsupportedKey(err.to_string()))?;
    if signature.len() != 64 {
        return Err(VerifierError::Encoding(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            signature.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    verifying
        .verify_strict(signing_input.as_bytes(), &sig)
        .map_err(|err| VerifierError::Backend(format!("Ed25519 verification failed: {err}")))
}

/// Error raised by [`EventSigner`] backends.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("signing failed: {0}")]
    Backend(String),
    #[error("invalid signing key: {0}")]
    Key(String),
}

impl From<SignerError> for Error {
    fn from(err: SignerError) -> Self {
        Error::Crypto(err.to_string())
    }
}

/// Error raised by [`EventVerifier`] backends.
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("signature verification failed: {0}")]
    Backend(String),
    #[error("invalid signature encoding: {0}")]
    Encoding(String),
    #[error("verifier received unsupported public-key encoding: {0}")]
    UnsupportedKey(String),
    #[error("proof binding mismatch: {0}")]
    Binding(String),
}

impl From<VerifierError> for Error {
    fn from(err: VerifierError) -> Self {
        match err {
            VerifierError::Binding(msg) => Error::Protocol(msg),
            other => Error::Crypto(other.to_string()),
        }
    }
}

/// Builds Event Envelope canonical to-be-signed bytes from any payload.
///
/// `EventProofBuilder` is the single entry point that downstream
/// services (`coauth`, `soland`, `inkson`) call to derive the bytes
/// the signer puts under the signature. It threads the canonical
/// JSON encoder used everywhere else in the SDK so all services
/// produce byte-identical signing input.
#[derive(Clone, Debug, Default)]
pub struct EventProofBuilder {
    /// Optional domain binding folded into the canonical payload.
    domain: Option<String>,
}

impl EventProofBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a domain string into the canonical payload (the field is
    /// always included verbatim in the canonical JSON).
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Encode `value` as canonical JSON bytes ready to be hashed and
    /// signed. The bytes are stable for any logically equal value.
    pub fn canonical_bytes<T: Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        Ok(canonical::canonical_json_bytes(value)?)
    }

    /// Compute the `sha256:<hex>` payload hash for `value`.
    pub fn payload_digest<T: Serialize>(&self, value: &T) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(value)?).map_err(Into::into)
    }

    /// Convenience: produce the canonical bytes for an Event Envelope.
    ///
    /// Strips `proofs` and `unsigned` so the bytes match what
    /// `Event::digest_payload` already produces. This wraps the same
    /// canonicalization rule callers would write by hand.
    pub fn envelope_bytes(&self, event: &arkret_wire::Event) -> Result<Vec<u8>> {
        let payload = event.digest_payload()?;
        Ok(canonical::canonical_json_bytes(&payload)?)
    }

    /// Run `signer` over the canonical bytes for `value` and return the
    /// raw signature bytes alongside the canonical payload hash.
    pub fn sign<T, S>(&self, value: &T, signer: &S) -> Result<SignedPayload>
    where
        T: Serialize,
        S: EventSigner + ?Sized,
    {
        let bytes = self.canonical_bytes(value)?;
        let hash = Hash::new(canonical::sha256_digest(&bytes))?;
        let signature = signer.sign(&bytes)?;
        Ok(SignedPayload {
            canonical_bytes: bytes,
            payload_digest: hash,
            signature,
        })
    }
}

/// Carrier produced by [`EventProofBuilder::sign`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPayload {
    pub canonical_bytes: Vec<u8>,
    pub payload_digest: Hash,
    pub signature: Vec<u8>,
}

/// Sign canonical bytes with an opaque private key.
///
/// Implementations of this trait MUST be deterministic for fixed input
/// (Ed25519 is naturally deterministic; ECDSA backends should use
/// RFC 6979). The returned bytes are the raw signature bytes (not a
/// detached JWS).
pub trait EventSigner {
    fn sign(&self, bytes: &[u8]) -> std::result::Result<Vec<u8>, SignerError>;
    /// Fully specified algorithm name used by the protected JWS header
    /// (e.g. `"Ed25519"`). It is not duplicated in the outer [`ProducerEventProof`].
    fn algorithm(&self) -> &str;
    /// Verification method id (`did:...#fragment`) the produced
    /// signatures should reference.
    fn verification_method(&self) -> &str;
}

/// Verify canonical bytes against a [`PublicKeyMaterial`].
pub trait EventVerifier {
    fn verify(
        &self,
        bytes: &[u8],
        signature: &[u8],
        public_key: &PublicKeyMaterial,
    ) -> std::result::Result<(), VerifierError>;
    /// Algorithm understood by this verifier (e.g. `"Ed25519"`).
    fn algorithm(&self) -> &str;
}

mod ed25519_jws {
    use arkret_canonical::base64url::{base64url_decode, base64url_encode};
    use arkret_canonical::canonical;
    use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
    use serde::Deserialize;

    /// SDK-canonical detached-JWS protected header (`{"alg":"Ed25519"}`).
    ///
    /// This is the single header byte string shared by fixtures and services
    /// for Move, Seal, and event-proof signatures. It intentionally omits
    /// `typ`; the default v1 proof profile does not declare one.
    pub(super) const PROTECTED_HEADER_ED25519: &str = r#"{"alg":"Ed25519"}"#;

    use super::{EventSigner, EventVerifier, PublicKeyMaterial, SignerError, VerifierError};

    /// Production Ed25519 [`EventSigner`] producing RFC 7797 detached
    /// JWS bytes (header.payload-stripped.signature).
    ///
    /// The signature is computed over `b64u(header) "." b64u(canonical_bytes)`
    /// so receivers re-derive the caller-supplied payload rather than trusting
    /// the JWS payload segment. This is not the Event-proof assembly API.
    pub struct Ed25519DetachedJwsSigner {
        signing_key: SigningKey,
        verification_method: String,
    }

    impl Ed25519DetachedJwsSigner {
        pub fn new(signing_key: SigningKey, verification_method: impl Into<String>) -> Self {
            Self {
                signing_key,
                verification_method: verification_method.into(),
            }
        }

        pub fn from_seed(seed: [u8; 32], verification_method: impl Into<String>) -> Self {
            Self::new(SigningKey::from_bytes(&seed), verification_method)
        }

        pub fn verifying_key(&self) -> VerifyingKey {
            self.signing_key.verifying_key()
        }

        /// Produce a generic detached JWS over caller-supplied bytes.
        ///
        /// This primitive does not assemble an Arkret event [`arkret_wire::ProducerEventProof`].
        /// Event proofs must be created with [`crate::sign_event`], which signs the
        /// protocol proof-binding object rather than raw event bytes.
        pub fn sign_detached_jws(&self, bytes: &[u8]) -> String {
            detached_jws_over(&self.signing_key, bytes)
        }
    }

    impl EventSigner for Ed25519DetachedJwsSigner {
        fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
            let signing_input = detached_signing_input(bytes);
            Ok(self
                .signing_key
                .sign(signing_input.as_bytes())
                .to_bytes()
                .to_vec())
        }

        fn algorithm(&self) -> &str {
            "Ed25519"
        }

        fn verification_method(&self) -> &str {
            &self.verification_method
        }
    }

    /// Production Ed25519 [`EventVerifier`] understanding the same
    /// RFC 7797 detached-JWS signing input.
    #[derive(Default, Clone, Copy)]
    pub struct Ed25519DetachedJwsVerifier;

    /// Metadata extracted from a successfully verified detached JWS.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VerifiedDetachedJws {
        key_id: Option<String>,
    }

    impl VerifiedDetachedJws {
        /// Return the optional RFC 7515 `kid` protected-header value.
        pub fn key_id(&self) -> Option<&str> {
            self.key_id.as_deref()
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct JwsProtectedHeader {
        alg: String,
        #[serde(default)]
        kid: Option<String>,
        #[serde(default)]
        typ: Option<String>,
        /// RFC 7515 §4.1.11 `crit`. Arkret v1 understands no critical
        /// extensions, so any present `crit` member MUST be rejected
        /// (`deny_unknown_fields` already rejects unrecognized members; this
        /// field makes the rejection explicit and self-documenting).
        #[serde(default)]
        crit: Option<serde_json::Value>,
    }

    impl Ed25519DetachedJwsVerifier {
        pub fn new() -> Self {
            Self
        }

        /// Verify a generic detached JWS whose signature covers exactly
        /// `canonical_bytes` (the JWS signing input is
        /// `b64u(header).b64u(canonical_bytes)`).
        ///
        /// This is a **generic** detached-JWS-over-payload primitive: the
        /// caller decides what `canonical_bytes` are. For Arkret **Event
        /// proofs**, the signed bytes are the canonical proof *binding
        /// object* (not the raw event bytes) — use the top-level
        /// [`super::verify_ed25519_detached_jws_proof`], which constructs that
        /// binding object from `proof` + `actor_id` per `encoding.md` §6.
        pub fn verify_detached_jws(
            &self,
            jws: &str,
            canonical_bytes: &[u8],
            public_key: &PublicKeyMaterial,
        ) -> Result<(), VerifierError> {
            self.verify_detached_jws_with_metadata(jws, canonical_bytes, public_key)
                .map(|_| ())
        }

        /// Verify a generic detached JWS and return validated protected-header
        /// metadata needed by protocol callers, such as the signing key id.
        pub fn verify_detached_jws_with_metadata(
            &self,
            jws: &str,
            canonical_bytes: &[u8],
            public_key: &PublicKeyMaterial,
        ) -> Result<VerifiedDetachedJws, VerifierError> {
            let parts: Vec<&str> = jws.split('.').collect();
            if parts.len() != 3 || !parts[1].is_empty() {
                return Err(VerifierError::Encoding(
                    "detached JWS must be header..signature with empty payload segment".to_owned(),
                ));
            }
            let header_bytes = base64url_decode(parts[0])
                .map_err(|err| VerifierError::Encoding(format!("invalid header base64: {err}")))?;
            let header: JwsProtectedHeader = canonical::from_canonical_json_slice(&header_bytes)
                .map_err(|err| {
                    VerifierError::Encoding(format!("invalid protected header: {err}"))
                })?;
            if header.alg != "Ed25519" {
                return Err(VerifierError::Backend(format!(
                    "Ed25519 verifier received non-Ed25519 protected alg '{}'",
                    header.alg
                )));
            }
            // RFC 7515 §4.1.11 — we recognise no critical extensions, so any
            // `crit` member fails closed.
            if header.crit.is_some() {
                return Err(VerifierError::Encoding(
                    "detached JWS declares unsupported `crit` extensions".to_owned(),
                ));
            }
            if let Some(typ) = header.typ.as_deref() {
                return Err(VerifierError::Encoding(format!(
                    "unsupported detached JWS typ '{typ}'"
                )));
            }
            let sig_bytes = base64url_decode(parts[2])
                .map_err(|err| VerifierError::Encoding(format!("invalid sig base64: {err}")))?;
            let signing_input = format!("{}.{}", parts[0], base64url_encode(canonical_bytes));
            self.verify_signing_input(&signing_input, &sig_bytes, public_key)?;
            Ok(VerifiedDetachedJws { key_id: header.kid })
        }

        fn verify_signing_input(
            &self,
            signing_input: &str,
            signature: &[u8],
            public_key: &PublicKeyMaterial,
        ) -> Result<(), VerifierError> {
            let key_bytes = public_key
                .ed25519_bytes()
                .map_err(|err| VerifierError::UnsupportedKey(err.to_string()))?;
            let verifying = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|err| VerifierError::UnsupportedKey(err.to_string()))?;
            if signature.len() != 64 {
                return Err(VerifierError::Encoding(format!(
                    "Ed25519 signature must be 64 bytes, got {}",
                    signature.len()
                )));
            }
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(signature);
            let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
            // `verify_strict` (ed25519-dalek's protocol-recommended path)
            // rejects signature malleability and small-order/non-canonical
            // R, matching `verify_ed25519_signing_input` so both detached-JWS
            // verifiers agree on validity (encoding.md §2.1 determinism).
            verifying
                .verify_strict(signing_input.as_bytes(), &sig)
                .map_err(|err| {
                    VerifierError::Backend(format!("Ed25519 verification failed: {err}"))
                })?;
            Ok(())
        }
    }

    impl EventVerifier for Ed25519DetachedJwsVerifier {
        fn verify(
            &self,
            bytes: &[u8],
            signature: &[u8],
            public_key: &PublicKeyMaterial,
        ) -> Result<(), VerifierError> {
            let signing_input = detached_signing_input(bytes);
            self.verify_signing_input(&signing_input, signature, public_key)
        }

        fn algorithm(&self) -> &str {
            "Ed25519"
        }
    }

    /// RFC 7797 unencoded-payload signing input: `b64url(header) "." b64url(payload)`.
    ///
    /// We base64-encode the canonical bytes here (rather than passing
    /// them in directly with `b64="false"`) because every Arkret SDK
    /// that talks to this verifier today expects the standard JWS
    /// shape. The detached form lives in the wire JWS — the middle
    /// segment is stripped — but the signing-input stays
    /// `header.payload`.
    pub(super) fn detached_signing_input(bytes: &[u8]) -> String {
        let header_b64 = base64url_encode(PROTECTED_HEADER_ED25519.as_bytes());
        format!("{header_b64}.{}", base64url_encode(bytes))
    }

    pub(super) fn detached_jws_over(signing_key: &SigningKey, bytes: &[u8]) -> String {
        let signing_input = detached_signing_input(bytes);
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = base64url_encode(signature.to_bytes());
        let header_b64 = base64url_encode(PROTECTED_HEADER_ED25519.as_bytes());
        format!("{header_b64}..{sig_b64}")
    }
}

pub use ed25519_jws::{Ed25519DetachedJwsSigner, Ed25519DetachedJwsVerifier, VerifiedDetachedJws};

fn ed25519_detached_jws_protected_b64(
    kid: Option<&str>,
) -> std::result::Result<String, SignerError> {
    let protected = match kid {
        None => ed25519_jws::PROTECTED_HEADER_ED25519.as_bytes().to_vec(),
        Some(kid) if !kid.trim().is_empty() => canonical::canonical_json_bytes(
            &serde_json::json!({"alg": "Ed25519", "kid": kid.trim()}),
        )
        .map_err(|error| SignerError::Backend(format!("protected header: {error}")))?,
        Some(_) => {
            return Err(SignerError::Backend(
                "detached JWS kid must not be empty".to_owned(),
            ));
        }
    };
    Ok(base64url_encode(protected))
}

/// Build the exact RFC 7515 signing input for Arkret's Ed25519 detached-JWS
/// profile. Products with external/HSM signers use this helper instead of
/// independently serializing protected headers.
pub fn ed25519_detached_jws_signing_input(
    payload: &[u8],
    kid: Option<&str>,
) -> std::result::Result<String, SignerError> {
    let protected = ed25519_detached_jws_protected_b64(kid)?;
    Ok(format!("{protected}.{}", base64url_encode(payload)))
}

/// Assemble an Arkret Ed25519 detached JWS from raw 64-byte signature output.
/// The protected header is SDK-owned; the wire payload segment is empty.
pub fn ed25519_detached_jws_from_signature(
    signature: &[u8],
    kid: Option<&str>,
) -> std::result::Result<String, SignerError> {
    if signature.len() != 64 {
        return Err(SignerError::Backend(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            signature.len()
        )));
    }
    let protected = ed25519_detached_jws_protected_b64(kid)?;
    Ok(format!("{protected}..{}", base64url_encode(signature)))
}

/// Construct a [`ProducerEventProof`] envelope for an already-signed payload. The
/// caller is responsible for supplying the detached JWS string produced by
/// their signer. The algorithm is carried only in its protected header.
#[allow(clippy::too_many_arguments)]
pub fn build_proof_envelope(
    kind: impl Into<String>,
    verification_method: DidUrl,
    payload_digest: Hash,
    signer_resolution_evidence_ref: arkret_wire::SignerEvidenceRef,
    domain: Option<String>,
    audience: Option<arkret_wire::Audience>,
    jws: impl Into<String>,
) -> ProducerEventProof {
    ProducerEventProof {
        kind: kind.into(),
        verification_method,
        event_digest: payload_digest,
        signer_resolution_evidence_ref: Some(signer_resolution_evidence_ref),
        created_at: Utc::now(),
        domain,
        audience,
        proof_purpose: None,
        jws: jws.into(),
    }
}

/// Sugar for the canonical detached-JWS production kind constant.
pub fn detached_jws_kind() -> &'static str {
    proof_kind::DETACHED_JWS
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url_decode;
    use serde_json::json;

    use super::*;

    #[test]
    fn detached_jws_codec_owns_protected_header_and_rejects_invalid_inputs() {
        let payload = br#"{"a":1}"#;
        let input = ed25519_detached_jws_signing_input(payload, None).unwrap();
        let protected = input.split_once('.').unwrap().0;
        assert_eq!(
            base64url_decode(protected).unwrap(),
            br#"{"alg":"Ed25519"}"#
        );

        let with_kid =
            ed25519_detached_jws_signing_input(payload, Some("did:web:alice.example#device-1"))
                .unwrap();
        let protected = with_kid.split_once('.').unwrap().0;
        assert_eq!(
            base64url_decode(protected).unwrap(),
            br#"{"alg":"Ed25519","kid":"did:web:alice.example#device-1"}"#
        );

        assert!(ed25519_detached_jws_signing_input(payload, Some(" ")).is_err());
        assert!(ed25519_detached_jws_from_signature(&[0_u8; 63], None).is_err());
        assert_eq!(
            ed25519_detached_jws_from_signature(&[0_u8; 64], None)
                .unwrap()
                .split('.')
                .count(),
            3
        );
    }

    #[test]
    fn canonical_bytes_are_stable_across_key_order() {
        let builder = EventProofBuilder::new();
        let a = builder.canonical_bytes(&json!({"b": 2, "a": 1})).unwrap();
        let b = builder.canonical_bytes(&json!({"a": 1, "b": 2})).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_bytes_reject_float_numbers() {
        let builder = EventProofBuilder::new();
        assert!(builder.canonical_bytes(&json!({"n": 1.5})).is_err());
    }

    #[test]
    fn payload_digest_is_sha256_of_canonical_bytes() {
        let builder = EventProofBuilder::new();
        let hash = builder.payload_digest(&json!({"a": 1})).unwrap();
        assert!(hash.as_str().starts_with("sha256:"));
        // Stable digest for canonical `{"a":1}`.
        assert_eq!(
            hash.as_str(),
            "sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
        );
    }

    #[test]
    fn public_key_material_jwk_decodes_to_raw_bytes() {
        let value = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });
        let key = PublicKeyMaterial::Jwk { value };
        let raw = key.ed25519_bytes().unwrap();
        assert_eq!(raw.len(), 32);
    }

    #[cfg(feature = "signer")]
    #[test]
    fn ed25519_signer_round_trips_through_event_verifier() {
        use serde_json::json;
        let signer = Ed25519DetachedJwsSigner::from_seed(
            [1u8; 32],
            "did:webvh:z6mkfixture:alice.example#key-1",
        );
        let verifier = Ed25519DetachedJwsVerifier::new();
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: signer.verifying_key().to_bytes().to_vec(),
        };
        let builder = EventProofBuilder::new();
        let signed = builder.sign(&json!({"hello": "world"}), &signer).unwrap();
        verifier
            .verify(&signed.canonical_bytes, &signed.signature, &public_key)
            .unwrap();
    }

    #[cfg(feature = "signer")]
    #[test]
    fn ed25519_generic_detached_jws_round_trips() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let signer = Ed25519DetachedJwsSigner::from_seed(
            [2u8; 32],
            "did:webvh:z6mkfixture:bob.example#key-1",
        );
        let bytes = canonical::canonical_json_bytes(&json!({"a": 1, "b": 2})).unwrap();
        let jws = signer.sign_detached_jws(&bytes);
        let verifier = Ed25519DetachedJwsVerifier::new();
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: signer.verifying_key().to_bytes().to_vec(),
        };
        verifier
            .verify_detached_jws(&jws, &bytes, &public_key)
            .unwrap();
        // Tampering MUST fail.
        let mut tampered = bytes;
        tampered.push(b'!');
        assert!(
            verifier
                .verify_detached_jws(&jws, &tampered, &public_key)
                .is_err()
        );

        let signature = jws.rsplit('.').next().unwrap();
        let bad_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let header_tampered = format!("{bad_header}..{signature}");
        assert!(
            verifier
                .verify_detached_jws(
                    &header_tampered,
                    &tampered[..tampered.len() - 1],
                    &public_key
                )
                .is_err()
        );

        let crit_header =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"Ed25519","typ":"JWT","crit":["b64"]}"#);
        let crit_tampered = format!("{crit_header}..{signature}");
        assert!(
            verifier
                .verify_detached_jws(&crit_tampered, &tampered[..tampered.len() - 1], &public_key)
                .is_err()
        );
    }

    #[cfg(feature = "signer")]
    #[test]
    fn event_proof_verifier_requires_the_explicit_realm_digest_suite() {
        let actor = arkret_wire::ActorId::service(
            arkret_wire::DidCoreId::new("ak:did_core:web:blake.example").unwrap(),
        );
        let verification_method = DidUrl::new("did:web:blake.example#key-1".to_owned()).unwrap();
        let canonical_bytes = canonical::canonical_json_bytes(&json!({"realm": "blake"})).unwrap();
        let digest = Hash::new(canonical::digest(
            arkret_canonical::DigestSuite::Blake3,
            &canonical_bytes,
        ))
        .unwrap();
        let signer = Ed25519DetachedJwsSigner::from_seed([23u8; 32], verification_method.as_str());
        let mut proof = build_proof_envelope(
            proof_kind::DETACHED_JWS,
            verification_method,
            digest,
            arkret_wire::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
            None,
            None,
            "",
        );
        let binding = proof.canonical_binding_bytes(&actor).unwrap();
        proof.jws = signer.sign_detached_jws(&binding);
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: signer.verifying_key().to_bytes().to_vec(),
        };

        verify_ed25519_detached_jws_proof_with_digest_suite(
            &proof,
            &canonical_bytes,
            &actor,
            &public_key,
            arkret_canonical::DigestSuite::Blake3,
        )
        .unwrap();
        assert!(
            verify_ed25519_detached_jws_proof(&proof, &canonical_bytes, &actor, &public_key)
                .is_err()
        );
    }
}
