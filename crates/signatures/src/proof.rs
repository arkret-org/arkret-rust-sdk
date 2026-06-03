//! Unified Event Envelope canonical proof builder and verifier.
//!
//! T5.1 (Round 22, 2026-05-19) — `coauth`, `soland`, and `yougen` each
//! grew their own canonical JSON + detached JWS plumbing for signing
//! Event Envelopes. This module is the single pipeline they should all
//! converge on: canonical-bytes computation, the `EventSigner` /
//! `EventVerifier` traits, the `PublicKeyMaterial` carrier, and a
//! production-grade `Ed25519DetachedJwsSigner` /
//! `Ed25519DetachedJwsVerifier` (RFC 7797 detached payload form).
//!
//! Migration is staged across T5.2 / T5.3; downstream services replace
//! their bespoke implementations with calls into this module.
//!
//! ```
//! use cokret_signatures::proof::{EventProofBuilder, EventSigner};
//! use serde_json::json;
//!
//! # #[cfg(feature = "signer")]
//! # {
//! use cokret_signatures::proof::Ed25519DetachedJwsSigner;
//!
//! let signer = Ed25519DetachedJwsSigner::from_seed(
//!     [9u8; 32],
//!     "did:web:alice.example#key-1",
//! );
//! let builder = EventProofBuilder::new();
//! let bytes = builder.canonical_bytes(&json!({"b": 2, "a": 1})).unwrap();
//! let sig = signer.sign(&bytes).unwrap();
//! assert_eq!(sig.len(), 64);
//! # }
//! ```

use std::fmt;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use cokret_core::{Error, Hash, Proof, Result, canonical, proof_kind};

/// Wire-form public key material used by [`EventVerifier`] adapters.
///
/// Each variant declares the on-the-wire encoding so a verifier can
/// reject keys it does not understand. Production deployments today
/// only need `Ed25519Raw`; the multibase / JWK variants are accepted
/// for forward-compatibility with DID document resolution.
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
}

/// Decode a `did:key` Ed25519 multibase string into raw key bytes.
///
/// Tolerates either the standard 2-byte multicodec prefix (`0xed 0x01`) or a
/// bare 32-byte payload. The base58btc primitive comes from
/// [`cokret_core::multibase`] — the single base58 home shared with `sdk`.
fn decode_multibase_btc58(value: &str) -> Result<Vec<u8>> {
    let decoded = canonical_decode_multibase(value)?;
    if decoded.len() == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
        Ok(decoded[2..].to_vec())
    } else {
        Ok(decoded)
    }
}

fn canonical_decode_multibase(value: &str) -> Result<Vec<u8>> {
    cokret_core::decode_multibase_base58btc(value)
}

mod key_bytes {
    use cokret_core::{base64url_decode, base64url_encode};
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
    cokret_core::base64url_decode(x)
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
    #[error("dev-proof rejected in production verifier: {0}")]
    DevProofRejected(String),
    #[error("proof binding mismatch: {0}")]
    Binding(String),
}

impl From<VerifierError> for Error {
    fn from(err: VerifierError) -> Self {
        match err {
            VerifierError::Binding(msg) | VerifierError::DevProofRejected(msg) => {
                Error::Protocol(msg)
            }
            other => Error::Crypto(other.to_string()),
        }
    }
}

/// Builds Event Envelope canonical to-be-signed bytes from any payload.
///
/// `EventProofBuilder` is the single entry point that downstream
/// services (`coauth`, `soland`, `yougen`) call to derive the bytes
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
        canonical::canonical_json_bytes(value)
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
    pub fn envelope_bytes(&self, event: &cokret_core::Event) -> Result<Vec<u8>> {
        let payload = event.digest_payload()?;
        canonical::canonical_json_bytes(&payload)
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
        Ok(SignedPayload { canonical_bytes: bytes, payload_digest: hash, signature })
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
    /// Algorithm name used when assembling a [`Proof`] envelope
    /// (e.g. `"EdDSA"`, `"ES256"`).
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
    /// Algorithm understood by this verifier (e.g. `"EdDSA"`).
    fn algorithm(&self) -> &str;
}

/// Marker enum distinguishing real proofs from in-process / test
/// shortcut proofs. Set on every emitted proof so receivers can
/// reject dev-mode proofs in production.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ProofType {
    /// Production proof carrying a real signature.
    Production { kind: String, algorithm: String },
    /// Dev/test shortcut proof. Must never round-trip past a
    /// `ProductionVerifier`.
    Development { reason: String },
}

impl ProofType {
    pub fn production(kind: impl Into<String>, algorithm: impl Into<String>) -> Self {
        Self::Production { kind: kind.into(), algorithm: algorithm.into() }
    }

    pub fn development(reason: impl Into<String>) -> Self {
        Self::Development { reason: reason.into() }
    }

    pub fn is_development(&self) -> bool {
        matches!(self, Self::Development { .. })
    }
}

impl fmt::Display for ProofType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Production { kind, algorithm } => write!(f, "production({kind}/{algorithm})"),
            Self::Development { reason } => write!(f, "development({reason})"),
        }
    }
}

/// Adapter that wraps any [`EventVerifier`] and refuses signatures
/// produced under a `Development` [`ProofType`].
pub struct ProductionVerifier<V> {
    inner: V,
}

impl<V> ProductionVerifier<V> {
    /// Wrap a base verifier so it rejects dev-mode proofs.
    pub fn wrap(inner: V) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &V {
        &self.inner
    }

    /// Verify `bytes` / `signature` after asserting that `proof_type`
    /// is `Production`.
    pub fn verify_typed(
        &self,
        proof_type: &ProofType,
        bytes: &[u8],
        signature: &[u8],
        public_key: &PublicKeyMaterial,
    ) -> std::result::Result<(), VerifierError>
    where
        V: EventVerifier,
    {
        if proof_type.is_development() {
            return Err(VerifierError::DevProofRejected(proof_type.to_string()));
        }
        self.inner.verify(bytes, signature, public_key)
    }

    /// Reject any `Proof` whose `kind` is in the canonical dev-kind
    /// allowlist (`dev` / `test` / `mock` / `stub` / `dummy`).
    pub fn assert_production_proof(&self, proof: &Proof) -> std::result::Result<(), VerifierError> {
        proof.validate_production().map_err(|err| VerifierError::DevProofRejected(err.to_string()))
    }
}

impl<V: EventVerifier> EventVerifier for ProductionVerifier<V> {
    fn verify(
        &self,
        bytes: &[u8],
        signature: &[u8],
        public_key: &PublicKeyMaterial,
    ) -> std::result::Result<(), VerifierError> {
        self.inner.verify(bytes, signature, public_key)
    }

    fn algorithm(&self) -> &str {
        self.inner.algorithm()
    }
}

#[cfg(feature = "signer")]
mod ed25519_jws {
    use chrono::Utc;
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
    use serde::Deserialize;

    use cokret_core::{
        Audience, Hash, Proof, base64url_decode, base64url_encode, canonical, proof_kind,
    };

    /// SDK-canonical detached-JWS protected header (`{"alg":"EdDSA"}`).
    ///
    /// 这是全生态(spec fixtures、soland `move_anchor_wire`、cotest、teabay
    /// `sdk::jws`)统一的 detached JWS header 字节;Move/Anchor/event-proof
    /// 三类签名共用同一 header,使 signing input 字节唯一,跨实现可互验。
    /// **不含** `typ`(spec §6 default proof 不声明 `typ`)。
    pub(super) const PROTECTED_HEADER_EDDSA: &str = r#"{"alg":"EdDSA"}"#;

    use super::{
        EventProofBuilder, EventSigner, EventVerifier, ProofType, PublicKeyMaterial, SignerError,
        VerifierError,
    };

    /// Production Ed25519 [`EventSigner`] producing RFC 7797 detached
    /// JWS bytes (header.payload-stripped.signature).
    ///
    /// The signature is computed over `b64u(header) "." b64u(canonical_bytes)`
    /// so receivers re-derive the payload from the canonical Event
    /// Envelope rather than trusting the JWS payload segment.
    pub struct Ed25519DetachedJwsSigner {
        signing_key: SigningKey,
        verification_method: String,
    }

    impl Ed25519DetachedJwsSigner {
        pub fn new(signing_key: SigningKey, verification_method: impl Into<String>) -> Self {
            Self { signing_key, verification_method: verification_method.into() }
        }

        pub fn from_seed(seed: [u8; 32], verification_method: impl Into<String>) -> Self {
            Self::new(SigningKey::from_bytes(&seed), verification_method)
        }

        pub fn verifying_key(&self) -> VerifyingKey {
            self.signing_key.verifying_key()
        }

        /// Produce a full Cokret [`Proof`] over `value` using this
        /// signer. Returns the canonical bytes alongside the proof so
        /// callers can persist them next to the envelope.
        pub fn sign_payload<T: serde::Serialize>(
            &self,
            value: &T,
            domain: Option<String>,
            audience: Option<Audience>,
        ) -> cokret_core::Result<(Vec<u8>, Proof)> {
            let builder = EventProofBuilder::new();
            let bytes = builder.canonical_bytes(value)?;
            let proof = self.build_proof(&bytes, domain, audience)?;
            Ok((bytes, proof))
        }

        /// Assemble a Cokret [`Proof`] over pre-canonicalized `bytes`.
        pub fn build_proof(
            &self,
            bytes: &[u8],
            domain: Option<String>,
            audience: Option<Audience>,
        ) -> cokret_core::Result<Proof> {
            let jws = detached_jws_over(&self.signing_key, bytes);
            let payload_digest = Hash::new(canonical::sha256_digest(bytes))?;
            Ok(Proof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: self.verification_method.clone(),
                payload_digest,
                created_at: Utc::now(),
                domain,
                audience,
                jws,
            })
        }

        /// The matching [`ProofType`] tag.
        pub fn proof_type() -> ProofType {
            ProofType::production(proof_kind::DETACHED_JWS, "EdDSA")
        }
    }

    impl EventSigner for Ed25519DetachedJwsSigner {
        fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
            let signing_input = detached_signing_input(bytes);
            Ok(self.signing_key.sign(signing_input.as_bytes()).to_bytes().to_vec())
        }

        fn algorithm(&self) -> &str {
            "EdDSA"
        }

        fn verification_method(&self) -> &str {
            &self.verification_method
        }
    }

    /// Production Ed25519 [`EventVerifier`] understanding the same
    /// RFC 7797 detached-JWS signing input.
    #[derive(Default, Clone, Copy)]
    pub struct Ed25519DetachedJwsVerifier;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct JwsProtectedHeader {
        alg: String,
        #[serde(default)]
        typ: Option<String>,
        /// RFC 7515 §4.1.11 `crit`. Cokret v1 understands no critical
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

        /// Verify a full Cokret [`Proof`] against the canonical bytes
        /// it should be bound to.
        pub fn verify_proof(
            &self,
            proof: &Proof,
            canonical_bytes: &[u8],
            public_key: &PublicKeyMaterial,
        ) -> Result<(), VerifierError> {
            if proof.alg != "EdDSA" {
                return Err(VerifierError::Backend(format!(
                    "Ed25519 verifier received non-EdDSA alg '{}'",
                    proof.alg
                )));
            }
            let expected = canonical::sha256_digest(canonical_bytes);
            if proof.payload_digest.as_str() != expected {
                return Err(VerifierError::Binding(format!(
                    "proof payload_digest '{}' does not match canonical bytes '{}'",
                    proof.payload_digest, expected
                )));
            }
            let parts: Vec<&str> = proof.jws.split('.').collect();
            if parts.len() != 3 || !parts[1].is_empty() {
                return Err(VerifierError::Encoding(
                    "detached JWS must be header..signature with empty payload segment".to_owned(),
                ));
            }
            let header_bytes = base64url_decode(parts[0])
                .map_err(|err| VerifierError::Encoding(format!("invalid header base64: {err}")))?;
            let header: JwsProtectedHeader =
                serde_json::from_slice(&header_bytes).map_err(|err| {
                    VerifierError::Encoding(format!("invalid protected header: {err}"))
                })?;
            if header.alg != proof.alg {
                return Err(VerifierError::Binding(format!(
                    "protected header alg '{}' does not match proof alg '{}'",
                    header.alg, proof.alg
                )));
            }
            if header.alg != "EdDSA" {
                return Err(VerifierError::Backend(format!(
                    "Ed25519 verifier received non-EdDSA protected alg '{}'",
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
            // Legacy producers may have emitted `typ:"JWT"`; accept it for
            // backward verification but the SDK-canonical header omits `typ`.
            if let Some(typ) = header.typ.as_deref()
                && typ != "JWT"
            {
                return Err(VerifierError::Encoding(format!(
                    "unsupported detached JWS typ '{typ}'"
                )));
            }
            let sig_bytes = base64url_decode(parts[2])
                .map_err(|err| VerifierError::Encoding(format!("invalid sig base64: {err}")))?;
            let signing_input = format!("{}.{}", parts[0], base64url_encode(canonical_bytes));
            self.verify_signing_input(&signing_input, &sig_bytes, public_key)
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
            verifying.verify(signing_input.as_bytes(), &sig).map_err(|err| {
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
            "EdDSA"
        }
    }

    /// RFC 7797 unencoded-payload signing input: `b64url(header) "." b64url(payload)`.
    ///
    /// We base64-encode the canonical bytes here (rather than passing
    /// them in directly with `b64="false"`) because every Cokret SDK
    /// that talks to this verifier today expects the standard JWS
    /// shape. The detached form lives in the wire JWS — the middle
    /// segment is stripped — but the signing-input stays
    /// `header.payload`.
    pub(super) fn detached_signing_input(bytes: &[u8]) -> String {
        let header_b64 = base64url_encode(PROTECTED_HEADER_EDDSA.as_bytes());
        format!("{header_b64}.{}", base64url_encode(bytes))
    }

    pub(super) fn detached_jws_over(signing_key: &SigningKey, bytes: &[u8]) -> String {
        let signing_input = detached_signing_input(bytes);
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = base64url_encode(signature.to_bytes());
        let header_b64 = base64url_encode(PROTECTED_HEADER_EDDSA.as_bytes());
        format!("{header_b64}..{sig_b64}")
    }
}

#[cfg(feature = "signer")]
pub use ed25519_jws::{Ed25519DetachedJwsSigner, Ed25519DetachedJwsVerifier};

/// Construct a [`Proof`] envelope for an already-signed payload. The
/// caller is responsible for supplying the algorithm name and the
/// detached JWS string produced by their signer.
#[allow(clippy::too_many_arguments)]
pub fn build_proof_envelope(
    kind: impl Into<String>,
    algorithm: impl Into<String>,
    verification_method: impl Into<String>,
    payload_digest: Hash,
    domain: Option<String>,
    audience: Option<cokret_core::Audience>,
    jws: impl Into<String>,
) -> Proof {
    Proof {
        kind: kind.into(),
        alg: algorithm.into(),
        verification_method: verification_method.into(),
        payload_digest,
        created_at: Utc::now(),
        domain,
        audience,
        jws: jws.into(),
    }
}

/// Sugar for the canonical detached-JWS production kind constant.
pub fn detached_jws_kind() -> &'static str {
    proof_kind::DETACHED_JWS
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn proof_type_distinguishes_dev_and_production() {
        let prod = ProofType::production("detached_jws", "EdDSA");
        let dev = ProofType::development("in-memory test fixture");
        assert!(!prod.is_development());
        assert!(dev.is_development());
        assert_eq!(prod.to_string(), "production(detached_jws/EdDSA)");
        assert_eq!(dev.to_string(), "development(in-memory test fixture)");
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
    fn production_verifier_assert_rejects_dev_kind_proofs() {
        struct NoopVerifier;
        impl EventVerifier for NoopVerifier {
            fn verify(
                &self,
                _: &[u8],
                _: &[u8],
                _: &PublicKeyMaterial,
            ) -> std::result::Result<(), VerifierError> {
                Ok(())
            }
            fn algorithm(&self) -> &str {
                "EdDSA"
            }
        }
        let verifier = ProductionVerifier::wrap(NoopVerifier);
        let dev_proof = build_proof_envelope(
            "dev",
            "EdDSA",
            "did:web:alice.example#key-1",
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
            None,
            None,
            "junk",
        );
        let err = verifier.assert_production_proof(&dev_proof).unwrap_err();
        assert!(matches!(err, VerifierError::DevProofRejected(_)));

        let prod_proof = build_proof_envelope(
            proof_kind::DETACHED_JWS,
            "EdDSA",
            "did:web:alice.example#key-1",
            Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
            None,
            None,
            "header..sig",
        );
        verifier.assert_production_proof(&prod_proof).unwrap();
    }

    #[test]
    fn production_verifier_typed_rejects_development_proof_type() {
        struct AlwaysOk;
        impl EventVerifier for AlwaysOk {
            fn verify(
                &self,
                _: &[u8],
                _: &[u8],
                _: &PublicKeyMaterial,
            ) -> std::result::Result<(), VerifierError> {
                Ok(())
            }
            fn algorithm(&self) -> &str {
                "EdDSA"
            }
        }
        let verifier = ProductionVerifier::wrap(AlwaysOk);
        let public = PublicKeyMaterial::Ed25519Raw { bytes: vec![0u8; 32] };
        let dev = ProofType::development("unit test stub");
        let err = verifier.verify_typed(&dev, b"bytes", b"sig", &public).unwrap_err();
        assert!(matches!(err, VerifierError::DevProofRejected(_)));
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
        let signer = Ed25519DetachedJwsSigner::from_seed([1u8; 32], "did:web:alice.example#key-1");
        let verifier = Ed25519DetachedJwsVerifier::new();
        let public_key =
            PublicKeyMaterial::Ed25519Raw { bytes: signer.verifying_key().to_bytes().to_vec() };
        let builder = EventProofBuilder::new();
        let signed = builder.sign(&json!({"hello": "world"}), &signer).unwrap();
        verifier.verify(&signed.canonical_bytes, &signed.signature, &public_key).unwrap();
    }

    #[cfg(feature = "signer")]
    #[test]
    fn ed25519_signer_proof_round_trips_through_jws_verifier() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let signer = Ed25519DetachedJwsSigner::from_seed([2u8; 32], "did:web:bob.example#key-1");
        let (bytes, proof) = signer
            .sign_payload(&json!({"a": 1, "b": 2}), Some("api.example".to_owned()), None)
            .unwrap();
        let verifier = Ed25519DetachedJwsVerifier::new();
        let public_key =
            PublicKeyMaterial::Ed25519Raw { bytes: signer.verifying_key().to_bytes().to_vec() };
        verifier.verify_proof(&proof, &bytes, &public_key).unwrap();
        // Tampering MUST fail.
        let mut tampered = bytes;
        tampered.push(b'!');
        assert!(verifier.verify_proof(&proof, &tampered, &public_key).is_err());

        let signature = proof.jws.rsplit('.').next().unwrap();
        let bad_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let mut header_tampered = proof.clone();
        header_tampered.jws = format!("{bad_header}..{signature}");
        assert!(
            verifier
                .verify_proof(&header_tampered, &tampered[..tampered.len() - 1], &public_key)
                .is_err()
        );

        let crit_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT","crit":["b64"]}"#);
        let mut crit_tampered = proof.clone();
        crit_tampered.jws = format!("{crit_header}..{signature}");
        assert!(
            verifier
                .verify_proof(&crit_tampered, &tampered[..tampered.len() - 1], &public_key)
                .is_err()
        );
    }

    #[cfg(feature = "signer")]
    #[test]
    fn ed25519_signer_proof_type_is_production() {
        let pt = Ed25519DetachedJwsSigner::proof_type();
        assert!(!pt.is_development());
        match pt {
            ProofType::Production { kind, algorithm } => {
                assert_eq!(kind, "detached_jws");
                assert_eq!(algorithm, "EdDSA");
            }
            other => panic!("expected production proof type, got {other:?}"),
        }
    }
}
