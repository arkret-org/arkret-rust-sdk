//! DID key binding proof — wire shape, verify, and Ed25519/multicodec
//! helpers.
//!
//! A *binding proof* is the minimal protocol primitive that says
//! "subject `S` controls key `K`": a signed assertion whose payload
//! commits to the subject and whose signature is produced by the
//! private half of `K`. The SDK hosts the pure verify pipeline so every
//! consumer (coauth, starid, inkson, cotest) reaches the same
//! `Ok(()) / Err(reason)` decision for the same `(proof, subject)`
//! tuple.
//!
//! The shape is intentionally narrow — no JWS envelope, no DID document
//! resolve. Higher-level strands that need a JWS envelope (e.g. coauth's
//! `ak.did_binding.control_proof.v1` JWT over a resolved DID doc) layer
//! on top of this primitive but still call back into
//! [`verify_binding_proof`] for the final cryptographic check once
//! they've extracted `(public_key, signature, payload)` from the
//! envelope.
//!
//! # Wire shape
//!
//! ```text
//! BindingProof {
//!   kind:       BindingProofKind,         // "Ed25519V1" today
//!   payload:    Vec<u8>,                  // canonical bytes; subject
//!                                         // MUST appear inside
//!   signature:  Vec<u8>,                  // 64 bytes for Ed25519V1
//!   public_key: Vec<u8>,                  // 32 bytes for Ed25519V1
//! }
//! ```
//!
//! # Subject binding
//!
//! `verify_binding_proof(&proof, expected_subject)` rejects unless the
//! UTF-8 bytes of `expected_subject` appear as a contiguous substring
//! of `proof.payload`. That's the canonical "subject embedded in the
//! payload" check from the binding spec — callers that need a stricter
//! schema (e.g. JSON-shaped payload with a specific field name) layer
//! their own check on top before invoking this verify.
//!
//! # Multicodec encoding
//!
//! [`multicodec_ed25519_public_key`] / [`multicodec_ed25519_from_bytes`]
//! produce the `z<base58btc(0xed01 || pubkey)>` form the `did:key`
//! method (and starid's `update_keys` slot) accept.
//! [`decode_multicodec_ed25519`] is the inverse and is used by tests
//! and adapters that need to extract the raw 32-byte key from a
//! multibase string.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::helpers::decode_base58btc;

/// Multicodec varint tag for Ed25519 public keys: `0xed 0x01`.
///
/// Two bytes are prepended to the 32-byte raw key before
/// multibase-encoding (`z` + base58btc) per
/// <https://github.com/multiformats/multicodec/blob/master/table.csv>.
const MULTICODEC_ED25519_PUB: [u8; 2] = [0xed, 0x01];

/// Base58btc alphabet (Bitcoin) used by `did:key` / multibase `z…`
/// prefix. Inlined to avoid pulling the `multibase` crate just for one
/// 58-character table; matches the alphabet
/// [`crate::identity::helpers::decode_base58btc`] consumes.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Discriminator for the on-wire binding proof family. Today only
/// `Ed25519V1` ships. `WebAuthnCose` is reserved for a future variant
/// that carries a raw COSE_Sign1 envelope produced by a WebAuthn
/// authenticator; until that lands [`verify_binding_proof`] returns
/// [`BindingError::Unsupported`] for it (rather than panicking).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingProofKind {
    /// Detached Ed25519 signature over `payload` with `public_key` as
    /// the raw 32-byte verifying key. v1 wire of the binding-proof
    /// primitive.
    Ed25519V1,
}

/// On-wire DID key binding proof. See module docs for the byte-level
/// shape and verify contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BindingProof {
    /// Algorithm family of `signature`.
    pub kind: BindingProofKind,
    /// Canonical payload bytes the signature commits to. MUST contain
    /// the expected subject string as a contiguous substring.
    pub payload: Vec<u8>,
    /// Raw signature bytes. 64 bytes for [`BindingProofKind::Ed25519V1`].
    pub signature: Vec<u8>,
    /// Raw public key bytes. 32 bytes for [`BindingProofKind::Ed25519V1`].
    pub public_key: Vec<u8>,
}

/// Errors returned by [`verify_binding_proof`] and the multicodec
/// helpers. All variants are deterministic from the inputs — verify
/// never returns a transient or runtime error.
#[derive(Debug, Error)]
pub enum BindingError {
    /// `proof.kind` is a known variant but no verifier is wired up for
    /// it in this SDK version (e.g. `WebAuthnCose` before it lands).
    /// Callers should treat this as a soft schema-level failure, not a
    /// signature failure.
    #[error("binding proof kind is not yet supported by this SDK")]
    Unsupported,

    /// `proof.payload` is empty — verification refuses to accept an
    /// empty payload (matches `jws::verify_jws_ed25519`'s contract).
    #[error("binding proof payload is empty")]
    EmptyPayload,

    /// `proof.public_key` has the wrong length for `proof.kind`.
    #[error(
        "binding proof public_key length {actual} does not match expected {expected} for kind {kind:?}"
    )]
    PublicKeyLength {
        kind: BindingProofKind,
        expected: usize,
        actual: usize,
    },

    /// `proof.signature` has the wrong length for `proof.kind`.
    #[error(
        "binding proof signature length {actual} does not match expected {expected} for kind {kind:?}"
    )]
    SignatureLength {
        kind: BindingProofKind,
        expected: usize,
        actual: usize,
    },

    /// The expected subject string did not appear as a contiguous
    /// UTF-8 substring of `proof.payload`. The signature may still be
    /// cryptographically valid, but it's not a binding for `subject`.
    #[error("binding proof payload does not contain expected subject")]
    SubjectMismatch,

    /// `proof.signature` did not verify against `proof.payload` under
    /// `proof.public_key`. Covers tampered payload, wrong key, and any
    /// other RFC 8032 verify failure — the underlying ed25519-dalek
    /// error message is preserved for callers to log.
    #[error("binding proof signature failed to verify: {0}")]
    SignatureMismatch(String),

    /// A multibase / multicodec input was malformed (wrong prefix,
    /// invalid base58, wrong multicodec tag, wrong key length).
    /// Returned by [`decode_multicodec_ed25519`].
    #[error("invalid multicodec encoding: {0}")]
    InvalidMulticodec(String),
}

/// Verify a binding proof against `expected_subject`.
///
/// Returns `Ok(())` if all of the following hold:
///   1. `proof.kind` is a supported variant.
///   2. `proof.payload` is non-empty.
///   3. `proof.public_key` / `proof.signature` have the expected length for the variant.
///   4. The UTF-8 bytes of `expected_subject` appear as a contiguous substring of `proof.payload`.
///   5. The signature verifies against the payload under the public key per the variant's
///      algorithm.
///
/// Otherwise returns the corresponding [`BindingError`]. No I/O, no
/// allocations beyond `Signature::from_bytes` / `VerifyingKey::from_bytes`.
pub fn verify_binding_proof(
    proof: &BindingProof,
    expected_subject: &str,
) -> Result<(), BindingError> {
    match proof.kind {
        BindingProofKind::Ed25519V1 => verify_ed25519_v1(proof, expected_subject),
    }
}

fn verify_ed25519_v1(proof: &BindingProof, expected_subject: &str) -> Result<(), BindingError> {
    if proof.payload.is_empty() {
        return Err(BindingError::EmptyPayload);
    }
    if proof.public_key.len() != 32 {
        return Err(BindingError::PublicKeyLength {
            kind: proof.kind,
            expected: 32,
            actual: proof.public_key.len(),
        });
    }
    if proof.signature.len() != 64 {
        return Err(BindingError::SignatureLength {
            kind: proof.kind,
            expected: 64,
            actual: proof.signature.len(),
        });
    }
    if !payload_contains_subject(&proof.payload, expected_subject) {
        return Err(BindingError::SubjectMismatch);
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&proof.public_key);
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| BindingError::SignatureMismatch(format!("invalid public key: {e}")))?;
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&proof.signature);
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify_strict(&proof.payload, &signature)
        .map_err(|e| BindingError::SignatureMismatch(format!("{e}")))
}

fn payload_contains_subject(payload: &[u8], subject: &str) -> bool {
    let needle = subject.as_bytes();
    if needle.is_empty() {
        return false;
    }
    if needle.len() > payload.len() {
        return false;
    }
    payload.windows(needle.len()).any(|w| w == needle)
}

/// Derive an `ed25519_dalek::SigningKey` from a raw 32-byte RFC 8032
/// seed. Pure function; no passkey / OIDC coupling. Used by signer-side
/// callers that have already extracted a 32-byte secret from whatever
/// source they trust (env var, KDF, HSM-unsealed buffer, ...).
#[must_use]
pub fn derive_ed25519_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Sign `payload` with `signing_key` and produce a [`BindingProof`]
/// for the Ed25519V1 variant. Convenience for tests and signer-side
/// callers that want a single primitive that emits exactly the bytes
/// [`verify_binding_proof`] consumes.
#[must_use]
pub fn sign_binding_proof_ed25519(signing_key: &SigningKey, payload: Vec<u8>) -> BindingProof {
    let signature = signing_key.sign(&payload).to_bytes().to_vec();
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    BindingProof {
        kind: BindingProofKind::Ed25519V1,
        payload,
        signature,
        public_key,
    }
}

/// Encode an Ed25519 public key as the multibase string
/// `z<base58btc(0xed01 || pubkey)>`.
///
/// This is the canonical `did:key`-friendly form: the leading `z`
/// flags base58btc multibase, the `0xed 0x01` multicodec varint tags
/// the key as Ed25519-pub, and the next 32 bytes are the raw verifying
/// key. Output for a valid Ed25519 key always starts with `z6Mk`
/// because of how the varint tag + 32-byte key encode under base58btc.
#[must_use]
pub fn multicodec_ed25519_public_key(verifying_key: &VerifyingKey) -> String {
    multicodec_ed25519_from_bytes(&verifying_key.to_bytes())
}

/// Lower-level multicodec encoder: takes raw 32 bytes (intended to be
/// an Ed25519 public key but the encoder doesn't enforce that — it
/// just prepends the Ed25519-pub multicodec tag and base58btc-encodes
/// the result). Useful for opaque-32-byte-identifier callers (e.g.
/// coauth's `passkey_derive`, which hashes a COSE key down to 32 bytes
/// and wears the Ed25519-pub envelope by spec) and for tests.
#[must_use]
pub fn multicodec_ed25519_from_bytes(bytes: &[u8; 32]) -> String {
    let mut envelope = Vec::with_capacity(2 + bytes.len());
    envelope.extend_from_slice(&MULTICODEC_ED25519_PUB);
    envelope.extend_from_slice(bytes);
    let mut out = String::with_capacity(1 + envelope.len() * 2);
    out.push('z');
    out.push_str(&base58btc_encode(&envelope));
    out
}

/// Decode a multibase `z…` string produced by
/// [`multicodec_ed25519_public_key`] / [`multicodec_ed25519_from_bytes`]
/// back into the 32-byte payload. Validates the leading `z`, the
/// `0xed 0x01` multicodec tag, and the 32-byte key length.
///
/// Returns the raw 32 bytes the encoder consumed — for a real Ed25519
/// public key this is the value that round-trips through
/// `VerifyingKey::from_bytes`.
pub fn decode_multicodec_ed25519(encoded: &str) -> Result<[u8; 32], BindingError> {
    let body = encoded.strip_prefix('z').ok_or_else(|| {
        BindingError::InvalidMulticodec("missing multibase 'z' prefix".to_owned())
    })?;
    let decoded = decode_base58btc(body)
        .ok_or_else(|| BindingError::InvalidMulticodec("invalid base58btc body".to_owned()))?;
    if decoded.len() != 34 {
        return Err(BindingError::InvalidMulticodec(format!(
            "expected 34-byte envelope (2-byte tag + 32-byte key), got {} bytes",
            decoded.len()
        )));
    }
    if decoded[..2] != MULTICODEC_ED25519_PUB {
        return Err(BindingError::InvalidMulticodec(format!(
            "expected multicodec tag {:02x?}, got {:02x?}",
            MULTICODEC_ED25519_PUB,
            &decoded[..2]
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded[2..]);
    Ok(out)
}

/// Decode a multibase `z…` string carrying a **64-byte Ed25519 signature**
/// back into its raw bytes.
///
/// Mirrors [`decode_multicodec_ed25519`] (public-key side): validates the
/// leading multibase `z`, requires the `0xed 0x01` Ed25519 multicodec tag,
/// and enforces the fixed 64-byte signature length. Any other multicodec
/// prefix or a wrong length is rejected.
pub fn decode_multicodec_ed25519_signature(encoded: &str) -> Result<[u8; 64], BindingError> {
    let body = encoded.strip_prefix('z').ok_or_else(|| {
        BindingError::InvalidMulticodec("missing multibase 'z' prefix".to_owned())
    })?;
    let decoded = decode_base58btc(body)
        .ok_or_else(|| BindingError::InvalidMulticodec("invalid base58btc body".to_owned()))?;
    if decoded.len() != 66 {
        return Err(BindingError::InvalidMulticodec(format!(
            "expected 66-byte envelope (2-byte tag + 64-byte signature), got {} bytes",
            decoded.len()
        )));
    }
    if decoded[..2] != MULTICODEC_ED25519_PUB {
        return Err(BindingError::InvalidMulticodec(format!(
            "expected multicodec tag {:02x?}, got {:02x?}",
            MULTICODEC_ED25519_PUB,
            &decoded[..2]
        )));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&decoded[2..]);
    Ok(out)
}

/// Minimal base58btc encoder. Accepts an arbitrary byte slice and
/// returns the base58btc-encoded string (no leading multibase tag —
/// that's the caller's job).
fn base58btc_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();

    let mut input: Vec<u8> = bytes.to_vec();
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);

    let mut start = leading_zeros;
    while start < input.len() {
        let mut remainder: u32 = 0;
        for byte in input.iter_mut().skip(start) {
            let acc = (remainder << 8) | u32::from(*byte);
            *byte = u8::try_from(acc / 58).expect("acc/58 fits in u8 because acc < 58 * 256");
            remainder = acc % 58;
        }
        output.push(BASE58_ALPHABET[remainder as usize]);
        while start < input.len() && input[start] == 0 {
            start += 1;
        }
    }

    let mut s = String::with_capacity(leading_zeros + output.len());
    for _ in 0..leading_zeros {
        s.push('1');
    }
    for &b in output.iter().rev() {
        s.push(b as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity vector: same seed → same key bytes. Locks down the
    /// "derive is pure" property the SDK contract advertises.
    #[test]
    fn derive_ed25519_from_seed_is_deterministic() {
        let seed = [0x42u8; 32];
        let a = derive_ed25519_from_seed(&seed);
        let b = derive_ed25519_from_seed(&seed);
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert_eq!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
    }

    /// Sign-then-verify round trip. The canonical happy path: signer
    /// emits a proof, verifier accepts it for the same subject.
    #[test]
    fn sign_then_verify_round_trip() {
        let seed = [0x11u8; 32];
        let signing = derive_ed25519_from_seed(&seed);
        let subject = "did:webvh:z6mkfixture:alice.example";
        let payload = format!("bind|{subject}|nonce-xyz").into_bytes();
        let proof = sign_binding_proof_ed25519(&signing, payload);
        verify_binding_proof(&proof, subject).expect("verify accepts a fresh proof");
    }

    /// Tampered signature must be rejected even though every other
    /// byte (payload, kind, public_key) is untouched. Catches a
    /// regression where the verifier accidentally short-circuits the
    /// `verify_strict` call.
    #[test]
    fn tampered_signature_is_rejected() {
        let seed = [0x22u8; 32];
        let signing = derive_ed25519_from_seed(&seed);
        let subject = "did:webvh:z6mkfixture:bob.example";
        let payload = format!("bind|{subject}|n1").into_bytes();
        let mut proof = sign_binding_proof_ed25519(&signing, payload);
        // Flip a bit in the signature.
        proof.signature[0] ^= 0x01;
        let err = verify_binding_proof(&proof, subject).expect_err("tampered sig must reject");
        assert!(matches!(err, BindingError::SignatureMismatch(_)));
    }

    /// Tampered payload must be rejected — the signature was over the
    /// original bytes, not the mutated ones. Same property as the
    /// tampered-signature test but exercised from the payload side.
    #[test]
    fn tampered_payload_is_rejected() {
        let seed = [0x23u8; 32];
        let signing = derive_ed25519_from_seed(&seed);
        let subject = "did:webvh:z6mkfixture:bob.example";
        let payload = format!("bind|{subject}|n2").into_bytes();
        let mut proof = sign_binding_proof_ed25519(&signing, payload);
        proof.payload[0] ^= 0x01;
        // Tampering with the payload also changes whether the subject
        // is still a substring; if it still is, the signature check
        // catches it. If it isn't (rare for a 1-bit flip in the first
        // byte), the subject check catches it. Either way, reject.
        let err = verify_binding_proof(&proof, subject).expect_err("tampered payload must reject");
        assert!(matches!(
            err,
            BindingError::SignatureMismatch(_) | BindingError::SubjectMismatch
        ));
    }

    /// Subject substring check: a proof signed for Alice does not bind
    /// Bob, even if the signature itself is valid.
    #[test]
    fn wrong_subject_is_rejected() {
        let seed = [0x33u8; 32];
        let signing = derive_ed25519_from_seed(&seed);
        let payload = b"bind|did:webvh:z6mkfixture:alice.example|n1".to_vec();
        let proof = sign_binding_proof_ed25519(&signing, payload);
        let err = verify_binding_proof(&proof, "did:webvh:z6mkfixture:bob.example")
            .expect_err("wrong subject must reject");
        assert!(matches!(err, BindingError::SubjectMismatch));
    }

    /// Empty payload must reject — we don't allow signing "nothing".
    #[test]
    fn empty_payload_is_rejected() {
        let seed = [0x44u8; 32];
        let signing = derive_ed25519_from_seed(&seed);
        // Construct directly: sign_binding_proof_ed25519 would happily
        // sign an empty vec; the verify-side guard is what we care
        // about here.
        let proof = BindingProof {
            kind: BindingProofKind::Ed25519V1,
            payload: Vec::new(),
            signature: vec![0u8; 64],
            public_key: signing.verifying_key().to_bytes().to_vec(),
        };
        let err = verify_binding_proof(&proof, "did:webvh:z6mkfixture:x.example")
            .expect_err("empty payload must reject");
        assert!(matches!(err, BindingError::EmptyPayload));
    }

    /// Wrong-length signature / public_key reject with a structured
    /// length error rather than panicking inside `from_bytes`. Two
    /// asserts in one test since they exercise the same guard family.
    #[test]
    fn wrong_length_keys_or_sigs_reject_with_structured_error() {
        let subject = "did:webvh:z6mkfixture:c.example";
        let payload = format!("bind|{subject}").into_bytes();
        let short_sig = BindingProof {
            kind: BindingProofKind::Ed25519V1,
            payload: payload.clone(),
            signature: vec![0u8; 63],
            public_key: vec![0u8; 32],
        };
        assert!(matches!(
            verify_binding_proof(&short_sig, subject),
            Err(BindingError::SignatureLength {
                expected: 64,
                actual: 63,
                ..
            })
        ));
        let short_pk = BindingProof {
            kind: BindingProofKind::Ed25519V1,
            payload,
            signature: vec![0u8; 64],
            public_key: vec![0u8; 31],
        };
        assert!(matches!(
            verify_binding_proof(&short_pk, subject),
            Err(BindingError::PublicKeyLength {
                expected: 32,
                actual: 31,
                ..
            })
        ));
    }

    /// Multicodec round trip: encode → decode → original 32 bytes.
    /// Also asserts the `z6Mk` prefix that `did:key` consumers match
    /// against, so a regression in the multicodec tag breaks this test
    /// rather than producing keys downstream rejects.
    #[test]
    fn multicodec_round_trip_and_prefix() {
        let seed = [0x55u8; 32];
        let key = derive_ed25519_from_seed(&seed).verifying_key();
        let encoded = multicodec_ed25519_public_key(&key);
        assert!(
            encoded.starts_with("z6Mk"),
            "multicodec output {encoded:?} must start with z6Mk"
        );
        let decoded = decode_multicodec_ed25519(&encoded).expect("decode succeeds");
        assert_eq!(
            decoded,
            key.to_bytes(),
            "round trip preserves the 32-byte key"
        );

        // multicodec_ed25519_from_bytes for opaque-32-byte input round
        // trips too (the encoder doesn't require a real ed25519 key).
        let opaque = [0u8; 32];
        let encoded2 = multicodec_ed25519_from_bytes(&opaque);
        let decoded2 = decode_multicodec_ed25519(&encoded2).expect("opaque round trip");
        assert_eq!(decoded2, opaque);
    }

    /// Multicodec decode rejects malformed inputs with structured
    /// errors rather than panicking. Three guard families: missing
    /// `z` prefix, wrong length, wrong tag.
    #[test]
    fn multicodec_decode_rejects_malformed_inputs() {
        assert!(matches!(
            decode_multicodec_ed25519("6Mkfoo"),
            Err(BindingError::InvalidMulticodec(_))
        ));
        // 33 bytes (2-byte tag + 31-byte key) — wrong length.
        let mut envelope = Vec::with_capacity(33);
        envelope.extend_from_slice(&MULTICODEC_ED25519_PUB);
        envelope.extend_from_slice(&[0u8; 31]);
        let short = format!("z{}", base58btc_encode(&envelope));
        assert!(matches!(
            decode_multicodec_ed25519(&short),
            Err(BindingError::InvalidMulticodec(_))
        ));
        // Wrong multicodec tag (X25519-pub = 0xec 0x01 instead of
        // Ed25519's 0xed 0x01).
        let mut envelope = Vec::with_capacity(34);
        envelope.extend_from_slice(&[0xec, 0x01]);
        envelope.extend_from_slice(&[0u8; 32]);
        let wrong_tag = format!("z{}", base58btc_encode(&envelope));
        assert!(matches!(
            decode_multicodec_ed25519(&wrong_tag),
            Err(BindingError::InvalidMulticodec(_))
        ));
    }
}
