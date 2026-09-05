//! Telling a real proof apart from a placeholder.
//!
//! Placeholder detached JWS values (`"eyJhbGciOiJFZDI1NTE5In0..c2lnbmF0dXJl"`,
//! `"header..producer"`, `"test-detached-jws"`, ...) and real Ed25519
//! signatures land in the same `ProducerEventProof` with the same field shape,
//! so replacing either with the other passes: a test that only ever checked
//! shape keeps passing against a real signature, and a test that verifies
//! signatures silently stops verifying anything when handed a placeholder.
//! Enumerating the literals does not converge — the workspace carries well over
//! a hundred, most of them deliberate negative cases — so the lever is the
//! type, not a list.
//!
//! [`ProofFidelity`] is carried alongside every Event this crate builds so the
//! difference is visible at the call site instead of being a property of which
//! constructor someone happened to import. The placeholder JWS itself has one
//! definition, `arkret_wire::test_support::structural_only_detached_jws`, which
//! this signer reaches through the `PayloadSigner` boundary.

use arkret_canonical::canonical;
use arkret_wire::test_support::structural_only_detached_jws;
use arkret_wire::{Did, DidUrl, Hash, PayloadSignature, PayloadSigner, Result};
use chrono::Utc;

/// What a fixture's proof actually establishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofFidelity {
    /// The proof is a real signature over the canonical transcript. A verifier
    /// accepts it, and any mutation of the covered bytes makes it fail.
    Verifiable,
    /// The proof is well-formed for the wire grammar and binds the payload
    /// digest, but carries no key material. A verifier rejects it. Use it only
    /// where the case under test is the envelope shape, never where the case
    /// is that something verified.
    StructuralOnly,
}

impl ProofFidelity {
    /// Whether a signature verifier is expected to accept this proof.
    #[must_use]
    pub const fn is_verifiable(self) -> bool {
        matches!(self, Self::Verifiable)
    }
}

/// A [`PayloadSigner`] that produces a wire-valid detached JWS with no key.
///
/// The signature segment is the payload digest, so the placeholder still
/// changes when the covered bytes change — a fixture cannot accidentally pin a
/// constant that survives a payload edit. It remains unverifiable by
/// construction, and everything it signs is reported as
/// [`ProofFidelity::StructuralOnly`].
pub struct StructuralOnlyPayloadSigner {
    did: Did,
    verification_method: DidUrl,
}

impl StructuralOnlyPayloadSigner {
    /// A placeholder signer publishing `verification_method` for `did`.
    #[must_use]
    pub fn new(did: Did, verification_method: DidUrl) -> Self {
        Self {
            did,
            verification_method,
        }
    }
}

impl PayloadSigner for StructuralOnlyPayloadSigner {
    fn signer_did(&self) -> &Did {
        &self.did
    }

    fn verification_method_id(&self) -> &DidUrl {
        &self.verification_method
    }

    fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<PayloadSignature> {
        let payload_digest = Hash::new(canonical::sha256_digest(canonical_bytes))?;
        Ok(PayloadSignature {
            verification_method: self.verification_method.clone(),
            jws: structural_only_detached_jws(&payload_digest),
            payload_digest,
            created_at: Utc::now(),
        })
    }

    fn sign_notary_payload_with_digest_suite(
        &self,
        canonical_bytes: &[u8],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<PayloadSignature> {
        let payload_digest = Hash::new(canonical::digest(digest_suite, canonical_bytes))?;
        Ok(PayloadSignature {
            verification_method: self.verification_method.clone(),
            jws: structural_only_detached_jws(&payload_digest),
            payload_digest,
            created_at: Utc::now(),
        })
    }
}
