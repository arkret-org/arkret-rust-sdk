//! Seal signer trait + builder helpers.
//!
//! The protocol's content-addressed Seal objects must be signed at the notary
//! boundary. The SDK exposes a tiny signer trait so downstream code (soland
//! seal reconfiguration, notary services, conformance harnesses) can plug
//! production keys in without re-implementing canonical bytes / id / payload
//! hash plumbing.
//!
//! There is no Move signer: v1 has no standalone Move object, and a Control
//! Move is an ordinary signed Event.
//!
//! The trait deliberately stays in the wire owner crate (with no crypto deps): an
//! Ed25519 implementation lives in `arkret-signatures` behind the `signer`
//! feature, and HSM-backed implementations can use the same trait.

use crate::{
    Did, DidUrl, Hash, PayloadSignature, Result, Seal, SealSignature, UnsignedSeal, canonical,
};

/// Trait implemented by Seal / notary signers (Ed25519 keypair, HSM,
/// hardware-backed key, etc.).
pub trait PayloadSigner {
    /// DID of the signing identity. For Seals this is the frozen authority.
    fn signer_did(&self) -> &Did;

    /// The verification method id (e.g. `did:webvh:z6mkfixture:alice.example#key-1`)
    /// the signer will publish as `PayloadSignature.verification_method`.
    fn verification_method_id(&self) -> &DidUrl;

    /// Sign arbitrary canonical bytes with the signer's key, producing a
    /// detached JWS plus the matching `payload_digest`. Helpers such as
    /// [`Seal::sign_with_signer`] builds the canonical body bytes and
    /// delegate here.
    fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<PayloadSignature>;

    /// Sign a Seal/notary payload while binding both the typed digest suite and
    /// the frozen verification method. Unlike ordinary Event proofs, the Seal
    /// profile requires protected `kid` to equal [`Self::verification_method_id`].
    /// Implementations MUST therefore construct a fresh notary-profile JWS;
    /// rewriting only `payload_digest` on an ordinary proof is invalid.
    fn sign_notary_payload_with_digest_suite(
        &self,
        canonical_bytes: &[u8],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<PayloadSignature>;
}

impl Seal {
    /// Sign an authority Seal's canonical commit transcript.
    /// The caller must durably reserve this exact body at its lineage position before signing.
    pub fn sign_with_signer<S: PayloadSigner + ?Sized>(
        body: UnsignedSeal,
        digest_suite: arkret_canonical::DigestSuite,
        signer: &S,
    ) -> Result<Seal> {
        let body_bytes = canonical::canonical_json_bytes(&body)?;
        let seal_digest = Hash::new(canonical::digest(digest_suite, &body_bytes))?;
        let transcript = canonical::canonical_json_bytes(&SealCommitTranscript {
            context: "ak.seal.commit.v1",
            seal_digest: &seal_digest,
        })?;
        Seal::from_canonical_body_and_signature(
            &body_bytes,
            SealSignature::from(
                signer.sign_notary_payload_with_digest_suite(&transcript, digest_suite)?,
            ),
            digest_suite,
        )
    }
}

#[derive(serde::Serialize)]
struct SealCommitTranscript<'a> {
    context: &'static str,
    seal_digest: &'a Hash,
}
