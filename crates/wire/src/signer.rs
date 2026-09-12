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
//! feature, and other backends (HSM, threshold scheme) can layer on the
//! same trait.

use crate::{
    Did, DidUrl, Hash, MultiSigKind, MultiSignature, PayloadSignature, Result, Seal, SealSignature,
    UnsignedSeal, WireError, canonical,
};

/// Trait implemented by Seal / notary signers (Ed25519 keypair, HSM,
/// threshold scheme, etc.).
pub trait PayloadSigner {
    /// DID of the signing identity. For Seals this is one of the notary-set
    /// members.
    fn signer_did(&self) -> &Did;

    /// The verification method id (e.g. `did:webvh:z6mkfixture:alice.example#key-1`)
    /// the signer will publish as `PayloadSignature.verification_method`.
    fn verification_method_id(&self) -> &DidUrl;

    /// Sign arbitrary canonical bytes with the signer's key, producing a
    /// detached JWS plus the matching `payload_digest`. Helpers such as
    /// [`Seal::sign_with_signers`] builds the canonical body bytes and
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
    /// Build a quorum Seal and sign its commit transcript.
    pub fn sign_with_signers<S>(
        body: UnsignedSeal,
        view: u64,
        digest_suite: arkret_canonical::DigestSuite,
        signers: &[&S],
    ) -> Result<Seal>
    where
        S: PayloadSigner + ?Sized,
    {
        if signers.is_empty() {
            return Err(WireError::Protocol(
                "Seal::sign_with_signers requires at least one signer".to_owned(),
            ));
        }
        let body_bytes = canonical::canonical_json_bytes(&body)?;
        let seal_digest = Hash::new(canonical::digest(digest_suite, &body_bytes))?;
        let transcript = canonical::canonical_json_bytes(&SealCommitTranscript {
            context: "ak.seal.commit.v1",
            seal_digest: &seal_digest,
            configuration_ref: &body.configuration_ref,
            notary_seq: body.notary_seq,
            view,
        })?;
        let mut signatures = Vec::with_capacity(signers.len());
        for signer in signers {
            signatures.push(seal_signature(
                signer.sign_notary_payload_with_digest_suite(&transcript, digest_suite)?,
            ));
        }
        signatures.sort_by(|left, right| left.verification_method.cmp(&right.verification_method));
        Seal::from_canonical_body_and_signature(
            &body_bytes,
            MultiSignature {
                kind: MultiSigKind::MultiSig,
                signatures,
                view,
            },
            digest_suite,
        )
    }
}

#[derive(serde::Serialize)]
struct SealCommitTranscript<'a> {
    context: &'static str,
    seal_digest: &'a Hash,
    configuration_ref: &'a crate::EventId,
    notary_seq: u64,
    view: u64,
}

fn seal_signature(signature: PayloadSignature) -> SealSignature {
    signature.into()
}

// ---------------------------------------------------------------------------
// Threshold partial-signature aggregation
// ---------------------------------------------------------------------------

/// One signer's contribution to a `k`-of-`n` threshold signature.
///
/// `signature` is the raw scheme-specific signature bytes (e.g. an Ed25519
/// detached JWS sig segment, BLS partial, FROST share). The aggregator does
/// NOT recompute it: callers MUST run their threshold-scheme verifier on
/// each partial via [`ThresholdAggregator::add_partial`] before the partial
/// enters the aggregator.
///
/// `kid` is the verification method id (`<did>#<key-fragment>`) so
/// downstream verifiers can resolve `signer_did` → public key without
/// trusting the partial body alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialSignature {
    pub signer_did: Did,
    pub signature: Vec<u8>,
    pub kid: DidUrl,
}

impl PartialSignature {
    pub fn new(signer_did: Did, signature: Vec<u8>, kid: DidUrl) -> Self {
        Self {
            signer_did,
            signature,
            kid,
        }
    }
}

/// Threshold partial-signature collector.
///
/// Collects [`PartialSignature`]s contributed by `n` signers and produces an
/// aggregated [`MultiSignature`] (or an opaque proof string suitable for
/// a canonical [`MultiSignature`] once the threshold `k` is met.
///
/// This struct is scheme-agnostic: it does NOT know how to combine partials
/// (BLS / FROST / Schnorr-musig all differ). Callers MUST call
/// [`Self::add_partial`] only after externally verifying the partial. The
/// final [`Self::aggregate`] step concatenates the per-partial signatures
/// into the Seal's quorum certificate whose individual members the receiver
/// re-checks against the frozen configuration.
///
/// For schemes that produce a single short aggregated proof (e.g. BLS), use
/// [`Self::aggregate_proof`] which returns the raw concatenation that
/// downstream code can replace with the scheme's own aggregator output.
#[derive(Clone, Debug)]
pub struct ThresholdAggregator {
    threshold: usize,
    partials: Vec<PartialSignature>,
}

impl ThresholdAggregator {
    /// Create a new aggregator with the given threshold `k`.
    ///
    /// Returns an error if `threshold == 0` (a zero threshold would
    /// trivially aggregate empty signer sets).
    pub fn new(threshold: usize) -> Result<Self> {
        if threshold == 0 {
            return Err(WireError::Protocol(
                "ThresholdAggregator threshold must be at least 1".to_owned(),
            ));
        }
        Ok(Self {
            threshold,
            partials: Vec::new(),
        })
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn partials(&self) -> &[PartialSignature] {
        &self.partials
    }

    /// Number of partials collected so far.
    pub fn collected(&self) -> usize {
        self.partials.len()
    }

    /// Threshold met (collected >= threshold).
    pub fn threshold_met(&self) -> bool {
        self.partials.len() >= self.threshold
    }

    /// Append a partial without verifying it. Caller is responsible for
    /// running the threshold scheme's per-partial verifier first.
    ///
    /// Rejects duplicate `signer_did` so the same signer can't double-count.
    pub fn add_partial(&mut self, partial: PartialSignature) -> Result<()> {
        if self
            .partials
            .iter()
            .any(|p| p.signer_did == partial.signer_did)
        {
            return Err(WireError::Protocol(format!(
                "duplicate partial from signer {}",
                partial.signer_did
            )));
        }
        if partial.signature.is_empty() {
            return Err(WireError::Protocol(format!(
                "partial signature from {} is empty",
                partial.signer_did
            )));
        }
        // `kid` is a `DidUrl`, so emptiness and "is it a DID URL at all" are
        // enforced by the type at construction time; no string re-check here.
        self.partials.push(partial);
        Ok(())
    }

    /// Produce an aggregated [`MultiSignature`] from the collected partials.
    ///
    /// Validates the threshold is met and that each partial individually
    /// verifies via the supplied `verify` closure (one call per partial).
    /// Returns an error if any individual verification fails or threshold
    /// not met.
    ///
    /// The resulting [`MultiSignature`] has one [`SealSignature`] per
    /// partial, with `payload_digest` = the supplied canonical-bytes hash and
    /// `jws` = the partial's raw signature base64-encoded so the wire shape
    /// is uniform regardless of the underlying scheme.
    pub fn aggregate<F>(
        &self,
        canonical_bytes: &[u8],
        view: u64,
        verify: F,
    ) -> Result<MultiSignature>
    where
        F: Fn(&PartialSignature, &[u8]) -> Result<()>,
    {
        if !self.threshold_met() {
            return Err(WireError::Protocol(format!(
                "threshold not met: have {} partials, need {}",
                self.partials.len(),
                self.threshold
            )));
        }
        let payload_digest = Hash::new(canonical::sha256_digest(canonical_bytes))
            .map_err(|err| WireError::Protocol(format!("invalid canonical hash: {err}")))?;
        let mut signatures = Vec::with_capacity(self.partials.len());
        for partial in &self.partials {
            verify(partial, canonical_bytes)?;
            // Encode the raw signature bytes via base64url-no-pad so the
            // wire shape stays uniform; receivers re-decode and re-verify
            // via the same scheme verifier.
            let encoded_sig = crate::base64url::base64url_encode(&partial.signature);
            signatures.push(SealSignature {
                verification_method: partial.kid.clone(),
                payload_digest: payload_digest.clone(),
                jws: format!("..{encoded_sig}"),
            });
        }
        Ok(MultiSignature {
            kind: MultiSigKind::MultiSig,
            signatures,
            view,
        })
    }
}
