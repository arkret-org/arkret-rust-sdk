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

use std::collections::BTreeSet;

use chrono::Utc;

use crate::{
    DidFullId, DidUrl, Hash, Hlc, MultiSigKind, MultiSignature, NotarySig, PayloadSignature,
    RealmId, Result, Seal, SealId, SealSignature, WireError, canonical,
};

/// Trait implemented by Seal / notary signers (Ed25519 keypair, HSM,
/// threshold scheme, etc.).
pub trait PayloadSigner {
    /// DID of the signing identity. For Seals this is one of the notary-set
    /// members.
    fn signer_did(&self) -> &DidFullId;

    /// The verification method id (e.g. `did:webvh:z6mkfixture:alice.example#key-1`)
    /// the signer will publish as `PayloadSignature.verification_method`.
    fn verification_method_id(&self) -> &DidUrl;

    /// Sign arbitrary canonical bytes with the signer's key, producing a
    /// detached JWS plus the matching `payload_digest`. Helpers such as
    /// [`Seal::sign_single`] build the canonical body bytes and delegate here.
    fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<PayloadSignature>;

    /// Sign canonical bytes while binding `payload_digest` to an explicit
    /// verified Realm digest suite. The compact detached JWS signs the same
    /// canonical bytes; only the typed digest field changes with the suite.
    fn sign_payload_with_digest_suite(
        &self,
        canonical_bytes: &[u8],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<PayloadSignature> {
        let mut signature = self.sign_payload(canonical_bytes)?;
        signature.payload_digest = Hash::new(canonical::digest(digest_suite, canonical_bytes))?;
        Ok(signature)
    }
}

impl Seal {
    /// Build + single-sign a normal Seal (delta-accepting). Delegates to
    /// [`Seal::sign_single_kind`] with `kind=Normal`.
    pub fn sign_single<S: PayloadSigner + ?Sized>(
        realm_id: RealmId,
        predecessor_refs: Vec<SealId>,
        delta: Vec<Hash>,
        state_root: Hash,
        hlc: Hlc,
        digest_suite: arkret_canonical::DigestSuite,
        signer: &S,
    ) -> Result<Seal> {
        Self::sign_single_kind(
            realm_id,
            predecessor_refs,
            delta,
            state_root,
            hlc,
            crate::SealKind::Normal,
            digest_suite,
            signer,
        )
    }

    /// Build + single-sign a normal Seal with an explicit construction mode.
    /// Compaction Seals require an explicit, complete
    /// `covered_event_digests` input and are therefore rejected by this
    /// delta-only convenience builder.
    ///
    /// Derives `control_event_set_root` from `delta` alone, which only
    /// equals the value a verifier recomputes when `predecessor_refs`
    /// carry no coverage of their own — i.e. genesis, or a Seal whose
    /// predecessors are all empty. `control_event_set_root` is
    /// *cumulative*: [`crate::state`-side verification][av] recomputes it
    /// over predecessor coverage ∪ delta and rejects the Seal when the
    /// declared root differs. Any Seal built on non-empty predecessors —
    /// every compaction Seal, in particular, whose empty delta hashes to
    /// the empty root — MUST use
    /// [`Seal::sign_single_kind_with_control_root`] and pass the
    /// cumulative root from the effective seal view.
    ///
    /// [av]: https://docs.rs/arkret-state
    #[allow(clippy::too_many_arguments)]
    pub fn sign_single_kind<S: PayloadSigner + ?Sized>(
        realm_id: RealmId,
        predecessor_refs: Vec<SealId>,
        delta: Vec<Hash>,
        state_root: Hash,
        hlc: Hlc,
        kind: crate::SealKind,
        digest_suite: arkret_canonical::DigestSuite,
        signer: &S,
    ) -> Result<Seal> {
        if kind.is_compaction() {
            return Err(WireError::Protocol(
                "compaction Seal requires an explicit covered_event_digests set".to_owned(),
            ));
        }
        let control_event_set_root = delta_control_root(&delta, digest_suite)?;
        Self::sign_single_kind_with_control_root(
            realm_id,
            predecessor_refs,
            delta,
            control_event_set_root,
            state_root,
            hlc,
            kind,
            digest_suite,
            signer,
        )
    }

    /// Build + single-sign a Seal whose cumulative `control_event_set_root`
    /// is supplied by the caller.
    ///
    /// This is the form to use whenever the Seal has predecessors that
    /// already cover control-plane Events: pass the root the notary computes over
    /// predecessor coverage ∪ delta (an effective seal view exposes it
    /// directly), because that is what a verifier recomputes. The
    /// delta-only shorthand [`Seal::sign_single_kind`] silently produces a
    /// root that a verifier rejects in exactly that case.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_single_kind_with_control_root<S: PayloadSigner + ?Sized>(
        realm_id: RealmId,
        predecessor_refs: Vec<SealId>,
        delta: Vec<Hash>,
        control_event_set_root: Hash,
        state_root: Hash,
        hlc: Hlc,
        _kind: crate::SealKind,
        digest_suite: arkret_canonical::DigestSuite,
        signer: &S,
    ) -> Result<Seal> {
        // Compute canonical body bytes (excluding id + notary_signature).
        let sealed_at = Utc::now();
        let previous_state_root = None;
        let previous_digest_algorithm = None;
        let completeness_root = control_event_set_root.clone();
        let notary_seq = 0;
        let data_view_root = None;
        let data_event_set_root = None;
        let availability_receipt_digests = Vec::new();
        let covered_event_digests = Vec::new();
        let body_bytes = canonical::canonical_json_bytes(&SealBodyView {
            realm_id: &realm_id,
            predecessor_refs: &predecessor_refs,
            delta: &delta,
            control_event_set_root: &control_event_set_root,
            state_root: &state_root,
            completeness_root: &completeness_root,
            notary_seq,
            data_view_root: &data_view_root,
            data_event_set_root: &data_event_set_root,
            availability_receipt_digests: &availability_receipt_digests,
            covered_event_digests: &covered_event_digests,
            previous_state_root: &previous_state_root,
            previous_digest_algorithm: &previous_digest_algorithm,
            sealed_at,
            hlc: &hlc,
        })?;
        let id = Seal::id_from_canonical_bytes(&body_bytes, digest_suite)?;
        let sig = seal_signature(signer.sign_payload_with_digest_suite(&body_bytes, digest_suite)?);
        Ok(Seal {
            id,
            realm_id,
            predecessor_refs,
            delta,
            control_event_set_root,
            state_root,
            completeness_root,
            notary_seq,
            data_view_root,
            data_event_set_root,
            availability_receipt_digests,
            covered_event_digests,
            previous_state_root,
            previous_digest_algorithm,
            notary_signature: NotarySig::Single(sig),
            sealed_at,
            hlc,
        })
    }

    /// Build + multi-sign a normal Seal. Delegates to
    /// [`Seal::sign_multi_kind`] with `kind=Normal`.
    pub fn sign_multi<S>(
        realm_id: RealmId,
        predecessor_refs: Vec<SealId>,
        delta: Vec<Hash>,
        state_root: Hash,
        hlc: Hlc,
        digest_suite: arkret_canonical::DigestSuite,
        signers: &[&S],
    ) -> Result<Seal>
    where
        S: PayloadSigner + ?Sized,
    {
        Self::sign_multi_kind(
            realm_id,
            predecessor_refs,
            delta,
            state_root,
            hlc,
            crate::SealKind::Normal,
            digest_suite,
            signers,
        )
    }

    /// Build + multi-sign a normal Seal with an explicit construction mode.
    /// Compaction Seals are rejected for the same reason as
    /// [`Seal::sign_single_kind`].
    #[allow(clippy::too_many_arguments)]
    pub fn sign_multi_kind<S>(
        realm_id: RealmId,
        predecessor_refs: Vec<SealId>,
        delta: Vec<Hash>,
        state_root: Hash,
        hlc: Hlc,
        kind: crate::SealKind,
        digest_suite: arkret_canonical::DigestSuite,
        signers: &[&S],
    ) -> Result<Seal>
    where
        S: PayloadSigner + ?Sized,
    {
        if kind.is_compaction() {
            return Err(WireError::Protocol(
                "compaction Seal requires an explicit covered_event_digests set".to_owned(),
            ));
        }
        if signers.is_empty() {
            return Err(WireError::Protocol(
                "Seal::sign_multi requires at least one signer".to_owned(),
            ));
        }
        let sealed_at = Utc::now();
        let previous_state_root = None;
        let previous_digest_algorithm = None;
        let control_event_set_root = delta_control_root(&delta, digest_suite)?;
        let completeness_root = control_event_set_root.clone();
        let notary_seq = 0;
        let data_view_root = None;
        let data_event_set_root = None;
        let availability_receipt_digests = Vec::new();
        let covered_event_digests = Vec::new();
        let body_bytes = canonical::canonical_json_bytes(&SealBodyView {
            realm_id: &realm_id,
            predecessor_refs: &predecessor_refs,
            delta: &delta,
            control_event_set_root: &control_event_set_root,
            state_root: &state_root,
            completeness_root: &completeness_root,
            notary_seq,
            data_view_root: &data_view_root,
            data_event_set_root: &data_event_set_root,
            availability_receipt_digests: &availability_receipt_digests,
            covered_event_digests: &covered_event_digests,
            previous_state_root: &previous_state_root,
            previous_digest_algorithm: &previous_digest_algorithm,
            sealed_at,
            hlc: &hlc,
        })?;
        let id = Seal::id_from_canonical_bytes(&body_bytes, digest_suite)?;
        let mut signatures = Vec::with_capacity(signers.len());
        for signer in signers {
            signatures.push(seal_signature(
                signer.sign_payload_with_digest_suite(&body_bytes, digest_suite)?,
            ));
        }
        signatures.sort_by(|left, right| left.verification_method.cmp(&right.verification_method));
        let seal = Seal {
            id,
            realm_id,
            predecessor_refs,
            delta,
            control_event_set_root,
            state_root,
            completeness_root,
            notary_seq,
            data_view_root,
            data_event_set_root,
            availability_receipt_digests,
            covered_event_digests,
            previous_state_root,
            previous_digest_algorithm,
            notary_signature: NotarySig::Multi(MultiSignature {
                kind: MultiSigKind::MultiSig,
                signatures,
            }),
            sealed_at,
            hlc,
        };
        seal.validate_structural()?;
        Ok(seal)
    }
}

fn delta_control_root(delta: &[Hash], digest_suite: arkret_canonical::DigestSuite) -> Result<Hash> {
    let covered: BTreeSet<Hash> = delta.iter().cloned().collect();
    let mut leaves: Vec<[u8; 32]> = covered
        .iter()
        .map(|event_digest| {
            let (suite, digest) = event_digest.as_str().split_once(':').ok_or_else(|| {
                WireError::Protocol("control-plane event_digest must carry a suite".to_owned())
            })?;
            canonical::digest_suite(suite)?;
            let mut bytes = [0_u8; 32];
            hex::decode_to_slice(digest, &mut bytes).map_err(|error| {
                WireError::Protocol(format!("invalid control-plane event_digest: {error}"))
            })?;
            Ok(bytes)
        })
        .collect::<Result<_>>()?;
    if leaves.is_empty() {
        return Hash::new(canonical::digest(digest_suite, [])).map_err(WireError::from);
    }
    for leaf in &mut leaves {
        *leaf = canonical::digest_bytes_from_slices(digest_suite, &[&[0x00], leaf]);
    }
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            if let Some(right) = pair.get(1) {
                next.push(canonical::digest_bytes_from_slices(
                    digest_suite,
                    &[&[0x01], &pair[0], right],
                ));
            } else {
                next.push(pair[0]);
            }
        }
        leaves = next;
    }
    Hash::new(format!(
        "{}:{}",
        digest_suite.as_str(),
        hex::encode(leaves[0])
    ))
    .map_err(WireError::from)
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
    pub signer_did: DidFullId,
    pub signature: Vec<u8>,
    pub kid: DidUrl,
}

impl PartialSignature {
    pub fn new(signer_did: DidFullId, signature: Vec<u8>, kid: DidUrl) -> Self {
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
/// into a multi-shape `NotarySig::Multi` whose individual members the
/// receiver re-checks against `signers`.
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
    pub fn aggregate<F>(&self, canonical_bytes: &[u8], verify: F) -> Result<MultiSignature>
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
        })
    }
}

/// Local clone of the Seal body view used for canonical-bytes derivation.
///
/// `core::seal::SealBody` is private to that module; we mirror it here
/// so the `sign_*` constructors don't need a public surface for the
/// hashing-only struct.
///
/// MAL-11 round 8: `kind` participates in the hashed bytes (forgery
/// defense — Normal vs Compaction seals with otherwise identical
/// fields MUST hash differently).
#[derive(serde::Serialize)]
struct SealBodyView<'a> {
    realm_id: &'a RealmId,
    predecessor_refs: &'a [SealId],
    delta: &'a [Hash],
    control_event_set_root: &'a Hash,
    state_root: &'a Hash,
    completeness_root: &'a Hash,
    notary_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_view_root: &'a Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_event_set_root: &'a Option<Hash>,
    availability_receipt_digests: &'a [Hash],
    #[serde(skip_serializing_if = "slice_is_empty")]
    covered_event_digests: &'a [Hash],
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_state_root: &'a Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_digest_algorithm: &'a Option<arkret_canonical::DigestSuite>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    sealed_at: chrono::DateTime<Utc>,
    hlc: &'a Hlc,
}

fn slice_is_empty(values: &&[Hash]) -> bool {
    values.is_empty()
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN".to_owned()).unwrap()
    }

    fn alice() -> DidFullId {
        DidFullId::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap()
    }

    fn alice_kid() -> DidUrl {
        DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap()
    }

    fn seal_id(byte: u8) -> SealId {
        SealId::new(format!(
            "ak:seal:sha256:{}",
            format!("{byte:02x}").repeat(32)
        ))
        .unwrap()
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn hlc() -> Hlc {
        Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap()
    }

    /// Deterministic test signer: produces a JWS that's just hex(payload_digest)
    /// so test vectors don't need real ed25519. Real signers live in
    /// `arkret-signatures::signer`.
    struct StubSigner {
        did: DidFullId,
        kid: DidUrl,
    }

    impl PayloadSigner for StubSigner {
        fn signer_did(&self) -> &DidFullId {
            &self.did
        }

        fn verification_method_id(&self) -> &DidUrl {
            &self.kid
        }

        fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<PayloadSignature> {
            let payload_digest = Hash::new(canonical::sha256_digest(canonical_bytes)).unwrap();
            Ok(PayloadSignature {
                verification_method: self.kid.clone(),
                payload_digest,
                created_at: Utc.with_ymd_and_hms(2026, 5, 9, 0, 0, 0).unwrap(),
                jws: "AAAA.BBBB.CCCC".to_owned(),
            })
        }
    }

    fn signer() -> StubSigner {
        StubSigner {
            did: alice(),
            kid: alice_kid(),
        }
    }

    #[test]
    fn seal_sign_single_validates_id_and_structural() {
        let s = signer();
        let a = Seal::sign_single(
            realm(),
            vec![seal_id(0xaa)],
            vec![hash(0x11)],
            hash(0x77),
            hlc(),
            arkret_canonical::DigestSuite::Sha256,
            &s,
        )
        .unwrap();
        a.validate_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        a.validate_structural().unwrap();
        match &a.notary_signature {
            NotarySig::Single(sig) => assert!(!sig.jws.is_empty()),
            other => panic!("expected single sig, got {other:?}"),
        }
    }

    #[test]
    fn seal_sign_multi_collects_one_sig_per_signer() {
        let alice = signer();
        let bob = StubSigner {
            did: DidFullId::new("did:webvh:z6mkfixture:bob.example".to_owned()).unwrap(),
            kid: bob_kid(),
        };
        let signers: &[&dyn PayloadSigner] = &[&alice, &bob];
        let a = Seal::sign_multi(
            realm(),
            vec![seal_id(0xaa)],
            vec![hash(0x11)],
            hash(0x77),
            hlc(),
            arkret_canonical::DigestSuite::Sha256,
            signers,
        )
        .unwrap();
        match &a.notary_signature {
            NotarySig::Multi(m) => assert_eq!(m.signatures.len(), 2),
            other => panic!("expected multi, got {other:?}"),
        }
    }

    #[test]
    fn seal_sign_multi_rejects_empty_signer_set() {
        let err = Seal::sign_multi::<dyn PayloadSigner>(
            realm(),
            vec![seal_id(0xaa)],
            vec![hash(0x11)],
            hash(0x77),
            hlc(),
            arkret_canonical::DigestSuite::Sha256,
            &[],
        )
        .unwrap_err();
        assert!(format!("{err}").contains("requires at least one signer"));
    }

    // -------------------------------------------------------------------
    // Threshold aggregator
    // -------------------------------------------------------------------

    fn bob() -> DidFullId {
        DidFullId::new("did:webvh:z6mkfixture:bob.example".to_owned()).unwrap()
    }

    fn bob_kid() -> DidUrl {
        DidUrl::new("did:webvh:z6mkfixture:bob.example#key-1").unwrap()
    }

    fn fixture_canonical_bytes() -> Vec<u8> {
        b"canonical-seal-body".to_vec()
    }

    #[test]
    fn threshold_aggregator_zero_threshold_rejected() {
        let err = ThresholdAggregator::new(0).unwrap_err();
        assert!(format!("{err}").contains("threshold must be at least 1"));
    }

    #[test]
    fn threshold_aggregator_collects_and_aggregates() {
        let mut agg = ThresholdAggregator::new(2).unwrap();
        agg.add_partial(PartialSignature::new(alice(), vec![1u8; 64], alice_kid()))
            .unwrap();
        assert!(!agg.threshold_met());
        agg.add_partial(PartialSignature::new(bob(), vec![2u8; 64], bob_kid()))
            .unwrap();
        assert!(agg.threshold_met());

        // Aggregate with a passing per-partial verifier.
        let multi = agg
            .aggregate(&fixture_canonical_bytes(), |_p, _bytes| Ok(()))
            .unwrap();
        assert_eq!(multi.signatures.len(), 2);
        assert_eq!(multi.kind, MultiSigKind::MultiSig);
        // Each signature carries the canonical-bytes payload hash.
        let expected = canonical::sha256_digest(fixture_canonical_bytes());
        for sig in &multi.signatures {
            assert_eq!(sig.payload_digest.as_str(), expected);
        }
    }

    #[test]
    fn threshold_aggregator_rejects_duplicate_signer() {
        let mut agg = ThresholdAggregator::new(2).unwrap();
        agg.add_partial(PartialSignature::new(alice(), vec![1u8; 64], alice_kid()))
            .unwrap();
        let err = agg
            .add_partial(PartialSignature::new(alice(), vec![3u8; 64], alice_kid()))
            .unwrap_err();
        assert!(format!("{err}").contains("duplicate partial"));
    }

    #[test]
    fn threshold_aggregator_aggregate_below_threshold_errors() {
        let mut agg = ThresholdAggregator::new(3).unwrap();
        agg.add_partial(PartialSignature::new(alice(), vec![1u8; 64], alice_kid()))
            .unwrap();
        let err = agg
            .aggregate(&fixture_canonical_bytes(), |_p, _bytes| Ok(()))
            .unwrap_err();
        assert!(format!("{err}").contains("threshold not met"));
    }

    #[test]
    fn threshold_aggregator_individual_verification_failure_propagates() {
        let mut agg = ThresholdAggregator::new(2).unwrap();
        agg.add_partial(PartialSignature::new(alice(), vec![1u8; 64], alice_kid()))
            .unwrap();
        agg.add_partial(PartialSignature::new(bob(), vec![2u8; 64], bob_kid()))
            .unwrap();
        let err = agg
            .aggregate(&fixture_canonical_bytes(), |_p, _bytes| {
                Err(WireError::Protocol("bad partial".to_owned()))
            })
            .unwrap_err();
        assert!(format!("{err}").contains("bad partial"));
    }

    #[test]
    fn partial_signature_rejects_empty_signature() {
        let mut agg = ThresholdAggregator::new(1).unwrap();
        let err = agg
            .add_partial(PartialSignature::new(alice(), vec![], alice_kid()))
            .unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    /// `PartialSignature.kid` is a `DidUrl`, so an empty or non-DID-URL
    /// verification method id cannot be constructed at all. The runtime
    /// emptiness check the aggregator used to run was removed with the
    /// migration; this pins the type-level replacement.
    #[test]
    fn partial_signature_kid_cannot_be_empty_or_bare() {
        assert!(DidUrl::new("").is_err());
        assert!(DidUrl::new("kid-1").is_err());
        assert!(DidUrl::new("did:webvh:z6mkfixture:alice.example").is_err());
        assert!(DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").is_ok());
    }
}
