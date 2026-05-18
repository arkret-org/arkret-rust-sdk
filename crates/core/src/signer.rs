//! Move / Anchor signer trait + builder helpers.
//!
//! Round 21 (2026-05-09): the protocol's content-addressed Move/Anchor objects
//! must be signed at the issuer / anchorer boundary. The SDK exposes a tiny
//! signer trait so downstream code (coauth `anchor_pending_move`, soland
//! anchor reconfig + bottom repair, yougen real-key signing) can plug
//! production keys in without re-implementing canonical bytes / id / payload
//! hash plumbing.
//!
//! The trait deliberately stays in `contrix-core` (no crypto deps): an
//! Ed25519 implementation lives in `contrix-signatures` behind the `signer`
//! feature, and other backends (HSM, threshold scheme) can layer on the
//! same trait.

use chrono::Utc;

use crate::canonical;
use crate::move_event::{Effect, Move, MoveSignature, Precondition, SemanticRef};
use crate::{
    Anchor, AnchorId, AnchorerSig, Did, Error, Hash, Hlc, MoveId, MultiSigKind, MultiSignature,
    Result, SpaceId, ThresholdSigKind, ThresholdSignature,
};

/// Builder view of a Move that has not yet been hashed / signed.
///
/// Constructed via `UnsignedMove::new(...)`; `sign(signer)` (or `MoveSigner::sign_move`)
/// turns it into a fully-signed [`Move`] whose `id` is the canonical-bytes
/// hash and whose `sig.payload_hash` matches the same canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedMove {
    pub issuer: Did,
    pub space_id: SpaceId,
    pub preconditions: Vec<Precondition>,
    pub effects: Vec<Effect>,
    pub anchor_ref: AnchorId,
    pub refs: Vec<SemanticRef>,
    pub hlc: Hlc,
}

impl UnsignedMove {
    pub fn new(
        issuer: Did,
        space_id: SpaceId,
        anchor_ref: AnchorId,
        effects: Vec<Effect>,
        hlc: Hlc,
    ) -> Self {
        Self {
            issuer,
            space_id,
            preconditions: Vec::new(),
            effects,
            anchor_ref,
            refs: Vec::new(),
            hlc,
        }
    }

    pub fn with_preconditions(mut self, preconditions: Vec<Precondition>) -> Self {
        self.preconditions = preconditions;
        self
    }

    pub fn with_refs(mut self, refs: Vec<SemanticRef>) -> Self {
        self.refs = refs;
        self
    }

    /// Compute canonical bytes for this unsigned body (exactly the bytes
    /// the issuer signs, exactly the bytes whose sha256 becomes `Move.id`).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        // Build a placeholder `Move` with empty sig, then re-use
        // `Move::canonical_bytes_for_id` (which excludes both id and sig).
        // The id and sig fields are not part of the canonical bytes so any
        // value will do.
        let placeholder = self.placeholder_move()?;
        placeholder.canonical_bytes_for_id()
    }

    fn placeholder_move(&self) -> Result<Move> {
        let placeholder_id = MoveId::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .map_err(|err| Error::Protocol(format!("placeholder move id invalid: {err}")))?;
        let placeholder_sig = MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: String::new(),
            payload_hash: Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .map_err(|err| Error::Protocol(format!("placeholder hash invalid: {err}")))?,
            created_at: Utc::now(),
            jws: String::new(),
        };
        Ok(Move {
            id: placeholder_id,
            issuer: self.issuer.clone(),
            space_id: self.space_id.clone(),
            preconditions: self.preconditions.clone(),
            effects: self.effects.clone(),
            anchor_ref: self.anchor_ref.clone(),
            refs: self.refs.clone(),
            hlc: self.hlc.clone(),
            sig: placeholder_sig,
        })
    }
}

/// Trait implemented by Move/Anchor signers (Ed25519 keypair, HSM, threshold
/// scheme, etc.).
///
/// `sign_move` MUST:
/// 1. Compute canonical bytes via `unsigned.canonical_bytes()`.
/// 2. Produce a JWS over those bytes using the signer's keypair.
/// 3. Return a [`Move`] whose `id` = `derive_id` of the canonical bytes
///    and whose `sig.payload_hash` = sha256 of the canonical bytes.
pub trait MoveSigner {
    /// Sign an unsigned Move and return the fully-formed wire object.
    fn sign_move(&self, unsigned: &UnsignedMove) -> Result<Move>;

    /// DID of the signing identity. MUST match `unsigned.issuer` when used
    /// to sign Moves; for Anchors this is one of the anchorer-set members.
    fn signer_did(&self) -> &Did;

    /// The verification method id (e.g. `did:web:alice.example#key-1`)
    /// the signer will publish as `MoveSignature.verification_method`.
    fn verification_method_id(&self) -> &str;

    /// Sign arbitrary canonical bytes with the signer's key, producing a
    /// detached JWS string. Implementations of `sign_move` typically use
    /// this internally; helpers like [`Anchor::sign_single`] also reuse
    /// it for the Anchor body.
    fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<MoveSignature>;
}

impl Move {
    /// Sign an unsigned Move via the supplied signer.
    pub fn sign<S: MoveSigner + ?Sized>(unsigned: &UnsignedMove, signer: &S) -> Result<Move> {
        if unsigned.issuer != *signer.signer_did() {
            return Err(Error::Protocol(format!(
                "Move issuer {} does not match signer DID {}",
                unsigned.issuer,
                signer.signer_did()
            )));
        }
        signer.sign_move(unsigned)
    }
}

impl Anchor {
    /// Build + single-sign a normal Anchor (frontier-advance). Delegates to
    /// [`Anchor::sign_single_kind`] with `kind=Normal`.
    pub fn sign_single<S: MoveSigner + ?Sized>(
        space_id: SpaceId,
        predecessor_refs: Vec<AnchorId>,
        frontier: Vec<MoveId>,
        state_root: Hash,
        hlc: Hlc,
        signer: &S,
    ) -> Result<Anchor> {
        Self::sign_single_kind(
            space_id,
            predecessor_refs,
            frontier,
            state_root,
            hlc,
            crate::AnchorKind::Normal,
            signer,
        )
    }

    /// MAL-11: build + single-sign an Anchor with an explicit
    /// [`crate::AnchorKind`]. Use `Normal` for frontier-advance anchors and
    /// `Compaction` for checkpoint anchors that re-state the existing
    /// frontier without accepting new moves.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_single_kind<S: MoveSigner + ?Sized>(
        space_id: SpaceId,
        predecessor_refs: Vec<AnchorId>,
        frontier: Vec<MoveId>,
        state_root: Hash,
        hlc: Hlc,
        kind: crate::AnchorKind,
        signer: &S,
    ) -> Result<Anchor> {
        // Compute canonical body bytes (excluding id + anchorer_sig).
        let body_bytes = canonical::canonical_json_bytes(&AnchorBodyView {
            space_id: &space_id,
            predecessor_refs: &predecessor_refs,
            frontier: &frontier,
            state_root: &state_root,
            hlc: &hlc,
            kind: &kind,
        })?;
        let id = Anchor::id_from_canonical_bytes(&body_bytes)?;
        let sig = signer.sign_payload(&body_bytes)?;
        Ok(Anchor {
            id,
            space_id,
            predecessor_refs,
            frontier,
            state_root,
            anchorer_sig: AnchorerSig::Single(sig),
            hlc,
            kind,
        })
    }

    /// Build + threshold-sign a normal Anchor. Delegates to
    /// [`Anchor::sign_threshold_kind`] with `kind=Normal`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_threshold(
        space_id: SpaceId,
        predecessor_refs: Vec<AnchorId>,
        frontier: Vec<MoveId>,
        state_root: Hash,
        hlc: Hlc,
        threshold: u32,
        signers: Vec<Did>,
        aggregated_proof: String,
    ) -> Result<Anchor> {
        Self::sign_threshold_kind(
            space_id,
            predecessor_refs,
            frontier,
            state_root,
            hlc,
            crate::AnchorKind::Normal,
            threshold,
            signers,
            aggregated_proof,
        )
    }

    /// MAL-11: build + threshold-sign an Anchor with an explicit
    /// [`crate::AnchorKind`]. See [`Anchor::sign_single_kind`] for the
    /// kind semantics.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_threshold_kind(
        space_id: SpaceId,
        predecessor_refs: Vec<AnchorId>,
        frontier: Vec<MoveId>,
        state_root: Hash,
        hlc: Hlc,
        kind: crate::AnchorKind,
        threshold: u32,
        signers: Vec<Did>,
        aggregated_proof: String,
    ) -> Result<Anchor> {
        let body_bytes = canonical::canonical_json_bytes(&AnchorBodyView {
            space_id: &space_id,
            predecessor_refs: &predecessor_refs,
            frontier: &frontier,
            state_root: &state_root,
            hlc: &hlc,
            kind: &kind,
        })?;
        let id = Anchor::id_from_canonical_bytes(&body_bytes)?;
        let sig = AnchorerSig::Threshold(ThresholdSignature {
            kind: ThresholdSigKind::ThresholdSig,
            threshold,
            signers,
            proof: aggregated_proof,
        });
        let anchor = Anchor {
            id,
            space_id,
            predecessor_refs,
            frontier,
            state_root,
            anchorer_sig: sig,
            hlc,
            kind,
        };
        anchor.validate_structural()?;
        Ok(anchor)
    }

    /// Build + multi-sign a normal Anchor. Delegates to
    /// [`Anchor::sign_multi_kind`] with `kind=Normal`.
    pub fn sign_multi<S>(
        space_id: SpaceId,
        predecessor_refs: Vec<AnchorId>,
        frontier: Vec<MoveId>,
        state_root: Hash,
        hlc: Hlc,
        signers: &[&S],
    ) -> Result<Anchor>
    where
        S: MoveSigner + ?Sized,
    {
        Self::sign_multi_kind(
            space_id,
            predecessor_refs,
            frontier,
            state_root,
            hlc,
            crate::AnchorKind::Normal,
            signers,
        )
    }

    /// MAL-11: build + multi-sign an Anchor with an explicit
    /// [`crate::AnchorKind`]. See [`Anchor::sign_single_kind`] for the
    /// kind semantics.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_multi_kind<S>(
        space_id: SpaceId,
        predecessor_refs: Vec<AnchorId>,
        frontier: Vec<MoveId>,
        state_root: Hash,
        hlc: Hlc,
        kind: crate::AnchorKind,
        signers: &[&S],
    ) -> Result<Anchor>
    where
        S: MoveSigner + ?Sized,
    {
        if signers.is_empty() {
            return Err(Error::Protocol(
                "Anchor::sign_multi requires at least one signer".to_owned(),
            ));
        }
        let body_bytes = canonical::canonical_json_bytes(&AnchorBodyView {
            space_id: &space_id,
            predecessor_refs: &predecessor_refs,
            frontier: &frontier,
            state_root: &state_root,
            hlc: &hlc,
            kind: &kind,
        })?;
        let id = Anchor::id_from_canonical_bytes(&body_bytes)?;
        let mut signatures = Vec::with_capacity(signers.len());
        for signer in signers {
            signatures.push(signer.sign_payload(&body_bytes)?);
        }
        let anchor = Anchor {
            id,
            space_id,
            predecessor_refs,
            frontier,
            state_root,
            anchorer_sig: AnchorerSig::Multi(MultiSignature {
                kind: MultiSigKind::MultiSig,
                signatures,
            }),
            hlc,
            kind,
        };
        anchor.validate_structural()?;
        Ok(anchor)
    }
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
    pub kid: String,
}

impl PartialSignature {
    pub fn new(signer_did: Did, signature: Vec<u8>, kid: impl Into<String>) -> Self {
        Self { signer_did, signature, kid: kid.into() }
    }
}

/// Threshold partial-signature collector.
///
/// Collects [`PartialSignature`]s contributed by `n` signers and produces an
/// aggregated [`MultiSignature`] (or an opaque proof string suitable for
/// [`AnchorerSig::Threshold`]) once the threshold `k` is met.
///
/// This struct is scheme-agnostic: it does NOT know how to combine partials
/// (BLS / FROST / Schnorr-musig all differ). Callers MUST supply a
/// per-partial verifier via [`Self::add_partial_verified`] or call
/// [`Self::add_partial`] only after externally verifying the partial. The
/// final [`Self::aggregate`] step concatenates the per-partial signatures
/// into a multi-shape `AnchorerSig::Multi` whose individual members the
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
            return Err(Error::Protocol(
                "ThresholdAggregator threshold must be at least 1".to_owned(),
            ));
        }
        Ok(Self { threshold, partials: Vec::new() })
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
        if self.partials.iter().any(|p| p.signer_did == partial.signer_did) {
            return Err(Error::Protocol(format!(
                "duplicate partial from signer {}",
                partial.signer_did
            )));
        }
        if partial.signature.is_empty() {
            return Err(Error::Protocol(format!(
                "partial signature from {} is empty",
                partial.signer_did
            )));
        }
        if partial.kid.is_empty() {
            return Err(Error::Protocol(format!(
                "partial signature from {} has empty verification method id",
                partial.signer_did
            )));
        }
        self.partials.push(partial);
        Ok(())
    }

    /// Append a partial after running `verify` on it. `verify` MUST return
    /// `Ok(())` if the partial signature is individually valid against the
    /// signer's published key for the canonical bytes the threshold body
    /// commits to.
    pub fn add_partial_verified<F>(&mut self, partial: PartialSignature, verify: F) -> Result<()>
    where
        F: FnOnce(&PartialSignature) -> Result<()>,
    {
        verify(&partial)?;
        self.add_partial(partial)
    }

    /// Produce an aggregated [`MultiSignature`] from the collected partials.
    ///
    /// Validates the threshold is met and that each partial individually
    /// verifies via the supplied `verify` closure (one call per partial).
    /// Returns an error if any individual verification fails or threshold
    /// not met.
    ///
    /// The resulting [`MultiSignature`] has one [`MoveSignature`] per
    /// partial, with `payload_hash` = the supplied canonical-bytes hash and
    /// `jws` = the partial's raw signature base64-encoded so the wire shape
    /// is uniform regardless of the underlying scheme.
    pub fn aggregate<F>(&self, canonical_bytes: &[u8], verify: F) -> Result<MultiSignature>
    where
        F: Fn(&PartialSignature, &[u8]) -> Result<()>,
    {
        if !self.threshold_met() {
            return Err(Error::Protocol(format!(
                "threshold not met: have {} partials, need {}",
                self.partials.len(),
                self.threshold
            )));
        }
        let payload_hash = Hash::new(canonical::sha256_digest(canonical_bytes))
            .map_err(|err| Error::Protocol(format!("invalid canonical hash: {err}")))?;
        let mut signatures = Vec::with_capacity(self.partials.len());
        for partial in &self.partials {
            verify(partial, canonical_bytes)?;
            // Encode the raw signature bytes via base64url-no-pad so the
            // wire shape stays uniform; receivers re-decode and re-verify
            // via the same scheme verifier.
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let encoded_sig = URL_SAFE_NO_PAD.encode(&partial.signature);
            signatures.push(MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: partial.kid.clone(),
                payload_hash: payload_hash.clone(),
                created_at: Utc::now(),
                jws: format!("..{encoded_sig}"),
            });
        }
        Ok(MultiSignature { kind: MultiSigKind::MultiSig, signatures })
    }

    /// Concatenate all partial signatures into a single proof string for
    /// schemes whose aggregator output is the simple concatenation of
    /// partials (or for tests that don't run a real threshold scheme).
    ///
    /// Returns base64url-no-pad of the concatenation, after checking that
    /// the threshold is met. Each partial is encoded as
    /// `<did>:<base64url-no-pad(sig)>` joined by `\n` then base64-encoded
    /// once more to keep the proof a single opaque string.
    pub fn aggregate_proof(&self) -> Result<String> {
        if !self.threshold_met() {
            return Err(Error::Protocol(format!(
                "threshold not met: have {} partials, need {}",
                self.partials.len(),
                self.threshold
            )));
        }
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let lines: Vec<String> = self
            .partials
            .iter()
            .map(|p| format!("{}:{}", p.signer_did, URL_SAFE_NO_PAD.encode(&p.signature)))
            .collect();
        Ok(URL_SAFE_NO_PAD.encode(lines.join("\n").as_bytes()))
    }

    pub fn signers(&self) -> Vec<Did> {
        self.partials.iter().map(|p| p.signer_did.clone()).collect()
    }
}

impl Anchor {
    /// Construct + threshold-sign an Anchor from already-collected partials.
    ///
    /// Calls [`ThresholdAggregator::aggregate_proof`] to derive the opaque
    /// `proof` string for [`AnchorerSig::Threshold`], then runs
    /// `validate_structural` (k ≤ n, unique signers, etc.).
    ///
    /// The partial signatures MUST have been individually verified before
    /// being added to the aggregator (call
    /// [`ThresholdAggregator::add_partial_verified`]). This constructor
    /// performs no further per-partial verification.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_threshold_partial(
        space_id: SpaceId,
        predecessor_refs: Vec<AnchorId>,
        frontier: Vec<MoveId>,
        state_root: Hash,
        hlc: Hlc,
        aggregator: &ThresholdAggregator,
    ) -> Result<Anchor> {
        let proof = aggregator.aggregate_proof()?;
        let signers = aggregator.signers();
        Anchor::sign_threshold(
            space_id,
            predecessor_refs,
            frontier,
            state_root,
            hlc,
            aggregator.threshold() as u32,
            signers,
            proof,
        )
    }
}

/// Local clone of the AnchorBody view used for canonical-bytes derivation.
///
/// `core::anchor::AnchorBody` is private to that module; we mirror it here
/// so the `sign_*` constructors don't need a public surface for the
/// hashing-only struct.
///
/// MAL-11 round 8: `kind` is included with the same `skip_serializing_if`
/// rule as `core::anchor::AnchorBody` — `Normal` is dropped from the wire
/// so pre-MAL-11 envelopes remain byte-identical, and `Compaction`
/// participates in the hashed bytes (forgery defense).
#[derive(serde::Serialize)]
struct AnchorBodyView<'a> {
    space_id: &'a SpaceId,
    predecessor_refs: &'a [AnchorId],
    frontier: &'a [MoveId],
    state_root: &'a Hash,
    hlc: &'a Hlc,
    #[serde(skip_serializing_if = "anchor_kind_is_default")]
    kind: &'a crate::AnchorKind,
}

fn anchor_kind_is_default(kind: &&crate::AnchorKind) -> bool {
    matches!(**kind, crate::AnchorKind::Normal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CellRef;
    use crate::move_event::{LatticeOp, LatticeOpType};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    fn space() -> SpaceId {
        SpaceId::new("cx:space:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn alice() -> Did {
        Did::new("did:web:alice.example".to_owned()).unwrap()
    }

    fn anchor_id(byte: u8) -> AnchorId {
        AnchorId::new(format!("cx:anchor:sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn move_id(byte: u8) -> MoveId {
        MoveId::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn hlc() -> Hlc {
        Hlc::new("0189c4d2af00-00000000-aabbccdd".to_owned()).unwrap()
    }

    /// Deterministic test signer: produces a JWS that's just hex(payload_hash)
    /// so test vectors don't need real ed25519. Real signers live in
    /// `contrix-signatures::signer`.
    struct StubSigner {
        did: Did,
        kid: String,
    }

    impl MoveSigner for StubSigner {
        fn sign_move(&self, unsigned: &UnsignedMove) -> Result<Move> {
            let bytes = unsigned.canonical_bytes()?;
            let id = Move::id_from_canonical_bytes(&bytes)?;
            let sig = self.sign_payload(&bytes)?;
            Ok(Move {
                id,
                issuer: unsigned.issuer.clone(),
                space_id: unsigned.space_id.clone(),
                preconditions: unsigned.preconditions.clone(),
                effects: unsigned.effects.clone(),
                anchor_ref: unsigned.anchor_ref.clone(),
                refs: unsigned.refs.clone(),
                hlc: unsigned.hlc.clone(),
                sig,
            })
        }

        fn signer_did(&self) -> &Did {
            &self.did
        }

        fn verification_method_id(&self) -> &str {
            &self.kid
        }

        fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<MoveSignature> {
            let payload_hash = Hash::new(canonical::sha256_digest(canonical_bytes)).unwrap();
            Ok(MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: self.kid.clone(),
                payload_hash,
                created_at: Utc.with_ymd_and_hms(2026, 5, 9, 0, 0, 0).unwrap(),
                jws: "AAAA.BBBB.CCCC".to_owned(),
            })
        }
    }

    fn signer() -> StubSigner {
        StubSigner { did: alice(), kid: "did:web:alice.example#key-1".to_owned() }
    }

    fn unsigned_move() -> UnsignedMove {
        UnsignedMove::new(
            alice(),
            space(),
            anchor_id(0xaa),
            vec![Effect {
                cell: CellRef::new(
                    "cx:cell:cx.component.member.state.v1:did.web.alice.example".to_owned(),
                )
                .unwrap(),
                op: LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(json!("active")),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            }],
            hlc(),
        )
    }

    #[test]
    fn move_sign_round_trip_validates_id_and_payload_hash() {
        let s = signer();
        let m = Move::sign(&unsigned_move(), &s).unwrap();
        m.validate_id().unwrap();
        m.validate_structural().unwrap();
        assert_eq!(m.issuer, alice());
        assert_eq!(m.sig.verification_method, "did:web:alice.example#key-1");
    }

    #[test]
    fn move_sign_rejects_issuer_mismatch() {
        let other = StubSigner {
            did: Did::new("did:web:bob.example".to_owned()).unwrap(),
            kid: "did:web:bob.example#key-1".to_owned(),
        };
        let err = Move::sign(&unsigned_move(), &other).unwrap_err();
        assert!(format!("{err}").contains("does not match signer DID"));
    }

    #[test]
    fn anchor_sign_single_validates_id_and_structural() {
        let s = signer();
        let a = Anchor::sign_single(
            space(),
            vec![anchor_id(0xaa)],
            vec![move_id(0x11)],
            hash(0x77),
            hlc(),
            &s,
        )
        .unwrap();
        a.validate_id().unwrap();
        a.validate_structural().unwrap();
        match &a.anchorer_sig {
            AnchorerSig::Single(sig) => assert_eq!(sig.alg, "EdDSA"),
            other => panic!("expected single sig, got {other:?}"),
        }
    }

    #[test]
    fn anchor_sign_threshold_round_trip() {
        let a = Anchor::sign_threshold(
            space(),
            vec![anchor_id(0xaa)],
            vec![move_id(0x11)],
            hash(0x77),
            hlc(),
            2,
            vec![alice(), Did::new("did:web:bob.example".to_owned()).unwrap()],
            "BLS_AGG".to_owned(),
        )
        .unwrap();
        a.validate_id().unwrap();
        a.validate_structural().unwrap();
        match &a.anchorer_sig {
            AnchorerSig::Threshold(t) => {
                assert_eq!(t.threshold, 2);
                assert_eq!(t.signers.len(), 2);
                assert_eq!(t.proof, "BLS_AGG");
            }
            other => panic!("expected threshold, got {other:?}"),
        }
    }

    #[test]
    fn anchor_sign_threshold_rejects_threshold_above_signer_count() {
        let err = Anchor::sign_threshold(
            space(),
            vec![anchor_id(0xaa)],
            vec![move_id(0x11)],
            hash(0x77),
            hlc(),
            5,
            vec![alice()],
            "p".to_owned(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("exceeds signer count"));
    }

    #[test]
    fn anchor_sign_multi_collects_one_sig_per_signer() {
        let alice = signer();
        let bob = StubSigner {
            did: Did::new("did:web:bob.example".to_owned()).unwrap(),
            kid: "did:web:bob.example#key-1".to_owned(),
        };
        let signers: &[&dyn MoveSigner] = &[&alice, &bob];
        let a = Anchor::sign_multi(
            space(),
            vec![anchor_id(0xaa)],
            vec![move_id(0x11)],
            hash(0x77),
            hlc(),
            signers,
        )
        .unwrap();
        match &a.anchorer_sig {
            AnchorerSig::Multi(m) => assert_eq!(m.signatures.len(), 2),
            other => panic!("expected multi, got {other:?}"),
        }
    }

    #[test]
    fn anchor_sign_multi_rejects_empty_signer_set() {
        let err = Anchor::sign_multi::<dyn MoveSigner>(
            space(),
            vec![anchor_id(0xaa)],
            vec![move_id(0x11)],
            hash(0x77),
            hlc(),
            &[],
        )
        .unwrap_err();
        assert!(format!("{err}").contains("requires at least one signer"));
    }

    #[test]
    fn unsigned_move_canonical_bytes_match_signed_move_canonical_bytes() {
        let s = signer();
        let u = unsigned_move();
        let unsigned_bytes = u.canonical_bytes().unwrap();
        let m = Move::sign(&u, &s).unwrap();
        let signed_bytes = m.canonical_bytes_for_id().unwrap();
        assert_eq!(unsigned_bytes, signed_bytes);
    }

    // -------------------------------------------------------------------
    // Threshold aggregator
    // -------------------------------------------------------------------

    fn bob() -> Did {
        Did::new("did:web:bob.example".to_owned()).unwrap()
    }

    fn carol() -> Did {
        Did::new("did:web:carol.example".to_owned()).unwrap()
    }

    fn fixture_canonical_bytes() -> Vec<u8> {
        b"canonical-anchor-body".to_vec()
    }

    #[test]
    fn threshold_aggregator_zero_threshold_rejected() {
        let err = ThresholdAggregator::new(0).unwrap_err();
        assert!(format!("{err}").contains("threshold must be at least 1"));
    }

    #[test]
    fn threshold_aggregator_collects_and_aggregates() {
        let mut agg = ThresholdAggregator::new(2).unwrap();
        agg.add_partial(PartialSignature::new(
            alice(),
            vec![1u8; 64],
            "did:web:alice.example#key-1",
        ))
        .unwrap();
        assert!(!agg.threshold_met());
        agg.add_partial(PartialSignature::new(bob(), vec![2u8; 64], "did:web:bob.example#key-1"))
            .unwrap();
        assert!(agg.threshold_met());

        // Aggregate with a passing per-partial verifier.
        let multi = agg.aggregate(&fixture_canonical_bytes(), |_p, _bytes| Ok(())).unwrap();
        assert_eq!(multi.signatures.len(), 2);
        assert_eq!(multi.kind, MultiSigKind::MultiSig);
        // Each signature carries the canonical-bytes payload hash.
        let expected = canonical::sha256_digest(fixture_canonical_bytes());
        for sig in &multi.signatures {
            assert_eq!(sig.payload_hash.as_str(), expected);
        }
    }

    #[test]
    fn threshold_aggregator_rejects_duplicate_signer() {
        let mut agg = ThresholdAggregator::new(2).unwrap();
        agg.add_partial(PartialSignature::new(alice(), vec![1u8; 64], "kid-1")).unwrap();
        let err =
            agg.add_partial(PartialSignature::new(alice(), vec![3u8; 64], "kid-1")).unwrap_err();
        assert!(format!("{err}").contains("duplicate partial"));
    }

    #[test]
    fn threshold_aggregator_aggregate_below_threshold_errors() {
        let mut agg = ThresholdAggregator::new(3).unwrap();
        agg.add_partial(PartialSignature::new(alice(), vec![1u8; 64], "kid-1")).unwrap();
        let err = agg.aggregate(&fixture_canonical_bytes(), |_p, _bytes| Ok(())).unwrap_err();
        assert!(format!("{err}").contains("threshold not met"));
    }

    #[test]
    fn threshold_aggregator_individual_verification_failure_propagates() {
        let mut agg = ThresholdAggregator::new(2).unwrap();
        agg.add_partial(PartialSignature::new(alice(), vec![1u8; 64], "kid-1")).unwrap();
        agg.add_partial(PartialSignature::new(bob(), vec![2u8; 64], "kid-2")).unwrap();
        let err = agg
            .aggregate(&fixture_canonical_bytes(), |_p, _bytes| {
                Err(Error::Protocol("bad partial".to_owned()))
            })
            .unwrap_err();
        assert!(format!("{err}").contains("bad partial"));
    }

    #[test]
    fn threshold_aggregator_add_partial_verified_runs_check() {
        let mut agg = ThresholdAggregator::new(1).unwrap();
        let err = agg
            .add_partial_verified(PartialSignature::new(alice(), vec![1u8; 64], "kid-1"), |_p| {
                Err(Error::Protocol("scheme verifier said no".to_owned()))
            })
            .unwrap_err();
        assert!(format!("{err}").contains("scheme verifier said no"));
        assert_eq!(agg.collected(), 0);
    }

    #[test]
    fn anchor_sign_threshold_partial_round_trip() {
        let mut agg = ThresholdAggregator::new(2).unwrap();
        agg.add_partial(PartialSignature::new(
            alice(),
            vec![1u8; 64],
            "did:web:alice.example#key-1",
        ))
        .unwrap();
        agg.add_partial(PartialSignature::new(bob(), vec![2u8; 64], "did:web:bob.example#key-1"))
            .unwrap();

        let a = Anchor::sign_threshold_partial(
            space(),
            vec![anchor_id(0xaa)],
            vec![move_id(0x11)],
            hash(0x77),
            hlc(),
            &agg,
        )
        .unwrap();

        a.validate_id().unwrap();
        a.validate_structural().unwrap();
        match &a.anchorer_sig {
            AnchorerSig::Threshold(t) => {
                assert_eq!(t.threshold, 2);
                assert_eq!(t.signers.len(), 2);
                assert!(!t.proof.is_empty());
            }
            other => panic!("expected threshold, got {other:?}"),
        }
    }

    #[test]
    fn anchor_sign_threshold_partial_below_threshold_errors() {
        let mut agg = ThresholdAggregator::new(3).unwrap();
        agg.add_partial(PartialSignature::new(alice(), vec![1u8; 64], "kid-1")).unwrap();
        agg.add_partial(PartialSignature::new(bob(), vec![2u8; 64], "kid-2")).unwrap();
        let err = Anchor::sign_threshold_partial(
            space(),
            vec![anchor_id(0xaa)],
            vec![move_id(0x11)],
            hash(0x77),
            hlc(),
            &agg,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("threshold not met"));
    }

    #[test]
    fn partial_signature_rejects_empty_signature_or_kid() {
        let mut agg = ThresholdAggregator::new(1).unwrap();
        let err = agg.add_partial(PartialSignature::new(alice(), vec![], "kid")).unwrap_err();
        assert!(format!("{err}").contains("empty"));
        let err = agg.add_partial(PartialSignature::new(carol(), vec![5u8; 64], "")).unwrap_err();
        assert!(format!("{err}").contains("empty verification method id"));
    }
}
