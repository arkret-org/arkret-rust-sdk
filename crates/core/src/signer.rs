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
            "cx:move:sha256:0000000000000000000000000000000000000000000000000000000000000000",
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
    /// Build + single-sign an Anchor over the given frontier and predecessor
    /// references. Panics-free: returns Err if the supplied state_root is
    /// malformed or the signer DID isn't accepted by the wire-shape.
    pub fn sign_single<S: MoveSigner + ?Sized>(
        space_id: SpaceId,
        predecessor_refs: Vec<AnchorId>,
        frontier: Vec<MoveId>,
        state_root: Hash,
        hlc: Hlc,
        signer: &S,
    ) -> Result<Anchor> {
        // Compute canonical body bytes (excluding id + anchorer_sig).
        let body_bytes = canonical::canonical_json_bytes(&AnchorBodyView {
            space_id: &space_id,
            predecessor_refs: &predecessor_refs,
            frontier: &frontier,
            state_root: &state_root,
            hlc: &hlc,
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
        })
    }

    /// Build + threshold-sign an Anchor. The supplied `signers` slice is the
    /// set of signers contributing partial signatures; `threshold` is the
    /// `k` value for a `k`-of-`n` scheme. The aggregated `proof` bytes are
    /// supplied by the caller (they come from the threshold scheme's
    /// aggregator, not from individual `MoveSigner`s).
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
        let body_bytes = canonical::canonical_json_bytes(&AnchorBodyView {
            space_id: &space_id,
            predecessor_refs: &predecessor_refs,
            frontier: &frontier,
            state_root: &state_root,
            hlc: &hlc,
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
        };
        anchor.validate_structural()?;
        Ok(anchor)
    }

    /// Build + multi-sign an Anchor. Every supplied [`MoveSigner`] produces
    /// one signature over the same canonical bytes; the receiver enforces
    /// the all-of-set policy.
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
        };
        anchor.validate_structural()?;
        Ok(anchor)
    }
}

/// Local clone of the AnchorBody view used for canonical-bytes derivation.
///
/// `core::anchor::AnchorBody` is private to that module; we mirror it here
/// so the `sign_*` constructors don't need a public surface for the
/// hashing-only struct.
#[derive(serde::Serialize)]
struct AnchorBodyView<'a> {
    space_id: &'a SpaceId,
    predecessor_refs: &'a [AnchorId],
    frontier: &'a [MoveId],
    state_root: &'a Hash,
    hlc: &'a Hlc,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::move_event::{LatticeOp, LatticeOpType};
    use crate::CellRef;
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
        MoveId::new(format!("cx:move:sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
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
}
