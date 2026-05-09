//! Contrix Anchor typed model.
//!
//! Per spec `event-auth-state-resolution.md` §4 and schema `anchor.schema.json`.
//! An Anchor is the ordering-authority's persistent commitment to a set of
//! Move frontier ids: it does NOT modify cells; cell changes only come
//! from Move effects whose ids are in `frontier`. The anchorer signs the
//! commitment in one of three forms:
//!
//! - **Single** — single DID anchorer (typical for principal control Spaces).
//! - **Multi** — explicit multi-sig (every listed signer must sign).
//! - **Threshold** — `k`-of-`n` threshold; the `proof` field carries the
//!   threshold-scheme-specific aggregated proof bytes.
//!
//! `Anchor.id` is `cx:anchor:sha256:<hex>` derived from canonical bytes
//! that exclude both `id` and `anchorer_sig` (sig is over the same bytes).
//! Per §4 rule 5, `state_root` is the canonical Merkle root of all cell
//! Lattice values + bottom diagnostics under this Anchor view; computing
//! it requires the lattice runtime so it is a hash field here that the
//! producer fills in (and the receiver recomputes after `apply_anchor`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::move_event::MoveSignature;
use crate::{AnchorId, Did, Error, Hash, Hlc, MoveId, Result, SpaceId};

/// Allowed Anchor signature algorithms (see `anchor.schema.json` `signature.alg`).
pub const ANCHOR_SIGNATURE_ALGS: &[&str] = &["EdDSA", "ES256", "ES384", "ES512"];

/// Anchorer signature in one of three normative shapes.
///
/// Wire encoding is a JSON oneOf, distinguished for multi/threshold by a
/// `kind` discriminator. `Single` is a bare signature (no `kind` tag) and
/// matches the `signature` schema directly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum AnchorerSig {
    /// Single-DID anchorer.
    Single(MoveSignature),
    /// Explicit multi-sig — every listed signer signs.
    Multi(MultiSignature),
    /// `k`-of-`n` threshold scheme with aggregated `proof`.
    Threshold(ThresholdSignature),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MultiSignature {
    /// Discriminator literal `"multi_sig"`.
    pub kind: MultiSigKind,
    pub signatures: Vec<MoveSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ThresholdSignature {
    /// Discriminator literal `"threshold_sig"`.
    pub kind: ThresholdSigKind,
    pub threshold: u32,
    pub signers: Vec<Did>,
    /// Threshold-scheme-specific aggregated proof bytes (base64 / hex /
    /// scheme-specific encoding declared by the threshold scheme profile).
    pub proof: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MultiSigKind {
    MultiSig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ThresholdSigKind {
    ThresholdSig,
}

/// Top-level Anchor object as defined by `anchor.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Anchor {
    pub id: AnchorId,
    pub space_id: SpaceId,
    /// Empty only for genesis Anchor. Otherwise must reference all
    /// predecessor leaves.
    pub predecessor_refs: Vec<AnchorId>,
    /// Move ids included in this Anchor's frontier. MUST be a superset of
    /// the union of all `predecessor_refs.frontier` (monotonicity).
    pub frontier: Vec<MoveId>,
    /// Canonical Merkle root over the per-cell Lattice values + bottom
    /// diagnostics under this Anchor view.
    pub state_root: Hash,
    pub anchorer_sig: AnchorerSig,
    pub hlc: Hlc,
}

/// Body view used for canonical-bytes derivation.
///
/// Excludes both `id` and `anchorer_sig`. The anchorer hashes these bytes
/// to populate `id`, then signs the same bytes (every signer in
/// multi/threshold cases signs the same canonical bytes).
#[derive(Serialize)]
struct AnchorBody<'a> {
    space_id: &'a SpaceId,
    predecessor_refs: &'a [AnchorId],
    frontier: &'a [MoveId],
    state_root: &'a Hash,
    hlc: &'a Hlc,
}

impl Anchor {
    /// Canonical bytes for Anchor id derivation and signature input.
    pub fn canonical_bytes_for_id(&self) -> Result<Vec<u8>> {
        let body = AnchorBody {
            space_id: &self.space_id,
            predecessor_refs: &self.predecessor_refs,
            frontier: &self.frontier,
            state_root: &self.state_root,
            hlc: &self.hlc,
        };
        canonical::canonical_json_bytes(&body)
    }

    /// Compute the content-addressed Anchor id for this Anchor's body.
    pub fn derive_id(&self) -> Result<AnchorId> {
        Self::id_from_canonical_bytes(&self.canonical_bytes_for_id()?)
    }

    pub fn id_from_canonical_bytes(bytes: &[u8]) -> Result<AnchorId> {
        let digest = Sha256::digest(bytes);
        let id = format!("cx:anchor:sha256:{digest:x}");
        AnchorId::new(id).map_err(|err| Error::Protocol(format!("invalid Anchor id: {err}")))
    }

    pub fn validate_id(&self) -> Result<()> {
        let derived = self.derive_id()?;
        if derived != self.id {
            return Err(Error::Protocol(format!(
                "Anchor id mismatch: declared {} but canonical bytes hash to {}",
                self.id, derived
            )));
        }
        Ok(())
    }

    /// Lightweight structural validation independent of the lattice runtime.
    ///
    /// Per spec §4:
    /// 1. `predecessor_refs=[]` is allowed only for genesis Anchor — but
    ///    detecting "this is the genesis Anchor of this Space" requires
    ///    knowledge of Space history, so this method only enforces the
    ///    weaker rule that empty `frontier` + empty `predecessor_refs` is
    ///    rejected (such an Anchor commits to nothing).
    /// 2. Threshold signatures: `threshold >= 1`, `threshold <= signers.len()`.
    /// 3. Multi-sig: `signatures.len() >= 1`, alg in allowlist.
    /// 4. Single sig alg in allowlist.
    pub fn validate_structural(&self) -> Result<()> {
        if self.predecessor_refs.is_empty() && self.frontier.is_empty() {
            return Err(Error::Protocol(
                "Anchor with empty predecessor_refs[] and empty frontier[] commits to nothing"
                    .to_owned(),
            ));
        }
        match &self.anchorer_sig {
            AnchorerSig::Single(sig) => Self::validate_signature_alg(&sig.alg)?,
            AnchorerSig::Multi(multi) => {
                if multi.signatures.is_empty() {
                    return Err(Error::Protocol(
                        "Anchor multi_sig must have at least one signature".to_owned(),
                    ));
                }
                for sig in &multi.signatures {
                    Self::validate_signature_alg(&sig.alg)?;
                }
            }
            AnchorerSig::Threshold(t) => {
                if t.threshold == 0 {
                    return Err(Error::Protocol(
                        "Anchor threshold_sig threshold must be >= 1".to_owned(),
                    ));
                }
                if t.signers.is_empty() {
                    return Err(Error::Protocol(
                        "Anchor threshold_sig must list at least one signer".to_owned(),
                    ));
                }
                if (t.threshold as usize) > t.signers.len() {
                    return Err(Error::Protocol(format!(
                        "Anchor threshold_sig threshold {} exceeds signer count {}",
                        t.threshold,
                        t.signers.len()
                    )));
                }
                if t.proof.is_empty() {
                    return Err(Error::Protocol(
                        "Anchor threshold_sig proof must not be empty".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_signature_alg(alg: &str) -> Result<()> {
        if !ANCHOR_SIGNATURE_ALGS.contains(&alg) {
            return Err(Error::Protocol(format!(
                "Anchor signature alg '{alg}' is not in allowed set {ANCHOR_SIGNATURE_ALGS:?}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::{Value, json};

    fn space() -> SpaceId {
        SpaceId::new("cx:space:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn move_id(hex_byte: u8) -> MoveId {
        let hex = format!("{hex_byte:02x}").repeat(32);
        MoveId::new(format!("cx:move:sha256:{hex}")).unwrap()
    }

    fn anchor_id(hex_byte: u8) -> AnchorId {
        let hex = format!("{hex_byte:02x}").repeat(32);
        AnchorId::new(format!("cx:anchor:sha256:{hex}")).unwrap()
    }

    fn hash(hex_byte: u8) -> Hash {
        let hex = format!("{hex_byte:02x}").repeat(32);
        Hash::new(format!("sha256:{hex}")).unwrap()
    }

    fn hlc() -> Hlc {
        Hlc::new("0189c4d2af00-00000000-aabbccdd".to_owned()).unwrap()
    }

    fn signature() -> MoveSignature {
        MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:anchorer.example#k1".to_owned(),
            payload_hash: hash(0xff),
            created_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        }
    }

    fn build_anchor(sig: AnchorerSig) -> Anchor {
        let mut a = Anchor {
            id: anchor_id(0x00),
            space_id: space(),
            predecessor_refs: vec![anchor_id(0xaa)],
            frontier: vec![move_id(0x11), move_id(0x22)],
            state_root: hash(0x77),
            anchorer_sig: sig,
            hlc: hlc(),
        };
        a.id = a.derive_id().unwrap();
        a
    }

    #[test]
    fn single_sig_anchor_id_round_trip() {
        let a = build_anchor(AnchorerSig::Single(signature()));
        a.validate_id().expect("derived id must match self.id");
    }

    #[test]
    fn multi_sig_anchor_id_round_trip() {
        let multi = MultiSignature {
            kind: MultiSigKind::MultiSig,
            signatures: vec![signature(), signature()],
        };
        let a = build_anchor(AnchorerSig::Multi(multi));
        a.validate_id().unwrap();
        a.validate_structural().unwrap();
    }

    #[test]
    fn threshold_sig_anchor_id_round_trip() {
        let t = ThresholdSignature {
            kind: ThresholdSigKind::ThresholdSig,
            threshold: 2,
            signers: vec![
                Did::new("did:web:a.example".to_owned()).unwrap(),
                Did::new("did:web:b.example".to_owned()).unwrap(),
                Did::new("did:web:c.example".to_owned()).unwrap(),
            ],
            proof: "BLS_AGG_PROOF_BASE64".to_owned(),
        };
        let a = build_anchor(AnchorerSig::Threshold(t));
        a.validate_id().unwrap();
        a.validate_structural().unwrap();
    }

    #[test]
    fn anchor_id_mismatch_rejected() {
        let mut a = build_anchor(AnchorerSig::Single(signature()));
        a.id = anchor_id(0xee); // wrong
        a.validate_id().expect_err("declared id ≠ canonical hash must reject");
    }

    #[test]
    fn anchor_canonical_bytes_excludes_id_and_sig() {
        let a = build_anchor(AnchorerSig::Single(signature()));
        let bytes = a.canonical_bytes_for_id().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(!s.contains("\"id\":"), "canonical bytes must not contain id");
        assert!(!s.contains("\"anchorer_sig\""), "canonical bytes must not contain anchorer_sig");
        assert!(!s.contains("\"jws\""), "canonical bytes must not leak signature internals");
    }

    #[test]
    fn empty_predecessor_and_frontier_rejected() {
        let mut a = build_anchor(AnchorerSig::Single(signature()));
        a.predecessor_refs.clear();
        a.frontier.clear();
        a.id = a.derive_id().unwrap();
        a.validate_structural().expect_err("empty pred + empty frontier commits to nothing");
    }

    #[test]
    fn threshold_above_signer_count_rejected() {
        let t = ThresholdSignature {
            kind: ThresholdSigKind::ThresholdSig,
            threshold: 5,
            signers: vec![Did::new("did:web:a.example".to_owned()).unwrap()],
            proof: "BLS_AGG".to_owned(),
        };
        let a = build_anchor(AnchorerSig::Threshold(t));
        let err = a.validate_structural().unwrap_err();
        assert!(format!("{err}").contains("exceeds signer count"));
    }

    #[test]
    fn threshold_zero_rejected() {
        let t = ThresholdSignature {
            kind: ThresholdSigKind::ThresholdSig,
            threshold: 0,
            signers: vec![Did::new("did:web:a.example".to_owned()).unwrap()],
            proof: "p".to_owned(),
        };
        let a = build_anchor(AnchorerSig::Threshold(t));
        let err = a.validate_structural().unwrap_err();
        assert!(format!("{err}").contains("threshold must be >= 1"));
    }

    #[test]
    fn empty_multi_sig_rejected() {
        let multi = MultiSignature { kind: MultiSigKind::MultiSig, signatures: vec![] };
        let a = build_anchor(AnchorerSig::Multi(multi));
        let err = a.validate_structural().unwrap_err();
        assert!(format!("{err}").contains("at least one signature"));
    }

    #[test]
    fn unknown_alg_rejected_in_single_sig() {
        let mut sig = signature();
        sig.alg = "RSA1_5".to_owned();
        let a = build_anchor(AnchorerSig::Single(sig));
        let err = a.validate_structural().unwrap_err();
        assert!(format!("{err}").contains("not in allowed set"));
    }

    #[test]
    fn anchorer_sig_serializes_with_kind_discriminator_for_multi_and_threshold() {
        let multi = MultiSignature { kind: MultiSigKind::MultiSig, signatures: vec![signature()] };
        let s = serde_json::to_string(&AnchorerSig::Multi(multi)).unwrap();
        assert!(s.contains("\"kind\":\"multi_sig\""), "got {s}");

        let t = ThresholdSignature {
            kind: ThresholdSigKind::ThresholdSig,
            threshold: 1,
            signers: vec![Did::new("did:web:a.example".to_owned()).unwrap()],
            proof: "p".to_owned(),
        };
        let s = serde_json::to_string(&AnchorerSig::Threshold(t)).unwrap();
        assert!(s.contains("\"kind\":\"threshold_sig\""), "got {s}");
    }

    #[test]
    fn single_sig_deserializes_from_bare_signature() {
        // Single sig wire form has no kind discriminator.
        let json = json!({
            "alg": "EdDSA",
            "verification_method": "did:web:anchorer.example#k1",
            "payload_hash": format!("sha256:{}", "ff".repeat(32)),
            "created_at": "2026-05-08T00:00:00Z",
            "jws": "AAAA.BBBB.CCCC"
        });
        let s: AnchorerSig = serde_json::from_value(json).unwrap();
        assert!(matches!(s, AnchorerSig::Single(_)));
    }

    #[test]
    fn deserialize_anchor_round_trip_through_canonical_bytes() {
        let a = build_anchor(AnchorerSig::Single(signature()));
        let v = serde_json::to_value(&a).unwrap();
        let r: Anchor = serde_json::from_value(v).unwrap();
        assert_eq!(r, a);
        // Re-derive id matches.
        r.validate_id().unwrap();
    }

    #[test]
    fn frontier_and_predecessor_in_canonical_bytes() {
        let a = build_anchor(AnchorerSig::Single(signature()));
        let bytes = a.canonical_bytes_for_id().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("\"frontier\""));
        assert!(s.contains("\"predecessor_refs\""));
        assert!(s.contains("\"state_root\""));
        assert!(s.contains("\"space_id\""));
    }

    // Sanity: parsed Value structure has expected fields.
    #[test]
    fn anchor_serializes_all_top_level_required_fields() {
        let a = build_anchor(AnchorerSig::Single(signature()));
        let v: Value = serde_json::to_value(&a).unwrap();
        for field in
            ["id", "space_id", "predecessor_refs", "frontier", "state_root", "anchorer_sig", "hlc"]
        {
            assert!(v.get(field).is_some(), "missing required field {field}");
        }
    }
}
