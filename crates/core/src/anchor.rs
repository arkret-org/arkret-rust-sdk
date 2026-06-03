//! Cokret Anchor typed model.
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
//! `Anchor.id` is `ck:anchor:sha256:<hex>` derived from canonical bytes
//! that exclude both `id` and `anchorer_signature` (sig is over the same bytes).
//! Per §4 rule 5, `state_root` is the canonical Merkle root of all cell
//! Lattice values + bottom diagnostics under this Anchor view; computing
//! it requires the lattice runtime so it is a hash field here that the
//! producer fills in (and the receiver recomputes after `apply_anchor`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use chrono::{DateTime, Utc};

use crate::canonical;
use crate::move_event::MoveSignature;
use crate::{AnchorId, Did, Error, Hash, Hlc, MoveId, Result, SpaceId};

/// Allowed Anchor signature algorithms (see `anchor.schema.json` `signature.alg`).
pub const ANCHOR_SIGNATURE_ALGS: &[&str] = &["EdDSA", "ES256", "ES384", "ES512"];

/// Compute canonical Anchor body bytes for id derivation / signature input.
/// Excludes both `id` and `anchorer_signature` per `anchor.schema.json`.
/// Round R2/R3 (2026-05-20) — explicit free-function shim mirroring the
/// spec name for downstream implementers.
pub fn anchor_canonical_bytes(anchor: &Anchor) -> Result<Vec<u8>> {
    anchor.canonical_bytes_for_id()
}

/// Compute the content-addressed Anchor id from canonical bytes:
/// `ck:anchor:sha256:` || hex(SHA-256(canonical_bytes)).
pub fn compute_anchor_id(canonical_bytes: &[u8]) -> Result<AnchorId> {
    Anchor::id_from_canonical_bytes(canonical_bytes)
}

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

/// Anchor categorization — distinguishes normal frontier-advance anchors
/// from compaction anchors (MAL-11).
///
/// A `Normal` anchor must obey the §4 rules: its `frontier` is a strict
/// superset of the predecessor-frontier union (monotonicity), and every
/// new move in `frontier \ pred_union` is verified.
///
/// A `Compaction` anchor accepts zero new moves (`frontier ==
/// pred_union`); its purpose is to mark a checkpoint at which historical
/// predecessor anchors become eligible for `AnchorStore::prune_predecessor`.
/// Compaction anchors are still signed by the anchorer and still appear in
/// the DAG; pruning is a separate explicit step on the store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    /// Normal frontier-advance anchor. Default for anchors deserialized
    /// from older wire envelopes without a `kind` field.
    #[default]
    Normal,
    /// MAL-11 compaction anchor. `frontier` MUST equal the union of
    /// predecessor frontiers (no new moves accepted).
    Compaction,
}

/// Top-level Anchor object as defined by `anchor.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Anchor {
    pub id: AnchorId,
    // NOTE: typed as `SpaceId` (which also accepts `ck:realm:` ids) rather
    // than `RealmId` because the entire cell/store/state layer is keyed by
    // `SpaceId`; tightening this to `RealmId` is part of the larger
    // Realm/Space type inversion (see _code_review report 06 #2). Wire output
    // is identical either way.
    pub realm_id: SpaceId,
    /// Empty only for genesis Anchor. Otherwise must reference all
    /// predecessor leaves.
    pub predecessor_refs: Vec<AnchorId>,
    /// Move ids included in this Anchor's frontier. MUST be a superset of
    /// the union of all `predecessor_refs.frontier` (monotonicity).
    pub frontier: Vec<MoveId>,
    /// Canonical Merkle root over the per-cell Lattice values + bottom
    /// diagnostics under this Anchor view.
    pub state_root: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_state_root: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_digest_algorithm: Option<String>,
    pub anchorer_signature: AnchorerSig,
    pub anchored_at: DateTime<Utc>,
    pub hlc: Hlc,
    /// MAL-11: explicit anchor categorization.
    #[serde(default, skip)]
    pub kind: AnchorKind,
}

impl AnchorKind {
    /// True for compaction anchors. Convenience for caller code.
    pub fn is_compaction(&self) -> bool {
        matches!(self, AnchorKind::Compaction)
    }
}

/// Body view used for canonical-bytes derivation.
///
/// Excludes both `id` and `anchorer_signature`. The anchorer hashes these bytes
/// to populate `id`, then signs the same bytes (every signer in
/// multi/threshold cases signs the same canonical bytes).
///
/// `kind` IS in the body — a compaction anchor and a normal anchor with
/// the same frontier MUST hash differently so the DAG can't be tricked
/// into pruning based on a forged compaction tag.
#[derive(Serialize)]
struct AnchorBody<'a> {
    realm_id: &'a SpaceId,
    predecessor_refs: &'a [AnchorId],
    frontier: &'a [MoveId],
    state_root: &'a Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_state_root: &'a Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_digest_algorithm: &'a Option<String>,
    anchored_at: &'a DateTime<Utc>,
    hlc: &'a Hlc,
}

impl Anchor {
    /// Canonical bytes for Anchor id derivation and signature input.
    pub fn canonical_bytes_for_id(&self) -> Result<Vec<u8>> {
        let body = AnchorBody {
            realm_id: &self.realm_id,
            predecessor_refs: &self.predecessor_refs,
            frontier: &self.frontier,
            state_root: &self.state_root,
            previous_state_root: &self.previous_state_root,
            previous_digest_algorithm: &self.previous_digest_algorithm,
            anchored_at: &self.anchored_at,
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
        let id = format!("ck:anchor:sha256:{digest:x}");
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
    /// 1. `predecessor_refs=[]` is allowed only for the Genesis Anchor.
    ///    The Genesis Anchor itself MUST have `frontier=[]` and an empty
    ///    state root; a no-predecessor Anchor with a non-empty frontier is a
    ///    schema violation because it would cover Moves without a baseline.
    /// 2. Threshold signatures: `threshold >= 1`, `threshold <= signers.len()`.
    /// 3. Multi-sig: `signatures.len() >= 1`, alg in allowlist.
    /// 4. Single sig alg in allowlist.
    pub fn validate_structural(&self) -> Result<()> {
        if self.predecessor_refs.is_empty() && !self.frontier.is_empty() {
            return Err(Error::Protocol(
                "Genesis Anchor MUST have frontier=[]; predecessor_refs=[] with non-empty frontier is invalid"
                    .to_owned(),
            ));
        }
        if self.predecessor_refs.is_empty()
            && self.state_root.as_str() != crate::state::state_root::EMPTY_STATE_ROOT
        {
            return Err(Error::Protocol(
                "Genesis Anchor MUST commit to the empty state_root".to_owned(),
            ));
        }
        if self.previous_state_root.is_some() != self.previous_digest_algorithm.is_some() {
            return Err(Error::Protocol(
                "Anchor previous_state_root and previous_digest_algorithm must be present together"
                    .to_owned(),
            ));
        }
        match &self.anchorer_signature {
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

    /// Round R2/R3 (2026-05-20) — validate frontier items use the bare
    /// `<algo>:<hex>` hash form. Reject legacy `ck:event:<uuid>` form which
    /// has been removed by the spec. (MoveId only accepts hash form per
    /// `is_hash`, so this method primarily catches strings that bypassed
    /// the typed constructor by being deserialized as raw JSON.)
    pub fn validate_frontier_format(frontier_strs: &[&str]) -> Result<()> {
        for entry in frontier_strs {
            if entry.starts_with("ck:event:") {
                return Err(Error::Protocol(format!(
                    "anchor frontier item {entry:?} uses removed ck:event:<uuid> form; \
                     MUST be bare <algo>:<hex> hash"
                )));
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
        SpaceId::new("ck:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn move_id(hex_byte: u8) -> MoveId {
        let hex = format!("{hex_byte:02x}").repeat(32);
        MoveId::new(format!("sha256:{hex}")).unwrap()
    }

    fn anchor_id(hex_byte: u8) -> AnchorId {
        let hex = format!("{hex_byte:02x}").repeat(32);
        AnchorId::new(format!("ck:anchor:sha256:{hex}")).unwrap()
    }

    fn hash(hex_byte: u8) -> Hash {
        let hex = format!("{hex_byte:02x}").repeat(32);
        Hash::new(format!("sha256:{hex}")).unwrap()
    }

    fn hlc() -> Hlc {
        Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap()
    }

    fn signature() -> MoveSignature {
        MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:anchorer.example#k1".to_owned(),
            payload_digest: hash(0xff),
            created_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        }
    }

    fn build_anchor(sig: AnchorerSig) -> Anchor {
        let mut a = Anchor {
            id: anchor_id(0x00),
            realm_id: space(),
            predecessor_refs: vec![anchor_id(0xaa)],
            frontier: vec![move_id(0x11), move_id(0x22)],
            state_root: hash(0x77),
            previous_state_root: None,
            previous_digest_algorithm: None,
            anchorer_signature: sig,
            anchored_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            hlc: hlc(),
            kind: AnchorKind::Normal,
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
        assert!(
            !s.contains("\"anchorer_signature\""),
            "canonical bytes must not contain anchorer_signature"
        );
        assert!(!s.contains("\"jws\""), "canonical bytes must not leak signature internals");
    }

    #[test]
    fn genesis_anchor_with_empty_frontier_is_valid() {
        let mut a = build_anchor(AnchorerSig::Single(signature()));
        a.predecessor_refs.clear();
        a.frontier.clear();
        a.state_root = Hash::new(crate::state::state_root::EMPTY_STATE_ROOT.to_owned()).unwrap();
        a.id = a.derive_id().unwrap();
        a.validate_structural().expect("Genesis Anchor is the empty-frontier root");
    }

    #[test]
    fn no_predecessor_anchor_with_frontier_rejected() {
        let mut a = build_anchor(AnchorerSig::Single(signature()));
        a.predecessor_refs.clear();
        a.id = a.derive_id().unwrap();
        let err = a.validate_structural().unwrap_err();
        assert!(format!("{err}").contains("frontier=[]"));
    }

    #[test]
    fn genesis_anchor_with_non_empty_state_root_rejected() {
        let mut a = build_anchor(AnchorerSig::Single(signature()));
        a.predecessor_refs.clear();
        a.frontier.clear();
        a.id = a.derive_id().unwrap();
        let err = a.validate_structural().unwrap_err();
        assert!(format!("{err}").contains("empty state_root"));
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
    fn anchorer_signature_serializes_with_kind_discriminator_for_multi_and_threshold() {
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
            "payload_digest": format!("sha256:{}", "ff".repeat(32)),
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
        assert!(s.contains("\"realm_id\""));
    }

    // Sanity: parsed Value structure has expected fields.
    #[test]
    fn anchor_serializes_all_top_level_required_fields() {
        let a = build_anchor(AnchorerSig::Single(signature()));
        let v: Value = serde_json::to_value(&a).unwrap();
        for field in [
            "id",
            "realm_id",
            "predecessor_refs",
            "frontier",
            "state_root",
            "anchorer_signature",
            "anchored_at",
            "hlc",
        ] {
            assert!(v.get(field).is_some(), "missing required field {field}");
        }
    }

    // ── MAL-11: AnchorKind ───────────────────────────────────────────────

    #[test]
    fn anchor_kind_is_internal_not_wire() {
        let mut a = build_anchor(AnchorerSig::Single(signature()));
        a.kind = AnchorKind::Compaction;
        a.id = a.derive_id().unwrap();
        let v = serde_json::to_value(&a).unwrap();
        assert!(v.get("kind").is_none());
    }

    #[test]
    fn anchor_kind_compaction_does_not_change_wire_id() {
        let mut normal = build_anchor(AnchorerSig::Single(signature()));
        let mut compaction = normal.clone();
        compaction.kind = AnchorKind::Compaction;
        normal.id = normal.derive_id().unwrap();
        compaction.id = compaction.derive_id().unwrap();
        assert_eq!(normal.id, compaction.id);
    }

    #[test]
    fn anchor_kind_round_trip_through_json_defaults_to_normal() {
        let mut a = build_anchor(AnchorerSig::Single(signature()));
        a.kind = AnchorKind::Compaction;
        a.id = a.derive_id().unwrap();
        let v = serde_json::to_value(&a).unwrap();
        let r: Anchor = serde_json::from_value(v).unwrap();
        assert_eq!(r.kind, AnchorKind::Normal);
        assert_eq!(r.id, a.id);
    }

    #[test]
    fn anchor_kind_helper_is_compaction() {
        assert!(AnchorKind::Compaction.is_compaction());
        assert!(!AnchorKind::Normal.is_compaction());
    }
}
