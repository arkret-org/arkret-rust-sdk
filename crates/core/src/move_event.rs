//! Cokret Move typed model.
//!
//! A Move is the protocol's atomic conditional multi-cell write primitive
//! introduced by spec 2026-05-08 (`spec/v1/zh/authz/event-auth-state-resolution.md`
//! §3, schema `move.schema.json`). Each Move:
//!
//! - is single-signed by its `issuer` (committee / multi-sig / threshold are
//!   anchorer-side concerns, not Move-side);
//! - declares ordered `preconditions[]` over cell ids — the Anchor batch
//!   pre-state must satisfy all of them or the Move fails as a whole;
//! - carries `effects[]` with `lattice_op` shapes whose validity depends on
//!   the target cell's declared Lattice type;
//! - references an `anchor_ref` so the receiver knows which Anchor view the
//!   issuer was working from, plus optional `refs[]` for `authorized_by` /
//!   `recovery_capability` / `parent_move` / `after` semantic dependencies.
//!
//! `Move::id` is content-addressed: `sha256:<hex>` derived from
//! [`Move::canonical_bytes_for_id`] (everything **except** `id` and `sig`).
//! `sig` is the issuer's detached JWS over those same canonical bytes.
//! The receiver MUST recompute the digest, MUST reject mismatches, and MUST
//! NOT trust an `id` that is not a function of the rest of the wire object.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::{AnchorId, CellRef, Did, Error, Hash, Hlc, MoveId, Result, SpaceId};

/// Allowed Move signature algorithms (must match `move.schema.json` `signature.alg`).
pub const MOVE_SIGNATURE_ALGS: &[&str] = &["EdDSA", "ES256", "ES384", "ES512"];

/// Top-level Move object as defined by `move.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Move {
    pub id: MoveId,
    pub issuer: Did,
    pub space_id: SpaceId,
    pub preconditions: Vec<Precondition>,
    pub effects: Vec<Effect>,
    pub anchor_ref: AnchorId,
    #[serde(default)]
    pub refs: Vec<SemanticRef>,
    pub hlc: Hlc,
    pub sig: MoveSignature,
}

/// Single precondition: a cell + a predicate. Combined with AND across the Move.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Precondition {
    pub cell: CellRef,
    pub predicate: Predicate,
}

/// Predicate over a cell value. Wire shape is `{op, value?, values?, predicate_id?}`.
///
/// The four normative core ops live in [`PredicateOp`]; `predicate_id` is
/// reserved for `satisfies`-mode lookups against a cell's schema-registered
/// deterministic predicates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Predicate {
    pub op: PredicateOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PredicateOp {
    /// Cell value / head must equal `value`.
    HeadEq,
    /// Cell value / exposed heads must be in `values`.
    HeadIn,
    /// Cell value must satisfy a schema-registered predicate identified by `predicate_id`.
    Satisfies,
    /// Cell set / OR-set / covered frontier must contain `value` (or `values` as subset).
    Contains,
}

/// Single effect: a cell + a lattice operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Effect {
    pub cell: CellRef,
    pub op: LatticeOp,
}

/// Lattice operation. Wire shape is `{kind, tag?, value?, from?, to?, reason?, issuer_seq?}`.
///
/// Which fields are required depends on the cell's declared Lattice type
/// (see spec §3.2). This struct accepts the union; per-type validation lives
/// in the `lattice` crate's per-implementation `validate_op`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct LatticeOp {
    #[serde(rename = "kind")]
    pub op_type: LatticeOpType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_seq: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum LatticeOpType {
    /// or-set add (requires `tag`, often `value`).
    Add,
    /// or-set remove (requires `tag`, optional `reason`).
    Remove,
    /// mv-register / cas-register set (requires `value`).
    Set,
    /// fsm transition (requires `from` + `to`).
    Transition,
    /// counter increment (requires non-negative `value`).
    Inc,
    /// counter decrement (requires non-negative `value`).
    Dec,
    /// ordered-log append (requires `value` and `issuer_seq`).
    Append,
}

/// Semantic dependency reference. `role` examples: `authorized_by`,
/// `attestation`, `parent_move`, `after`, `recovery_capability`.
/// `critical` defaults to `true`; unrecognized critical roles MUST fail
/// closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SemanticRef {
    pub id: String,
    pub role: String,
    #[serde(default = "default_critical", skip_serializing_if = "is_default_critical")]
    pub critical: bool,
}

fn default_critical() -> bool {
    true
}

fn is_default_critical(value: &bool) -> bool {
    *value
}

/// Issuer detached-JWS signature over canonical bytes (excluding `sig` and `id`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MoveSignature {
    pub alg: String,
    pub verification_method: String,
    pub payload_digest: Hash,
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

/// Body view used for canonical-bytes derivation.
///
/// Excludes both `id` (which is being computed) and `sig` (which is computed
/// last over the same canonical bytes). The field order mirrors the on-wire
/// schema exactly; canonical JSON will sort object keys at serialization
/// time so the order in this struct is documentation only.
#[derive(Serialize)]
struct MoveBody<'a> {
    issuer: &'a Did,
    space_id: &'a SpaceId,
    preconditions: &'a [Precondition],
    effects: &'a [Effect],
    anchor_ref: &'a AnchorId,
    refs: &'a [SemanticRef],
    hlc: &'a Hlc,
}

impl Move {
    /// Canonical bytes for hashing / signing.
    ///
    /// Excludes `id` and `sig` per spec §3 rule 1. The producer hashes these
    /// bytes to populate `id`, then signs the same bytes to populate `sig`.
    pub fn canonical_bytes_for_id(&self) -> Result<Vec<u8>> {
        let body = MoveBody {
            issuer: &self.issuer,
            space_id: &self.space_id,
            preconditions: &self.preconditions,
            effects: &self.effects,
            anchor_ref: &self.anchor_ref,
            refs: &self.refs,
            hlc: &self.hlc,
        };
        canonical::canonical_json_bytes(&body)
    }

    /// Compute the content-addressed Move id for this Move's body.
    pub fn derive_id(&self) -> Result<MoveId> {
        Self::id_from_canonical_bytes(&self.canonical_bytes_for_id()?)
    }

    /// Compute a Move id from already-canonicalized bytes.
    pub fn id_from_canonical_bytes(bytes: &[u8]) -> Result<MoveId> {
        let digest = Sha256::digest(bytes);
        let id = format!("sha256:{digest:x}");
        MoveId::new(id).map_err(|err| Error::Protocol(format!("invalid Move id: {err}")))
    }

    /// Validate that `self.id` matches `derive_id()`.
    ///
    /// Receivers MUST call this before trusting any field of the Move.
    pub fn validate_id(&self) -> Result<()> {
        let derived = self.derive_id()?;
        if derived != self.id {
            return Err(Error::Protocol(format!(
                "Move id mismatch: declared {} but canonical bytes hash to {}",
                self.id, derived
            )));
        }
        Ok(())
    }

    /// Lightweight structural validation independent of cell schemas.
    ///
    /// Per-cell `validate_op` lives in the `lattice` crate (M4); this only
    /// covers wire-shape rules that don't need a cell registry:
    ///
    /// 1. `effects[]` MUST contain at least one entry (no pure-query Move).
    /// 2. `preconditions.len()` and `effects.len()` MUST be `<= 256`
    ///    (schema bound).
    /// 3. Signature `alg` MUST be in [`MOVE_SIGNATURE_ALGS`].
    /// 4. `payload_digest` MUST equal sha256 of canonical bytes.
    pub fn validate_structural(&self) -> Result<()> {
        if self.effects.is_empty() {
            return Err(Error::Protocol(
                "Move effects[] must contain at least one entry; pure-query Moves are not allowed"
                    .to_owned(),
            ));
        }
        if self.preconditions.len() > 256 {
            return Err(Error::Protocol(format!(
                "Move preconditions[] too large: {} > 256",
                self.preconditions.len()
            )));
        }
        if self.effects.len() > 256 {
            return Err(Error::Protocol(format!(
                "Move effects[] too large: {} > 256",
                self.effects.len()
            )));
        }
        if !MOVE_SIGNATURE_ALGS.iter().any(|allowed| *allowed == self.sig.alg) {
            return Err(Error::Protocol(format!(
                "Move signature alg '{}' is not in allowed set {:?}",
                self.sig.alg, MOVE_SIGNATURE_ALGS
            )));
        }
        let canonical_hash = canonical::sha256_digest(self.canonical_bytes_for_id()?);
        if self.sig.payload_digest.as_str() != canonical_hash {
            return Err(Error::Protocol(format!(
                "Move signature payload_digest {} does not match canonical bytes hash {}",
                self.sig.payload_digest, canonical_hash
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sha256_digest;
    use serde_json::json;

    fn sample_move_body_json() -> Value {
        json!({
            "issuer": "did:web:admin.example",
            "space_id": "ck:space:0196419b-0000-7000-8000-00000000014a",
            "preconditions": [
                {
                    "cell": "ck:cell:ck.component.member.state.v1:did.web.alice.example",
                    "predicate": {
                        "op": "head_eq",
                        "value": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    }
                }
            ],
            "effects": [
                {
                    "cell": "ck:cell:ck.component.member.state.v1:did.web.alice.example",
                    "op": {
                        "kind": "transition",
                        "from": "join",
                        "to": "ban",
                        "reason": "abuse"
                    }
                }
            ],
            "anchor_ref": "ck:anchor:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "refs": [],
            "hlc": "0189c4d2af00-0000-aabbccdd"
        })
    }

    fn sample_move() -> Move {
        let body = sample_move_body_json();
        let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
        let payload_digest = sha256_digest(&body_bytes);
        let move_id_hex = {
            let digest = Sha256::digest(&body_bytes);
            format!("sha256:{digest:x}")
        };
        let mut full = body.as_object().unwrap().clone();
        full.insert("id".to_owned(), Value::String(move_id_hex));
        full.insert(
            "sig".to_owned(),
            json!({
                "alg": "EdDSA",
                "verification_method": "did:web:admin.example#k1",
                "payload_digest": payload_digest,
                "created_at": "2026-05-08T00:00:00Z",
                "jws": "AAAA.BBBB.CCCC"
            }),
        );
        serde_json::from_value(Value::Object(full)).unwrap()
    }

    #[test]
    fn id_matches_canonical_bytes_hash() {
        let m = sample_move();
        m.validate_id().expect("id must match canonical bytes");
    }

    #[test]
    fn id_mismatch_is_rejected() {
        let mut m = sample_move();
        // Fabricate a wrong id with valid prefix shape.
        m.id =
            MoveId::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        m.validate_id().expect_err("declared id ≠ canonical hash must reject");
    }

    #[test]
    fn structural_validation_rejects_empty_effects() {
        let mut m = sample_move();
        m.effects.clear();
        // Re-derive id so the failure is on effects rule, not id mismatch.
        m.id = m.derive_id().unwrap();
        let err = m.validate_structural().unwrap_err();
        assert!(format!("{err}").contains("effects[] must contain"));
    }

    #[test]
    fn structural_validation_rejects_unknown_alg() {
        let mut m = sample_move();
        m.sig.alg = "RSA1_5".to_owned();
        let err = m.validate_structural().unwrap_err();
        assert!(format!("{err}").contains("not in allowed set"));
    }

    #[test]
    fn structural_validation_rejects_payload_digest_drift() {
        let mut m = sample_move();
        m.sig.payload_digest =
            Hash::new("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
                .unwrap();
        let err = m.validate_structural().unwrap_err();
        assert!(format!("{err}").contains("payload_digest"));
    }

    #[test]
    fn canonical_bytes_excludes_id_and_sig() {
        let m = sample_move();
        let bytes = m.canonical_bytes_for_id().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(!s.contains("\"id\":"), "canonical bytes must not contain id field");
        assert!(!s.contains("\"sig\":"), "canonical bytes must not contain sig field");
        assert!(s.contains("\"issuer\""));
        assert!(s.contains("\"effects\""));
    }

    #[test]
    fn predicate_op_serializes_snake_case() {
        let pred = Predicate {
            op: PredicateOp::HeadEq,
            value: Some(json!("foo")),
            values: None,
            predicate_id: None,
        };
        let s = serde_json::to_string(&pred).unwrap();
        assert!(s.contains("\"op\":\"head_eq\""), "got {s}");
    }

    #[test]
    fn lattice_op_type_serializes_snake_case() {
        let op = LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(json!("join")),
            to: Some(json!("ban")),
            reason: Some("abuse".to_owned()),
            issuer_seq: None,
        };
        let s = serde_json::to_string(&op).unwrap();
        assert!(s.contains("\"kind\":\"transition\""), "got {s}");
        assert!(s.contains("\"reason\":\"abuse\""), "got {s}");
        // None fields skipped.
        assert!(!s.contains("\"tag\""));
        assert!(!s.contains("\"value\""));
    }

    #[test]
    fn semantic_ref_default_critical_true_omitted_on_serialize() {
        let r = SemanticRef {
            id: "ck:grant:01964105-0000-7000-8000-000000000000".to_owned(),
            role: "authorized_by".to_owned(),
            critical: true,
        };
        let s = serde_json::to_string(&r).unwrap();
        // critical=true is the default and should be skipped.
        assert!(!s.contains("\"critical\""), "default critical=true should be skipped: {s}");
    }

    #[test]
    fn semantic_ref_critical_false_serialized() {
        let r = SemanticRef {
            id: "ck:grant:01964105-0000-7000-8000-000000000000".to_owned(),
            role: "after".to_owned(),
            critical: false,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"critical\":false"), "got {s}");
    }

    #[test]
    fn move_id_validator_rejects_bad_shape() {
        // Spec e10b6ad (C47): event_digest is a bare `<algo>:<hex>` hash.
        MoveId::new("01js0mv0000000000000000000".to_owned())
            .expect_err("non-hash payload must reject");
    }

    #[test]
    fn anchor_id_validator_accepts_valid() {
        AnchorId::new(
            "ck:anchor:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
        )
        .expect("valid anchor id");
    }

    #[test]
    fn cell_ref_validator_accepts_simple_and_composite() {
        CellRef::new("ck:cell:ck.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap();
        CellRef::new(
            "ck:cell:ck.component.capability.grant.v1:cx.grant.01js0gr0000000000000000000"
                .to_owned(),
        )
        .unwrap();
    }
}
