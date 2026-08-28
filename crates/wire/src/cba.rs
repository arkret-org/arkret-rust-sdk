//! CBA control-plane wire fragments and the reducer's internal projection type.
//!
//! v1 has no standalone Move object and no producer-authored cell-write
//! channel. A Control Move is an [`crate::Event`] that carries [`SealBasis`]
//! plus optional [`Precondition`]s; every cell target and lattice operation is
//! derived by the receiver from the registered reducer contract over the
//! signed `kind + payload` and the frozen pre-state
//! (`zh/authz/event-auth-state-resolution.md` §5, `zh/models/event-and-patch.md`
//! §2.4.2).
//!
//! [`ProjectionEffect`] is therefore a *reducer output*, not a wire input. It
//! is deliberately not reachable from any serialized Event: nothing in this
//! crate embeds it into an envelope, and reintroducing such a field would
//! restore the producer-supplied reducer-instruction backdoor that v1 removed.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{CellRef, Hash, SealId};

/// Signed governance basis of a Control Move.
///
/// The ordered accepted Seal leaves are the sole producer-authored commitment
/// in the Event. Receivers resolve them and recompute the effective roots.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealBasis {
    /// Accepted Seal ids in canonical ascending order without duplicates.
    pub leaves: Vec<SealId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealBasisWire {
    leaves: Vec<SealId>,
}

impl<'de> Deserialize<'de> for SealBasis {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SealBasisWire::deserialize(deserializer)?;
        let basis = Self {
            leaves: wire.leaves,
        };
        basis
            .validate_protocol_bounds()
            .map_err(serde::de::Error::custom)?;
        Ok(basis)
    }
}

impl SealBasis {
    pub const MAX_LEAVES: usize = 64;

    /// Validate the closed v1 `seal_basis` collection constraints.
    pub fn validate_protocol_bounds(&self) -> crate::Result<()> {
        if self.leaves.is_empty() || self.leaves.len() > Self::MAX_LEAVES {
            return Err(crate::WireError::Protocol(format!(
                "seal_basis.leaves must contain between 1 and {} Seal ids",
                Self::MAX_LEAVES
            )));
        }
        if self.leaves.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(crate::WireError::Protocol(
                "seal_basis.leaves must be unique and in canonical ascending order".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Accepted Seal frontier of a B-model recovery re-anchor.
///
/// Distinct from [`SealBasis`] on purpose. A Control Move's `seal_basis` carries
/// leaves only, because the roots live on the Seals and a producer-authored copy
/// would be a second truth the receiver must ignore anyway. This frontier is the
/// one registered exception: `zh/authz/event-auth-state-resolution.md` §5.1 keeps
/// both roots on the wire because they feed the recovery frontier
/// compare-and-swap, and no amount of local recomputation tells a receiver
/// whether the producer's snapshot was raced.
///
/// Carried by `ak.device.reanchor`'s `pre_fence_seal_frontier` and, byte-identically, by
/// the recovery session's `accepted_seal_frontier` — the spec `$ref`s one shape
/// from the other, and admission compares the two for equality.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReanchorPreFenceSealFrontier {
    /// Accepted Seal ids in canonical ascending order without duplicates.
    pub leaves: Vec<SealId>,
    /// Control-plane event set root covered by the `leaves` view.
    pub control_event_set_root: Hash,
    /// Governance state root under the `leaves` view.
    pub state_root: Hash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceReanchorPreFenceSealFrontierWire {
    leaves: Vec<SealId>,
    control_event_set_root: Hash,
    state_root: Hash,
}

impl<'de> Deserialize<'de> for DeviceReanchorPreFenceSealFrontier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceReanchorPreFenceSealFrontierWire::deserialize(deserializer)?;
        let basis = Self {
            leaves: wire.leaves,
            control_event_set_root: wire.control_event_set_root,
            state_root: wire.state_root,
        };
        basis
            .validate_protocol_bounds()
            .map_err(serde::de::Error::custom)?;
        Ok(basis)
    }
}

impl DeviceReanchorPreFenceSealFrontier {
    /// Validate the leaf collection constraints.
    ///
    /// Delegates to [`SealBasis`] so the 1..=64 bound and the canonical ordering
    /// rule have exactly one implementation.
    pub fn validate_protocol_bounds(&self) -> crate::Result<()> {
        SealBasis {
            leaves: self.leaves.clone(),
        }
        .validate_protocol_bounds()
    }
}

/// Single precondition: a cell + a predicate. Combined with AND across the
/// Control Move; any unsatisfied precondition fails the whole Event.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Precondition {
    pub cell_id: CellRef,
    pub predicate: Predicate,
}

/// Predicate over a cell value. Wire shape is `{op, value?, values?, predicate_id?}`.
///
/// The four normative core ops live in [`PredicateOp`]; `predicate_id` is
/// reserved for `satisfies`-mode lookups against a cell's schema-registered
/// deterministic predicates.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Predicate {
    pub op: PredicateOp,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::deserialize_optional_value_preserving_null"
    )]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate_id: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// One receiver-derived write: a cell plus the lattice operation the
/// registered reducer contract projects for it.
///
/// This type exists only between the projection evaluator and the lattice /
/// state layers. It is never accepted from, nor emitted to, a peer as part of
/// an Event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionEffect {
    pub cell_id: CellRef,
    pub op: LatticeOp,
    /// This write is the `event-auth-state-resolution.md` §9.5 recovery reset,
    /// not an ordinary lattice write.
    ///
    /// A reset **replaces** the cell: it is a boundary in that cell's history,
    /// and every op accepted before it stops being an input to the cell's join.
    /// The op below still travels as a `set`, because the lattice op vocabulary
    /// is spec-registered and has no `reset` member — which is exactly why the
    /// distinction has to live here. Without it the reset is indistinguishable
    /// from a normal `set` and joins **against** the concurrent branches that
    /// put the cell in `⊥`, so the cell never leaves `⊥` and the one escape
    /// path §9.5 defines does not exist.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub recovery_reset: bool,
}

impl ProjectionEffect {
    /// An ordinary lattice write: joins with everything already on the cell.
    pub fn join(cell: CellRef, op: LatticeOp) -> Self {
        Self {
            cell_id: cell,
            op,
            recovery_reset: false,
        }
    }

    /// The §9.5 recovery write: a boundary that discards the cell's prior ops.
    pub fn reset(cell: CellRef, op: LatticeOp) -> Self {
        Self {
            cell_id: cell,
            op,
            recovery_reset: true,
        }
    }
}

/// A projected operation before the frozen pre-state is consulted.
///
/// Most registered projections are a pure function of `kind + payload` and
/// arrive as [`ProjectedOp::Direct`]. Two grammar forms deliberately are not:
/// `transition_to` reads the current head as its `from`, and `apply_patch`
/// computes the new register value from the current one. Keeping them
/// unresolved here is what stops a producer from asserting a pre-state it
/// never observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectedOp {
    /// Fully determined by the signed Event.
    Direct(LatticeOp),
    /// `fsm` transition to `to`; the reducer supplies `from` from the frozen
    /// pre-state and checks the transition against the cell's closed table.
    TransitionTo { to: Value },
    /// `mv_register` / `cas_register` update produced by applying a
    /// schema-defined Patch to the frozen pre-state. The Patch itself is never
    /// stored as the cell value.
    ApplyPatch {
        patch: Value,
        /// Producer-signed digest of the frozen pre-state this patch was
        /// computed against, when the registry declares an `expected_prestate`
        /// source and the payload carries it.
        ///
        /// The reducer MUST reject the whole Event when this is present and
        /// does not byte-equal the frozen pre-state's canonical digest. It is
        /// an optimistic guard layered on top of the lattice, not a substitute
        /// for it: a `cas_register` still needs its `head_eq` precondition and
        /// an `mv_register` still exposes concurrent heads.
        expected_prestate: Option<Value>,
    },
    /// `or_set` observed-remove of every surviving add dot on the target cell
    /// under the frozen pre-state, optionally narrowed to elements whose
    /// `element_field` equals a projected value.
    ///
    /// The dot set is deterministic because the Control Move's `seal_basis`
    /// pins the frontier, so no producer enumeration is needed. A
    /// producer-named subset is `or_set_delta`'s `remove` branch instead.
    RemoveObserved {
        element_match: Option<ObservedRemoveMatch>,
    },
    /// Resolve a cell in `⊥` back to one legal value
    /// (`event-auth-state-resolution.md` §9.5).
    ///
    /// This is not a lattice op and does not join: it replaces the cell.
    /// `ak.conflict.recovery` is the only kind whose contract may project
    /// it, and the reducer MUST apply it only to a cell already in `⊥`, and
    /// only when the Event carries the `recovery_capability` and
    /// `state_witness` refs that section requires. On a cell in any other state
    /// the write MUST be rejected — otherwise recovery becomes a general
    /// overwrite channel that bypasses every lattice.
    Reset { value: Value },
}

/// Narrowing predicate for [`ProjectedOp::RemoveObserved`].
///
/// `element_field` is a dotted named path on the **element value**, not an
/// Event root path — that is what distinguishes it from `condition.field`.
/// Elements where the path is absent do not take part in the removal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedRemoveMatch {
    pub element_field: String,
    pub expected: Value,
}

/// One registered cell write, projected from the Event but not yet resolved
/// against the frozen pre-state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedCellWrite {
    pub cell_id: CellRef,
    pub op: ProjectedOp,
}

impl ProjectedCellWrite {
    /// The resolved write when the projection needs no pre-state.
    pub fn as_direct(&self) -> Option<ProjectionEffect> {
        match &self.op {
            ProjectedOp::Direct(op) => {
                Some(ProjectionEffect::join(self.cell_id.clone(), op.clone()))
            }
            _ => None,
        }
    }
}

/// Lattice operation. Shape is `{kind, tag?, value?, from?, to?, reason?, issuer_seq?}`.
///
/// Which members are populated depends on the target cell's declared Lattice
/// type (see `event-auth-state-resolution.md` §9). This struct accepts the
/// union; per-type validation lives in the `arkret-state` lattice
/// implementations' `validate_op`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeOp {
    #[serde(rename = "kind")]
    pub op_type: LatticeOpType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::deserialize_optional_value_preserving_null"
    )]
    pub value: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::deserialize_optional_value_preserving_null"
    )]
    pub from: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_helpers::deserialize_optional_value_preserving_null"
    )]
    pub to: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_seq: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

impl LatticeOpType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Set => "set",
            Self::Transition => "transition",
            Self::Inc => "inc",
            Self::Dec => "dec",
            Self::Append => "append",
        }
    }
}

impl LatticeOp {
    /// A `set` operation with every optional member absent.
    ///
    /// Projection evaluators build operations from this base and populate only
    /// the members the registered `effect_projection` declares; an operation
    /// member that the contract does not declare MUST stay absent rather than
    /// fall back to an implementation-private default.
    pub fn empty() -> Self {
        Self {
            op_type: LatticeOpType::Set,
            tag: None,
            value: None,
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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
        // None members are skipped.
        assert!(!s.contains("\"tag\""));
        assert!(!s.contains("\"value\""));
    }

    #[test]
    fn predicate_head_eq_preserves_explicit_null_round_trip() {
        // Genesis `head_eq null` asserts an empty cell. The explicit wire `null`
        // MUST survive a parse → re-serialize cycle byte-for-byte, otherwise the
        // canonical digest drifts away from the locally-signed one and the
        // reducer's `head_eq` (which requires `value`) rejects the genesis write.
        let wire = r#"{"op":"head_eq","value":null}"#;
        let parsed: Predicate = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.value, Some(Value::Null));
        assert_eq!(serde_json::to_string(&parsed).unwrap(), wire);
    }

    #[test]
    fn predicate_absent_value_stays_none_and_is_omitted() {
        // A genuinely-absent `value` (e.g. `head_in` carries `values`, not
        // `value`) must remain `None` and serialize without the key.
        let wire = r#"{"op":"head_in","values":["a","b"]}"#;
        let parsed: Predicate = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.value, None);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), wire);
    }

    #[test]
    fn lattice_op_transition_preserves_explicit_null_from() {
        // `from: null → join` (an invite-accept / genesis membership) carries an
        // explicit null on `from` that must round-trip without collapsing.
        let wire = r#"{"kind":"transition","from":null,"to":"invite"}"#;
        let parsed: LatticeOp = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.from, Some(Value::Null));
        assert_eq!(parsed.to, Some(Value::String("invite".to_owned())));
        assert_eq!(serde_json::to_string(&parsed).unwrap(), wire);
    }

    #[test]
    fn seal_basis_rejects_reducer_instruction_members() {
        let wire = json!({
            "leaves": ["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "control_event_set_root": format!("sha256:{}", "b".repeat(64)),
            "state_root": format!("sha256:{}", "c".repeat(64)),
            "effects": [],
        });
        serde_json::from_value::<SealBasis>(wire)
            .expect_err("seal_basis must not absorb a reducer-instruction member");
    }

    #[test]
    fn seal_basis_requires_canonical_non_empty_leaves() {
        let leaf = SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap();
        SealBasis { leaves: Vec::new() }
            .validate_protocol_bounds()
            .expect_err("empty basis must be rejected");
        SealBasis {
            leaves: vec![leaf.clone(), leaf],
        }
        .validate_protocol_bounds()
        .expect_err("duplicate basis leaves must be rejected");
    }
}
