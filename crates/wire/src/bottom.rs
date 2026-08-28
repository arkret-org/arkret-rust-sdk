//! Bottom (`⊥`) diagnostic typed model.
//!
//! See spec `spec/v1/zh/authz/event-auth-state-resolution.md` §5.1 and
//! schema `bottom.schema.json`. A cell's effective Lattice value resolves
//! to bottom when the join under the current Seal view produces no valid
//! single value (or violates the cell's declared safety rules). Bottom is
//! either rejected (`bottom=reject` cell_ids, e.g. capability / membership
//! safety-critical) or exposed to projections (`bottom=expose` cell_ids, e.g.
//! soft display state) — never silently winner-picked by the receiver.
//!
//! Wire diagnostic surfaced on `/account/subscribe`, `/events`, and state-query
//! responses so clients (and admin UIs) can show structured "this cell is
//! ⊥, here are the candidate head_ids, here is the Seal view it was
//! observed under" without re-implementing the conflict semantics.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{CellRef, Hash, SchemaId, SealId};

/// Free-form structured details object for a Bottom diagnostic.
///
/// The spec defines `details` as a JSON object with stable kind-specific keys,
/// not an arbitrary JSON scalar / array.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BottomDetails(BTreeMap<String, Value>);

impl BottomDetails {
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl std::ops::Deref for BottomDetails {
    type Target = BTreeMap<String, Value>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for BottomDetails {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub fn bottom_details<K, I>(pairs: I) -> BottomDetails
where
    K: Into<String>,
    I: IntoIterator<Item = (K, Value)>,
{
    BottomDetails(
        pairs
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}

/// Why the join produced bottom.
///
/// The six variants are normative in `bottom.schema.json`. New diagnostic
/// kinds MUST go through a schema profile bump and new `BottomKind`
/// variant — receivers MUST fail closed on unrecognized kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BottomKind {
    /// Concurrent cas-register / fsm divergence on a safety-critical cell.
    Conflict,
    /// fsm op violates the cell's `allowed_transitions`.
    InvalidTransition,
    /// Move ref points at an absent or already-failed prior Move.
    MissingDependency,
    /// Move issuer lacks capability for the op (verifier-side rejection
    /// surfaced as a cell-level diagnostic when the unauthorized op
    /// would otherwise have left the cell in an undefined state).
    Unauthorized,
    /// Multiple notary cell Seal leaves diverge on next-batch authority.
    NotarySplit,
    /// Lattice op or value violates the declared cell schema.
    SchemaError,
}

/// Seal leaves and (optional) state_root that pin where the bottom was
/// observed. Diagnostics MUST include this so the receiver can reproduce
/// the join without ambiguity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealView {
    pub leaves: Vec<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<Hash>,
}

/// Structured bottom diagnostic for a cell join.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bottom {
    pub kind: BottomKind,
    /// Cell ids participating in this bottom. Multi-cell when an atomic
    /// multi-cell Move failed across linked cell_ids.
    pub cell_ids: Vec<CellRef>,
    /// Sealed Move ids whose effects (or precondition checks) produced
    /// this bottom. Empty for structural bottoms (e.g. notary cell
    /// schema_error) not tied to a specific Move.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub move_ids: Vec<Hash>,
    /// Seal view the bottom was observed under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_view: Option<SealView>,
    /// Candidate head_ids for `kind=conflict` only. Receivers MUST NOT pick
    /// a winner from this array; UI / audit display only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub head_ids: Vec<Value>,
    /// Free-form structured details; producers SHOULD use stable keys per
    /// kind (e.g. invalid_transition: from/to/expected_transitions;
    /// schema_error: schema_id/violation_path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<BottomDetails>,
    /// When the cell first crossed `Space.bottom_escalation_after_ms`.
    /// Absent within the grace window. Implementations SHOULD raise an
    /// out-of-band notification once set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub escalated_at: Option<DateTime<Utc>>,
}

impl Bottom {
    pub const SCHEMA: &'static str = SchemaId::BOTTOM_V1;
    /// Construct a minimal bottom diagnostic with required fields.
    pub fn new(kind: BottomKind, cell_ids: Vec<CellRef>) -> Self {
        Self {
            kind,
            cell_ids,
            move_ids: Vec::new(),
            seal_view: None,
            head_ids: Vec::new(),
            details: None,
            escalated_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn cell(s: &str) -> CellRef {
        CellRef::new(s.to_owned()).unwrap()
    }

    fn move_id(hex: &str) -> Hash {
        Hash::new(format!("sha256:{hex}")).unwrap()
    }

    fn seal_id(hex: &str) -> SealId {
        SealId::new(format!("ak:seal:sha256:{hex}")).unwrap()
    }

    #[test]
    fn bottom_kind_serializes_snake_case() {
        let kinds = [
            (BottomKind::Conflict, "conflict"),
            (BottomKind::InvalidTransition, "invalid_transition"),
            (BottomKind::MissingDependency, "missing_dependency"),
            (BottomKind::Unauthorized, "unauthorized"),
            (BottomKind::NotarySplit, "notary_split"),
            (BottomKind::SchemaError, "schema_error"),
        ];
        for (k, expected) in kinds {
            let s = serde_json::to_string(&k).unwrap();
            assert_eq!(s, format!("\"{expected}\""));
        }
    }

    #[test]
    fn minimal_bottom_serializes_only_required_fields() {
        let b = Bottom::new(
            BottomKind::Conflict,
            vec![cell("ak:cell:ak.component.realm.policy.v1:x")],
        );
        let s = serde_json::to_string(&b).unwrap();
        assert!(s.contains("\"kind\":\"conflict\""));
        assert!(s.contains("\"cell_ids\""));
        // Empty / None fields should be skipped.
        assert!(!s.contains("\"move_ids\""));
        assert!(!s.contains("\"seal_view\""));
        assert!(!s.contains("\"head_ids\""));
        assert!(!s.contains("\"details\""));
        assert!(!s.contains("\"escalated_at\""));
    }

    #[test]
    fn conflict_bottom_with_head_ids_round_trips() {
        let b = Bottom {
            kind: BottomKind::Conflict,
            cell_ids: vec![cell("ak:cell:ak.component.realm.policy.v1:x")],
            move_ids: vec![
                move_id("4444444444444444444444444444444444444444444444444444444444444444"),
                move_id("5555555555555555555555555555555555555555555555555555555555555555"),
            ],
            seal_view: Some(SealView {
                leaves: vec![seal_id(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )],
                state_root: None,
            }),
            head_ids: vec![json!({"value": "open"}), json!({"value": "closed"})],
            details: None,
            escalated_at: None,
        };
        let s = serde_json::to_string(&b).unwrap();
        let r: Bottom = serde_json::from_str(&s).unwrap();
        assert_eq!(r, b);
    }

    #[test]
    fn invalid_transition_with_details() {
        let b = Bottom {
            kind: BottomKind::InvalidTransition,
            cell_ids: vec![cell(
                "ak:cell:ak.component.member.state.v1:did.web.alice.example",
            )],
            move_ids: vec![],
            seal_view: None,
            head_ids: vec![],
            details: Some(bottom_details([
                ("expected_transitions", json!(["join", "ban"])),
                ("from", json!("leave")),
                ("to", json!("join")),
            ])),
            escalated_at: None,
        };
        let s = serde_json::to_string(&b).unwrap();
        assert!(s.contains("\"kind\":\"invalid_transition\""));
        assert!(s.contains("expected_transitions"));
    }

    #[test]
    fn notary_split_kind_carries_no_move_ids() {
        let b = Bottom::new(
            BottomKind::NotarySplit,
            vec![cell(
                "ak:cell:ak.component.notary.v1:ak.space.01js0sp00000000000000000aa",
            )],
        );
        assert!(b.move_ids.is_empty());
        let r: Bottom = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(r.kind, BottomKind::NotarySplit);
    }

    #[test]
    fn deserialize_unknown_kind_is_rejected() {
        let raw = json!({
            "kind": "future_unknown_bottom",
            "cell_ids": ["ak:cell:ak.component.member.state.v1:did.web.alice.example"]
        });
        let r: Result<Bottom, _> = serde_json::from_value(raw);
        assert!(r.is_err(), "unknown BottomKind must fail closed");
    }
}
