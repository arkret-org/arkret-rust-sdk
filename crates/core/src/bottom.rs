//! Bottom (`⊥`) diagnostic typed model.
//!
//! See spec `spec/v1/zh/authz/event-auth-state-resolution.md` §5.1 and
//! schema `bottom.schema.json`. A cell's effective Lattice value resolves
//! to bottom when the join under the current Anchor view produces no valid
//! single value (or violates the cell's declared safety rules). Bottom is
//! either rejected (`bottom=reject` cells, e.g. capability / membership
//! safety-critical) or exposed to projections (`bottom=expose` cells, e.g.
//! soft display state) — never silently winner-picked by the receiver.
//!
//! Wire diagnostic surfaced on `/account/subscribe`, `/events`, and state-query
//! responses so clients (and admin UIs) can show structured "this cell is
//! ⊥, here are the candidate heads, here is the Anchor view it was
//! observed under" without re-implementing the conflict semantics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AnchorId, CellRef, Hash, MoveId};

/// Why the join produced bottom.
///
/// The six variants are normative in `bottom.schema.json`. New diagnostic
/// kinds MUST go through a schema profile bump and new `BottomKind`
/// variant — receivers MUST fail closed on unrecognized kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    /// Multiple anchorer cell Anchor leaves diverge on next-batch authority.
    AnchorerSplit,
    /// Lattice op or value violates the declared cell schema.
    SchemaError,
}

/// Anchor leaves and (optional) state_root that pin where the bottom was
/// observed. Diagnostics MUST include this so the receiver can reproduce
/// the join without ambiguity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AnchorView {
    pub leaves: Vec<AnchorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<Hash>,
}

/// Structured bottom diagnostic for a cell join.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Bottom {
    pub kind: BottomKind,
    /// Cell ids participating in this bottom. Multi-cell when an atomic
    /// multi-cell Move failed across linked cells.
    pub cells: Vec<CellRef>,
    /// Anchored Move ids whose effects (or precondition checks) produced
    /// this bottom. Empty for structural bottoms (e.g. anchorer cell
    /// schema_error) not tied to a specific Move.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub move_ids: Vec<MoveId>,
    /// Anchor view the bottom was observed under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_view: Option<AnchorView>,
    /// Candidate heads for `kind=conflict` only. Receivers MUST NOT pick
    /// a winner from this array; UI / audit display only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heads: Vec<Value>,
    /// Free-form structured details; producers SHOULD use stable keys per
    /// kind (e.g. invalid_transition: from/to/expected_transitions;
    /// schema_error: schema_id/violation_path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    /// When the cell first crossed `Space.bottom_escalation_after_ms`.
    /// Absent within the grace window. Implementations SHOULD raise an
    /// out-of-band notification once set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalated_at: Option<DateTime<Utc>>,
}

impl Bottom {
    /// Construct a minimal bottom diagnostic with required fields.
    pub fn new(kind: BottomKind, cells: Vec<CellRef>) -> Self {
        Self {
            kind,
            cells,
            move_ids: Vec::new(),
            anchor_view: None,
            heads: Vec::new(),
            details: None,
            escalated_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cell(s: &str) -> CellRef {
        CellRef::new(s.to_owned()).unwrap()
    }

    fn move_id(hex: &str) -> MoveId {
        MoveId::new(format!("sha256:{hex}")).unwrap()
    }

    fn anchor_id(hex: &str) -> AnchorId {
        AnchorId::new(format!("cx:anchor:sha256:{hex}")).unwrap()
    }

    #[test]
    fn bottom_kind_serializes_snake_case() {
        let kinds = [
            (BottomKind::Conflict, "conflict"),
            (BottomKind::InvalidTransition, "invalid_transition"),
            (BottomKind::MissingDependency, "missing_dependency"),
            (BottomKind::Unauthorized, "unauthorized"),
            (BottomKind::AnchorerSplit, "anchorer_split"),
            (BottomKind::SchemaError, "schema_error"),
        ];
        for (k, expected) in kinds {
            let s = serde_json::to_string(&k).unwrap();
            assert_eq!(s, format!("\"{expected}\""));
        }
    }

    #[test]
    fn minimal_bottom_serializes_only_required_fields() {
        let b =
            Bottom::new(BottomKind::Conflict, vec![cell("cx:cell:cx.component.space.policy.v1:x")]);
        let s = serde_json::to_string(&b).unwrap();
        assert!(s.contains("\"kind\":\"conflict\""));
        assert!(s.contains("\"cells\""));
        // Empty / None fields should be skipped.
        assert!(!s.contains("\"move_ids\""));
        assert!(!s.contains("\"anchor_view\""));
        assert!(!s.contains("\"heads\""));
        assert!(!s.contains("\"details\""));
        assert!(!s.contains("\"escalated_at\""));
    }

    #[test]
    fn conflict_bottom_with_heads_round_trips() {
        let b = Bottom {
            kind: BottomKind::Conflict,
            cells: vec![cell("cx:cell:cx.component.space.policy.v1:x")],
            move_ids: vec![
                move_id("4444444444444444444444444444444444444444444444444444444444444444"),
                move_id("5555555555555555555555555555555555555555555555555555555555555555"),
            ],
            anchor_view: Some(AnchorView {
                leaves: vec![anchor_id(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )],
                state_root: None,
            }),
            heads: vec![json!({"value": "open"}), json!({"value": "closed"})],
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
            cells: vec![cell("cx:cell:cx.component.member.state.v1:did.web.alice.example")],
            move_ids: vec![],
            anchor_view: None,
            heads: vec![],
            details: Some(json!({
                "from": "leave",
                "to": "join",
                "expected_transitions": ["join", "ban"]
            })),
            escalated_at: None,
        };
        let s = serde_json::to_string(&b).unwrap();
        assert!(s.contains("\"kind\":\"invalid_transition\""));
        assert!(s.contains("expected_transitions"));
    }

    #[test]
    fn anchorer_split_kind_carries_no_move_ids() {
        let b = Bottom::new(
            BottomKind::AnchorerSplit,
            vec![cell("cx:cell:cx.component.anchorer.v1:cx.space.01js0sp00000000000000000aa")],
        );
        assert!(b.move_ids.is_empty());
        let r: Bottom = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(r.kind, BottomKind::AnchorerSplit);
    }

    #[test]
    fn deserialize_unknown_kind_is_rejected() {
        let raw = json!({
            "kind": "future_unknown_bottom",
            "cells": ["cx:cell:cx.component.member.state.v1:did.web.alice.example"]
        });
        let r: Result<Bottom, _> = serde_json::from_value(raw);
        assert!(r.is_err(), "unknown BottomKind must fail closed");
    }
}
