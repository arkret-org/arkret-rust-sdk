//! Identity-preserving causal register.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{OpError, ResolvedCellState, StateModel, StateModelKind, StateWrite};
use crate::{CellRef, EventId, LatticeOp, LatticeOpType};

#[derive(Clone, Copy, Debug, Default)]
pub struct CausalRegister;

/// Complete causal-register state for one eligibility context.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalRegisterState {
    pub covered_event_ids: BTreeSet<EventId>,
    pub winner: CausalWinner,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalWinner {
    pub event_id: EventId,
    pub depth: u64,
    pub value: Value,
}

fn depth_for(
    event_id: &EventId,
    writes: &BTreeMap<EventId, &StateWrite>,
    depths: &mut BTreeMap<EventId, u64>,
    visiting: &mut BTreeSet<EventId>,
) -> Result<u64, OpError> {
    if let Some(depth) = depths.get(event_id) {
        return Ok(*depth);
    }
    if !visiting.insert(event_id.clone()) {
        return Err(OpError::InvalidValue {
            kind: "causal_register",
            field: "causal_refs",
            reason: "same-Cell dependency cycle".to_owned(),
        });
    }
    let write = writes
        .get(event_id)
        .ok_or_else(|| OpError::Unrepresentable {
            kind: "causal_register",
            reason: format!("missing same-Cell predecessor {event_id}"),
        })?;
    let depth = if let Some(depth) = write.fixed_depth {
        if depth > 9_007_199_254_740_991 {
            return Err(OpError::Unrepresentable {
                kind: "causal_register",
                reason: "cached causal depth exceeds the JSON-safe integer range".to_owned(),
            });
        }
        depth
    } else if write.supersedes.is_empty() {
        0
    } else {
        let mut maximum = 0;
        let mut seen = BTreeSet::new();
        for predecessor in &write.supersedes {
            if !seen.insert(predecessor) {
                return Err(OpError::InvalidValue {
                    kind: "causal_register",
                    field: "causal_refs",
                    reason: "duplicate same-Cell predecessor".to_owned(),
                });
            }
            maximum = maximum.max(depth_for(predecessor, writes, depths, visiting)?);
        }
        maximum
            .checked_add(1)
            .filter(|depth| *depth <= 9_007_199_254_740_991)
            .ok_or_else(|| OpError::Unrepresentable {
                kind: "causal_register",
                reason: "causal depth exceeds the JSON-safe integer range".to_owned(),
            })?
    };
    visiting.remove(event_id);
    depths.insert(event_id.clone(), depth);
    Ok(depth)
}

/// Compute the deterministic current value from authenticated same-Cell writes.
pub fn causal_register_state(writes: &[StateWrite]) -> Result<CausalRegisterState, OpError> {
    let mut unique: BTreeMap<EventId, &StateWrite> = BTreeMap::new();
    for write in writes {
        if CausalRegister.validate_op(&write.op).is_err() {
            continue;
        }
        if let Some(previous) = unique.get(&write.event_id) {
            if previous.op.value != write.op.value
                || previous.supersedes != write.supersedes
                || previous.fixed_depth != write.fixed_depth
            {
                return Err(OpError::InvalidValue {
                    kind: "causal_register",
                    field: "event_id",
                    reason: "one Event identity maps to different value or predecessors".to_owned(),
                });
            }
            continue;
        }
        unique.insert(write.event_id.clone(), write);
    }

    let covered_event_ids: BTreeSet<_> = unique.keys().cloned().collect();
    if unique.is_empty() {
        return Err(OpError::Unrepresentable {
            kind: "causal_register",
            reason: "no valid writes".to_owned(),
        });
    }
    let mut depths = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    for event_id in unique.keys() {
        depth_for(event_id, &unique, &mut depths, &mut visiting)?;
    }
    let (event_id, depth) = depths
        .iter()
        .max_by(|(left_id, left_depth), (right_id, right_depth)| {
            left_depth
                .cmp(right_depth)
                .then_with(|| left_id.token_bytes().cmp(&right_id.token_bytes()))
        })
        .expect("nonempty causal write set has a winner");
    let winner_write = unique.get(event_id).expect("winner is covered");

    Ok(CausalRegisterState {
        covered_event_ids,
        winner: CausalWinner {
            event_id: event_id.clone(),
            depth: *depth,
            value: winner_write.op.value.clone().unwrap_or(Value::Null),
        },
    })
}

impl StateModel for CausalRegister {
    fn kind(&self) -> StateModelKind {
        StateModelKind::CausalRegister
    }

    fn validate_op(&self, op: &LatticeOp) -> Result<(), OpError> {
        if op.op_type != LatticeOpType::Set {
            return Err(OpError::UnsupportedOpType {
                got: op.op_type.as_str().to_owned(),
                expected_kind: "causal_register",
            });
        }
        if op.value.is_none() {
            return Err(OpError::MissingField {
                kind: "causal_register",
                field: "value",
            });
        }
        Ok(())
    }

    fn resolve(&self, cell: &CellRef, writes: &[StateWrite]) -> Result<ResolvedCellState, OpError> {
        let _ = cell;
        causal_register_state(writes).map(ResolvedCellState::Causal)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::Hash;

    fn event(byte: u8) -> EventId {
        EventId::from_event_digest(
            &Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap(),
        )
        .unwrap()
    }

    fn set(value: Value) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Set,
            value: Some(value),
            ..LatticeOp::empty()
        }
    }

    #[test]
    fn causal_depth_beats_a_higher_id_stale_sibling() {
        let first = StateWrite::new(event(1), set(json!("A")));
        let sibling = StateWrite::new(event(2), set(json!("A")));
        let returned = StateWrite::superseding(event(3), set(json!("A")), vec![event(1)]);
        let state = causal_register_state(&[first, sibling, returned]).unwrap();
        assert_eq!(state.covered_event_ids.len(), 3);
        assert_eq!(state.winner.event_id, event(3));
        assert_eq!(state.winner.depth, 1);
    }

    #[test]
    fn partial_observation_join_formula_recomputes_from_covered_writes() {
        let first = StateWrite::new(event(1), set(json!("A")));
        let next = StateWrite::superseding(event(2), set(json!("B")), vec![event(1)]);
        let concurrent = StateWrite::new(event(3), set(json!("C")));
        let state = causal_register_state(&[concurrent, next, first]).unwrap();
        assert_eq!(state.winner.event_id, event(2));
        assert_eq!(state.winner.depth, 1);
    }

    #[test]
    fn same_depth_uses_complete_typed_event_identity() {
        let state = causal_register_state(&[
            StateWrite::new(event(1), set(json!("A"))),
            StateWrite::new(event(2), set(json!("B"))),
        ])
        .unwrap();
        assert_eq!(state.winner.event_id, event(2));
        assert_eq!(state.winner.depth, 0);
    }

    #[test]
    fn missing_dependency_and_cycle_fail_closed() {
        let missing = StateWrite::superseding(event(2), set(json!("B")), vec![event(1)]);
        assert!(matches!(
            causal_register_state(&[missing]),
            Err(OpError::Unrepresentable { .. })
        ));
        let left = StateWrite::superseding(event(1), set(json!("A")), vec![event(2)]);
        let right = StateWrite::superseding(event(2), set(json!("B")), vec![event(1)]);
        assert!(matches!(
            causal_register_state(&[left, right]),
            Err(OpError::InvalidValue { .. })
        ));
    }
}
